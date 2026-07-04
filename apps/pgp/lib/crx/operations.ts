/**
 * ============================================================================
 * CRX signing-key coordinator (JS side).
 * ============================================================================
 *
 * Drives generate / import / sign / verify for CRX (Chrome extension)
 * signing keys, reusing the exact protection machinery the PGP keys use
 * (Argon2id / WebAuthn-PRF -> AES-256-GCM, all inside WASM). Mirrors
 * `protection/protect-flow.ts`; every password / PRF buffer is `.fill(0)`'d
 * in a `finally`. The RSA private key never leaves WASM in the clear.
 */

import { fromBase64, toBase64 } from "../encoding";
import type { CrxProtectFlowResult, CrxVerifyResult } from "../pgp/wasm";
import {
  dropCrxKey,
  generateCrxKeyWithPassword,
  generateCrxKeyWithPrf,
  importCrxKeyWithPassword,
  importCrxKeyWithPrf,
  reprotectCrxKeyWithPassword,
  signCrxWithHandle,
  unlockCrxWithPassword,
  unlockCrxWithPrf,
  verifyCrx,
} from "../pgp/wasm";
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
} from "../protection/password-kdf";
import {
  authenticateAndGetPrf,
  generatePrfSalt,
  generateStoredSecret,
  registerPasskey,
} from "../protection/webauthn-prf";
import { addCrxKey, updateCrxLastUsed } from "./storage";
import type { CrxSigningKeyBlob } from "./types";

export type CrxProtectionInput =
  | { method: "password"; password: string }
  | { method: "passkey"; reusePasskeyCredentialId?: string };

// ── blob assembly ────────────────────────────────────────────────────

function buildPasswordCrxBlob(
  result: CrxProtectFlowResult,
  label?: string,
): CrxSigningKeyBlob {
  const salt = result.blob.slice(0, 16);
  const iv = result.blob.slice(16, 28);
  const ct = result.blob.slice(28);
  return {
    version: 1,
    extensionId: result.meta.extensionId,
    label,
    publicKeyDerB64: result.meta.publicKeyDerB64,
    algorithm: result.meta.algorithm,
    protection: { method: "password", kdfSalt: toBase64(salt) },
    encryptedPrivateKey: toBase64(ct),
    iv: toBase64(iv),
    createdAt: Date.now(),
    lastUsedAt: Date.now(),
  };
}

function buildPasskeyCrxBlob(
  result: CrxProtectFlowResult,
  credentialId: string,
  prfSalt: ArrayBuffer,
  storedSecret: ArrayBuffer,
  label?: string,
): CrxSigningKeyBlob {
  const iv = result.blob.slice(0, 12);
  const ct = result.blob.slice(12);
  return {
    version: 1,
    extensionId: result.meta.extensionId,
    label,
    publicKeyDerB64: result.meta.publicKeyDerB64,
    algorithm: result.meta.algorithm,
    protection: {
      method: "passkey",
      credentialId,
      prfSalt: toBase64(prfSalt),
      // storedSecret is HKDF salt, persisted in plaintext alongside ct.
      storedSecret: toBase64(storedSecret),
    },
    encryptedPrivateKey: toBase64(ct),
    iv: toBase64(iv),
    createdAt: Date.now(),
    lastUsedAt: Date.now(),
  };
}

// ── protection helpers (shared by generate + import) ─────────────────

type PasswordRunner = (password: Uint8Array) => Promise<CrxProtectFlowResult>;
type PrfRunner = (
  prfOutput: Uint8Array,
  storedSecret: Uint8Array,
) => Promise<CrxProtectFlowResult>;

async function protectWithPassword(
  password: string,
  run: PasswordRunner,
  label?: string,
): Promise<CrxSigningKeyBlob> {
  if (!password || password.length < 8) {
    throw new Error("Password must be at least 8 characters");
  }
  const passwordBytes = new TextEncoder().encode(password);
  try {
    return buildPasswordCrxBlob(await run(passwordBytes), label);
  } finally {
    passwordBytes.fill(0);
  }
}

async function resolveCredential(userIdHint: string): Promise<string> {
  const reg = await registerPasskey(userIdHint, userIdHint);
  if (!reg.prfEnabled) {
    throw new Error(
      "Your authenticator doesn't support PRF. Try a different passkey or use a password instead.",
    );
  }
  return reg.credentialId;
}

async function protectWithPasskey(
  protection: Extract<CrxProtectionInput, { method: "passkey" }>,
  run: PrfRunner,
  userIdHint: string,
  label?: string,
): Promise<CrxSigningKeyBlob> {
  const credentialId =
    protection.reusePasskeyCredentialId ??
    (await resolveCredential(userIdHint));

  const prfSalt = generatePrfSalt();
  const { prfOutput } = await authenticateAndGetPrf(credentialId, prfSalt);
  const storedSecret = generateStoredSecret();
  const storedSecretBytes = new Uint8Array(storedSecret);
  try {
    const result = await run(prfOutput, storedSecretBytes);
    return buildPasskeyCrxBlob(
      result,
      credentialId,
      prfSalt,
      storedSecret,
      label,
    );
  } finally {
    prfOutput.fill(0);
  }
}

// ── public API: generate / import ────────────────────────────────────

/** Generate a fresh RSA-2048 CRX signing key, protect it, and store it. */
export async function generateCrxKey(
  protection: CrxProtectionInput,
  label?: string,
): Promise<CrxSigningKeyBlob> {
  const blob =
    protection.method === "password"
      ? await protectWithPassword(
          protection.password,
          (pw) =>
            generateCrxKeyWithPassword(
              pw,
              ARGON2_MEMORY_KIB,
              ARGON2_ITERATIONS,
              ARGON2_PARALLELISM,
            ),
          label,
        )
      : await protectWithPasskey(
          protection,
          (prf, ss) => generateCrxKeyWithPrf(prf, ss),
          label ?? "CRX signing key",
          label,
        );
  await addCrxKey(blob);
  return blob;
}

/** Import an existing RSA private key (PKCS#8 or PKCS#1 PEM), re-protect
 *  it, and store it. Use this to bring a key already registered with the
 *  Chrome Web Store. */
export async function importCrxKey(
  pem: string,
  protection: CrxProtectionInput,
  label?: string,
): Promise<CrxSigningKeyBlob> {
  const blob =
    protection.method === "password"
      ? await protectWithPassword(
          protection.password,
          (pw) =>
            importCrxKeyWithPassword(
              pem,
              pw,
              ARGON2_MEMORY_KIB,
              ARGON2_ITERATIONS,
              ARGON2_PARALLELISM,
            ),
          label,
        )
      : await protectWithPasskey(
          protection,
          (prf, ss) => importCrxKeyWithPrf(pem, prf, ss),
          label ?? "CRX signing key",
          label,
        );
  await addCrxKey(blob);
  return blob;
}

// ── public API: unlock + sign + verify ───────────────────────────────

/**
 * Unlock a CRX key into WASM and return its handle (password prompt or
 * passkey ceremony). The caller OWNS the handle and MUST {@link closeCrxKey}
 * it. Exposed for the bulk-export flow, which unlocks up-front to validate,
 * then re-seals under the export passphrase. For a one-shot sign, prefer
 * {@link signZipWithCrxKey}, which manages the handle itself.
 */
export async function openCrxKey(
  blob: CrxSigningKeyBlob,
  password?: string,
): Promise<number> {
  return unlockCrxKey(blob, password);
}

/** Drop (and zeroize) a handle returned by {@link openCrxKey}. */
export async function closeCrxKey(handle: number): Promise<void> {
  await dropCrxKey(handle);
}

/**
 * Re-seal an already-unlocked CRX key (by handle) under `password`, returning
 * a fresh portable `CrxSigningKeyBlob`. The plaintext key never leaves WASM.
 * Used by "Export All Keys" to re-wrap every CRX key under the single export
 * passphrase, so a passkey-protected key (bound to one authenticator) becomes
 * a password-protected blob that restores on any device.
 */
export async function resealCrxKeyUnderPassword(
  handle: number,
  password: string,
  label?: string,
): Promise<CrxSigningKeyBlob> {
  if (!password || password.length < 8) {
    throw new Error("Password must be at least 8 characters");
  }
  const passwordBytes = new TextEncoder().encode(password);
  try {
    const result = await reprotectCrxKeyWithPassword(
      handle,
      passwordBytes,
      ARGON2_MEMORY_KIB,
      ARGON2_ITERATIONS,
      ARGON2_PARALLELISM,
    );
    return buildPasswordCrxBlob(result, label);
  } finally {
    passwordBytes.fill(0);
  }
}

async function unlockCrxKey(
  blob: CrxSigningKeyBlob,
  password?: string,
): Promise<number> {
  const ciphertext = fromBase64(blob.encryptedPrivateKey);
  const iv = fromBase64(blob.iv);

  if (blob.protection.method === "password") {
    if (!password) {
      throw new Error("Password required to unlock this CRX signing key");
    }
    const passwordBytes = new TextEncoder().encode(password);
    try {
      return await unlockCrxWithPassword(
        ciphertext,
        iv,
        fromBase64(blob.protection.kdfSalt),
        blob.extensionId,
        passwordBytes,
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
      );
    } finally {
      passwordBytes.fill(0);
    }
  }

  const { prfOutput } = await authenticateAndGetPrf(
    blob.protection.credentialId,
    fromBase64(blob.protection.prfSalt),
  );
  try {
    return await unlockCrxWithPrf(
      ciphertext,
      iv,
      prfOutput,
      fromBase64(blob.protection.storedSecret),
      blob.extensionId,
    );
  } finally {
    prfOutput.fill(0);
  }
}

/**
 * Sign a packed extension ZIP into a CRX3 `.crx`. Unlocks the key (password
 * prompt or passkey ceremony), signs in WASM, and drops the handle — a
 * self-contained signing act, never a cached key.
 */
export async function signZipWithCrxKey(
  blob: CrxSigningKeyBlob,
  zipBytes: Uint8Array,
  opts: { password?: string } = {},
): Promise<Uint8Array> {
  const handle = await unlockCrxKey(blob, opts.password);
  try {
    const crx = await signCrxWithHandle(zipBytes, handle);
    await updateCrxLastUsed(blob.extensionId);
    return crx;
  } finally {
    await dropCrxKey(handle);
  }
}

/** Verify a `.crx` file's embedded signature. No key material involved. */
export async function verifyCrxFile(
  crx: Uint8Array,
): Promise<CrxVerifyResult> {
  return verifyCrx(crx);
}
