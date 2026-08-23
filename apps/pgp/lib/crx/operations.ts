/**
 * ============================================================================
 * CRX signing-key coordinator (JS side).
 * ============================================================================
 *
 * Drives generate / import / sign / verify for CRX (Chrome extension)
 * signing keys, reusing the exact protection machinery the PGP keys use
 * (Argon2id / WebAuthn-PRF -> AES-256-GCM, all inside WASM). The protect
 * path itself is literally shared with `protection/protect-flow.ts` — see
 * `protection/protect-runner.ts`, which owns the secret lifetimes; every
 * password / PRF buffer is `.fill(0)`'d in a `finally`, there and in the
 * unlock/reseal paths below. The RSA private key never leaves WASM in the
 * clear.
 */

import { fromBase64, toBase64 } from "../encoding";
import { AppError } from "../errors/app-error";
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
import type { ProtectSpec } from "../protection/protect-runner";
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
} from "../protection/password-kdf";
import {
  assertStrongPassword,
  runProtect,
} from "../protection/protect-runner";
import { unpackPasswordBlob } from "../protection/protected-blob";
import { authenticateAndGetPrf } from "../protection/webauthn-prf";
import { updateCrxLastUsed } from "./storage";
import type { CrxProtection, CrxSigningKeyBlob } from "./types";

export type CrxProtectionInput =
  | { method: "password"; password: string }
  | { method: "passkey"; reusePasskeyCredentialId?: string };

// ── blob assembly (the CRX-specific half of the flow) ───────────────

type CrxSpec = ProtectSpec<CrxProtectFlowResult, CrxSigningKeyBlob>;

/** Assemble a stored blob from the wasm metadata plus the already-unpacked
 *  seal. The protection union and the packed-blob layout are shared with
 *  the PGP keyring — see `protection/protected-blob.ts`. */
function crxBlob(
  result: CrxProtectFlowResult,
  protection: CrxProtection,
  iv: Uint8Array,
  ct: Uint8Array,
  label?: string,
): CrxSigningKeyBlob {
  return {
    version: 1,
    extensionId: result.meta.extensionId,
    label,
    publicKeyDerB64: result.meta.publicKeyDerB64,
    algorithm: result.meta.algorithm,
    protection,
    encryptedPrivateKey: toBase64(ct),
    iv: toBase64(iv),
    createdAt: Date.now(),
    lastUsedAt: Date.now(),
  };
}

/**
 * The CRX half of a protect flow: the two wasm exports to call and how
 * their metadata maps into a `CrxSigningKeyBlob`. No `cache*` hooks — a
 * CRX key is never held open past the act that needed it, so there is
 * nothing to chain an unlock into.
 */
function crxSpec(
  userIdHint: string,
  runPassword: CrxSpec["runPassword"],
  runPrf: CrxSpec["runPrf"],
  label?: string,
): CrxSpec {
  return {
    userIdHint,
    runPassword,
    runPrf,
    fromPassword: (result, { salt, iv, ct }) =>
      crxBlob(
        result,
        { method: "password", kdfSalt: toBase64(salt) },
        iv,
        ct,
        label,
      ),
    fromPrf: (result, { iv, ct }, prf) =>
      crxBlob(
        result,
        {
          method: "passkey",
          credentialId: prf.credentialId,
          prfSalt: toBase64(prf.prfSalt),
          // storedSecret is HKDF salt, persisted in plaintext alongside ct.
          storedSecret: toBase64(prf.storedSecret),
        },
        iv,
        ct,
        label,
      ),
  };
}

// ── public API: generate / import ────────────────────────────────────

/** Generate a fresh RSA-2048 CRX signing key and protect it. Returns the
 *  blob WITHOUT persisting it -- the caller stores it (e.g. `useCrxKeys.add`,
 *  which also refreshes the UI). One persist path, no double writes. */
export async function generateCrxKey(
  protection: CrxProtectionInput,
  label?: string,
): Promise<CrxSigningKeyBlob> {
  const { blob } = await runProtect(
    protection,
    crxSpec(
      label ?? "CRX signing key",
      (password) =>
        generateCrxKeyWithPassword(
          password,
          ARGON2_MEMORY_KIB,
          ARGON2_ITERATIONS,
          ARGON2_PARALLELISM,
        ),
      (prfOutput, storedSecret) =>
        generateCrxKeyWithPrf(prfOutput, storedSecret),
      label,
    ),
  );
  return blob;
}

/** Import an existing RSA private key (PKCS#8 or PKCS#1 PEM) and re-protect
 *  it. Use this to bring a key already registered with the Chrome Web Store.
 *  Returns the blob WITHOUT persisting it -- see {@link generateCrxKey}. */
export async function importCrxKey(
  pem: string,
  protection: CrxProtectionInput,
  label?: string,
): Promise<CrxSigningKeyBlob> {
  const { blob } = await runProtect(
    protection,
    crxSpec(
      label ?? "CRX signing key",
      (password) =>
        importCrxKeyWithPassword(
          pem,
          password,
          ARGON2_MEMORY_KIB,
          ARGON2_ITERATIONS,
          ARGON2_PARALLELISM,
        ),
      (prfOutput, storedSecret) => importCrxKeyWithPrf(pem, prfOutput, storedSecret),
      label,
    ),
  );
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
 * Export an unlocked CRX key (by handle) as an UNENCRYPTED PKCS#8 PEM -- the
 * raw private key. This is the deliberately-unsafe path (mirrors PGP's
 * plaintext key export): the key crosses into JS, so callers MUST gate it
 * behind explicit confirmation and drop the string promptly.
 */
export { exportCrxPrivateKeyPem } from "../pgp/wasm";

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
  assertStrongPassword(password);
  const passwordBytes = new TextEncoder().encode(password);
  try {
    const result = await reprotectCrxKeyWithPassword(
      handle,
      passwordBytes,
      ARGON2_MEMORY_KIB,
      ARGON2_ITERATIONS,
      ARGON2_PARALLELISM,
    );
    const { salt, iv, ct } = unpackPasswordBlob(result.blob);
    return crxBlob(
      result,
      { method: "password", kdfSalt: toBase64(salt) },
      iv,
      ct,
      label,
    );
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
      throw new AppError(
        "password-required",
        "Password required to unlock this CRX signing key",
      );
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
