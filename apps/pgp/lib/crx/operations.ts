/**
 * CRX signing-key coordinator: generate / import / sign / verify. Shares
 * the protect path and secret lifetimes with PGP via
 * `protection/protect-runner.ts`; every password / PRF buffer is
 * `.fill(0)`'d in a `finally`. The RSA private key never leaves WASM in
 * the clear (except via the explicit plaintext export below).
 */

import { fromBase64, toBase64 } from "~/lib/encoding";
import { AppError } from "~/lib/errors/app-error";
import { t } from "~/lib/i18n";
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
  type CrxProtectFlowResult,
  type CrxVerifyResult,
} from "~/lib/pgp/wasm";
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
} from "~/lib/protection/password-kdf";
import {
  assertStrongPassword,
  runProtect,
  type ProtectSpec,
} from "~/lib/protection/protect-runner";
import { unpackPasswordBlob } from "~/lib/protection/protected-blob";
import { authenticateAndGetPrf } from "~/lib/protection/webauthn-prf";
import { updateCrxLastUsed } from "./storage";
import type { CrxProtection, CrxSigningKeyBlob } from "./types";

export type CrxProtectionInput =
  | { method: "password"; password: string }
  | { method: "passkey"; reusePasskeyCredentialId?: string };

type CrxSpec = ProtectSpec<CrxProtectFlowResult, CrxSigningKeyBlob>;

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

/** No `cache*` hooks: a CRX key is never held open past one act. */
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

/** Generate an RSA-2048 CRX signing key. Returns the blob WITHOUT
 *  persisting it; the caller is the one persist path. */
export async function generateCrxKey(
  protection: CrxProtectionInput,
  label?: string,
): Promise<CrxSigningKeyBlob> {
  const { blob } = await runProtect(
    protection,
    crxSpec(
      label ?? t("settings_crx_default_key_name"),
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

/** Import an RSA PEM (PKCS#8 or PKCS#1). Not persisted, as above. */
export async function importCrxKey(
  pem: string,
  protection: CrxProtectionInput,
  label?: string,
): Promise<CrxSigningKeyBlob> {
  const { blob } = await runProtect(
    protection,
    crxSpec(
      label ?? t("settings_crx_default_key_name"),
      (password) =>
        importCrxKeyWithPassword(
          pem,
          password,
          ARGON2_MEMORY_KIB,
          ARGON2_ITERATIONS,
          ARGON2_PARALLELISM,
        ),
      (prfOutput, storedSecret) =>
        importCrxKeyWithPrf(pem, prfOutput, storedSecret),
      label,
    ),
  );
  return blob;
}

/** Unlock a CRX key into WASM. The caller OWNS the handle and MUST
 *  {@link closeCrxKey} it; prefer {@link signZipWithCrxKey} for one-shot
 *  signing. */
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

/** UNENCRYPTED PKCS#8 PEM export: the key crosses into JS, so callers
 *  MUST gate it behind explicit confirmation and drop the string promptly. */
export { exportCrxPrivateKeyPem } from "~/lib/pgp/wasm";

/** Re-seal an unlocked CRX key under `password` (plaintext stays in
 *  WASM), so a passkey-bound key can be exported portably. */
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

/** Sign a ZIP into a CRX3 `.crx`: unlock, sign, drop -- never cached. */
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
export async function verifyCrxFile(crx: Uint8Array): Promise<CrxVerifyResult> {
  return verifyCrx(crx);
}
