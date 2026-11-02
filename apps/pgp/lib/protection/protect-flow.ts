/**
 * Generate / import + protect flows for OpenPGP keys. Secret lifetime and
 * the `cache: true` chained unlock live in `protect-runner.ts`; this file
 * picks the wasm exports and maps cert metadata into a `ProtectedKeyBlob`.
 * Threat model and zeroization table: `apps/pgp/SECURITY.md`.
 */

import type { GenerateKeyOptions } from "../pgp/types";
import type { ProtectFlowResult } from "../pgp/wasm";
import type { ProtectedKeyBlob } from "../storage/keyring";
import type { ProtectionInput, ProtectSpec } from "./protect-runner";
import type { PasswordBlobParts, PrfBlobParts } from "./protected-blob";
import { toBase64 } from "../encoding";
import { t } from "../i18n";
import {
  generateProtectedWithPassword,
  generateProtectedWithPrf,
  protectImportedWithPassword,
  protectImportedWithPrf,
  unlockWithPassword,
  unlockWithPrf,
} from "../pgp/wasm";
import { blobFromEncrypted } from "../storage/keyring";
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
} from "./password-kdf";
import { runProtect } from "./protect-runner";

const EMPTY = new Uint8Array(0);

/** Copy the revocation cert and parse warning, which live outside the
 *  encrypted half. */
function withCertMeta(
  blob: ProtectedKeyBlob,
  result: ProtectFlowResult,
): ProtectedKeyBlob {
  if (result.meta.revocationCertificate) {
    blob.revocationCertificate = result.meta.revocationCertificate;
  }
  if (result.meta.keyInfo.securityWarning) {
    blob.securityWarning = result.meta.keyInfo.securityWarning;
  }
  return blob;
}

function keySpec(
  userIdHint: string,
  runPassword: ProtectSpec<ProtectFlowResult, ProtectedKeyBlob>["runPassword"],
  runPrf: ProtectSpec<ProtectFlowResult, ProtectedKeyBlob>["runPrf"],
): ProtectSpec<ProtectFlowResult, ProtectedKeyBlob> {
  return {
    userIdHint,
    runPassword,
    runPrf,

    fromPassword: (result, { salt, iv, ct }: PasswordBlobParts) =>
      withCertMeta(
        blobFromEncrypted(
          result.meta.keyInfo.keyId,
          result.meta.keyInfo.userIds,
          result.meta.keyInfo.algorithm,
          result.meta.publicKeyArmored,
          {
            method: "password",
            ciphertext: toBase64(ct),
            iv: toBase64(iv),
            salt: toBase64(salt),
          },
        ),
        result,
      ),

    fromPrf: (result, { iv, ct }: PrfBlobParts, prf) =>
      withCertMeta(
        blobFromEncrypted(
          result.meta.keyInfo.keyId,
          result.meta.keyInfo.userIds,
          result.meta.keyInfo.algorithm,
          result.meta.publicKeyArmored,
          {
            method: "passkey",
            ciphertext: toBase64(ct),
            iv: toBase64(iv),
            credentialId: prf.credentialId,
            prfSalt: toBase64(prf.prfSalt),
            // storedSecret is HKDF salt, persisted in plaintext alongside ct.
            storedSecret: toBase64(prf.storedSecret),
          },
        ),
        result,
      ),

    cachePassword: (result, { salt, iv, ct }, passwordBytes) =>
      unlockWithPassword(
        ct,
        iv,
        salt,
        result.meta.keyInfo.keyId,
        passwordBytes,
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
      ),

    cachePrf: (result, { iv, ct }, prf) =>
      unlockWithPrf(
        ct,
        iv,
        prf.prfOutput,
        prf.storedSecretBytes,
        result.meta.keyInfo.keyId,
      ),
  };
}

export type { ProtectionInput };

interface CommonOpts {
  /** Used to label a freshly-registered passkey, ignored for reuse/password. */
  userIdHint?: string;
}

export interface ProtectFlowOutput {
  blob: ProtectedKeyBlob;
  /** Present iff `cache: true` was requested AND the unlock succeeded. */
  handle?: number;
}

/**
 * Generate a new keypair and protect it. The plaintext cert exists only
 * inside the wasm call and is NEVER inserted into KEY_STORE by it.
 */
export async function generateAndProtect(
  keyOpts: GenerateKeyOptions,
  protection: ProtectionInput,
  common: CommonOpts = {},
): Promise<ProtectFlowOutput> {
  return runProtect(
    protection,
    keySpec(
      common.userIdHint ??
        (keyOpts.email ? `${keyOpts.name} <${keyOpts.email}>` : keyOpts.name),
      (password) =>
        generateProtectedWithPassword(
          keyOpts,
          password,
          ARGON2_MEMORY_KIB,
          ARGON2_ITERATIONS,
          ARGON2_PARALLELISM,
        ),
      (prfOutput, storedSecret) =>
        generateProtectedWithPrf(keyOpts, prfOutput, storedSecret),
    ),
  );
}

/**
 * Import an armored private key and re-protect it; same KEY_STORE
 * invariants as `generateAndProtect`.
 *
 * @secret-handling `sourcePassphrase` is encoded to a `Uint8Array` and
 * `.fill(0)`'d in a `finally` that wraps the whole flow, including the
 * password gate and WebAuthn ceremony (both can throw before wasm).
 */
export async function importAndProtect(
  armoredPrivateKey: string,
  /** Source-key passphrase if the import is S2K-encrypted; null otherwise. */
  sourcePassphrase: string | null,
  protection: ProtectionInput,
  common: CommonOpts = {},
): Promise<ProtectFlowOutput> {
  const sourcePassphraseBytes = sourcePassphrase
    ? new TextEncoder().encode(sourcePassphrase)
    : EMPTY;

  try {
    return await runProtect(
      protection,
      keySpec(
        common.userIdHint ?? t("keygen_passkey_imported_user"),
        (password) =>
          protectImportedWithPassword(
            armoredPrivateKey,
            sourcePassphraseBytes,
            password,
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
          ),
        (prfOutput, storedSecret) =>
          protectImportedWithPrf(
            armoredPrivateKey,
            sourcePassphraseBytes,
            prfOutput,
            storedSecret,
          ),
      ),
    );
  } finally {
    if (sourcePassphraseBytes.length > 0) sourcePassphraseBytes.fill(0);
  }
}
