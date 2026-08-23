/**
 * ============================================================================
 * Generate / import + protect flows (OpenPGP keys).
 * ============================================================================
 *
 * This is the JS-side coordinator that drives every "produce a fresh
 * encrypted-key blob" path for PGP certs. The mechanics it used to own —
 * the password / PRF input lifetime (encode → call → `.fill(0)` in
 * `finally`), the optional `cache: true` chained unlock, and the
 * wire-format unpacking of the wasm packed-binary return — now live once
 * in `protect-runner.ts`, shared with the CRX signing-key flow. What
 * stays here is the PGP-specific half: which wasm export to call, and how
 * the returned cert metadata lands in a `ProtectedKeyBlob`.
 *
 * The guarantees are unchanged and still load-bearing:
 *   - password / PRF material crosses as `Uint8Array`, never a JS string,
 *     and is `.fill(0)`'d in a `finally` (`protect-runner.ts`),
 *   - `cache: true` performs a chained unlock through the standard
 *     `unlockWith*` path, so KEY_STORE insertion is always tied to the
 *     user-just-typed-credentials unlock action, never to the protect
 *     call itself,
 *   - the source passphrase of an imported key is `.fill(0)`'d here, on
 *     every exit from `importAndProtect`.
 *
 * For the threat model and per-secret zeroization audit table, see
 * `apps/pgp/SECURITY.md`. For the wasm-side guarantee that the cert
 * never enters KEY_STORE during a protect call, see the doc-comment
 * header in `apps/pgp/gpg-wasm/src/lib.rs`.
 */

import type { GenerateKeyOptions } from "../pgp/types";
import type { ProtectFlowResult } from "../pgp/wasm";
import type { ProtectedKeyBlob } from "../storage/keyring";
import type { ProtectionInput, ProtectSpec } from "./protect-runner";
import type { PasswordBlobParts, PrfBlobParts } from "./protected-blob";
import { toBase64 } from "../encoding";
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

// ── blob assembly (the PGP-specific half of the flow) ────────────────

/** Copy across the optional cert facts that live outside the encrypted
 *  half: a revocation certificate minted at generation time, and the
 *  non-blocking parse warning shown as a badge. */
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

/**
 * The PGP half of a protect flow: the two wasm exports to call, how their
 * metadata maps into a `ProtectedKeyBlob`, and the chained unlocks that
 * back `cache: true`.
 */
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

// ── public API ───────────────────────────────────────────────────────

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
 * Generate a new keypair and protect it under the chosen method.
 * Plaintext cert exists only inside the wasm call; it is NEVER inserted
 * into the long-lived KEY_STORE by this call. If `cache: true` is set,
 * the blob is then immediately unlocked via the standard `unlockWith*`
 * path -- KEY_STORE insertion stays tied to an explicit
 * (user-just-typed-credentials) unlock.
 */
export async function generateAndProtect(
  keyOpts: GenerateKeyOptions,
  protection: ProtectionInput,
  common: CommonOpts = {},
): Promise<ProtectFlowOutput> {
  return runProtect(
    protection,
    keySpec(
      common.userIdHint ?? `${keyOpts.name} <${keyOpts.email}>`,
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
 * Import an armored private key (optionally passphrase-protected) and
 * re-protect it under the chosen method. Plaintext cert exists only
 * inside the wasm call. Same KEY_STORE invariants as
 * `generateAndProtect` w/r/t the optional `cache` flag.
 *
 * @secret-handling `sourcePassphrase` is encoded to a `Uint8Array` and
 * `.fill(0)`'d in a `finally` that wraps the whole flow -- including the
 * password-strength gate and the WebAuthn ceremony, both of which can
 * throw before wasm is ever reached.
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
        common.userIdHint ?? "Imported PGP Key",
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
