/**
 * ============================================================================
 * Generate / import + protect flows.
 * ============================================================================
 *
 * This is the JS-side coordinator that drives every "produce a fresh
 * encrypted-key blob" path. It owns:
 *   - the password / passphrase / PRF input lifetime (encode → call →
 *     `.fill(0)` in `finally`),
 *   - the optional `cache: true` chained unlock (so KEY_STORE
 *     insertion is always tied to the user-just-typed-credentials
 *     unlock action, never to the protect call itself),
 *   - the wire-format unpacking from the wasm packed-binary return.
 *
 * For the threat model and per-secret zeroization audit table, see
 * `apps/pgp/SECURITY.md`. For the wasm-side guarantee that the cert
 * never enters KEY_STORE during a protect call, see the doc-comment
 * header in `apps/pgp/gpg-wasm/src/lib.rs`.
 */

import type { GenerateKeyOptions } from "../pgp/types";
import type { ProtectFlowResult } from "../pgp/wasm";
import {
  generateProtectedWithPassword,
  generateProtectedWithPrf,
  protectImportedWithPassword,
  protectImportedWithPrf,
  unlockWithPassword,
  unlockWithPrf,
} from "../pgp/wasm";
import { blobFromEncrypted } from "../storage/keyring";
import type { ProtectedKeyBlob } from "../storage/keyring";
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
} from "./password-kdf";
import {
  authenticateAndGetPrf,
  generatePrfSalt,
  generateStoredSecret,
  registerPasskey,
} from "./webauthn-prf";

const EMPTY = new Uint8Array(0);

function toBase64(bytes: ArrayBufferView | ArrayBuffer): string {
  const view =
    bytes instanceof ArrayBuffer
      ? new Uint8Array(bytes)
      : new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let binary = "";
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function unpackPasswordBlob(packed: Uint8Array) {
  return {
    salt: packed.slice(0, 16),
    iv: packed.slice(16, 28),
    ct: packed.slice(28),
  };
}

function unpackPrfBlob(packed: Uint8Array) {
  return { iv: packed.slice(0, 12), ct: packed.slice(12) };
}

function buildPasswordBlob(result: ProtectFlowResult): ProtectedKeyBlob {
  const { salt, iv, ct } = unpackPasswordBlob(result.blob);
  const blob = blobFromEncrypted(
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
  );
  if (result.meta.revocationCertificate) {
    blob.revocationCertificate = result.meta.revocationCertificate;
  }
  return blob;
}

function buildPasskeyBlob(
  result: ProtectFlowResult,
  credentialId: string,
  prfSalt: ArrayBuffer,
  storedSecret: ArrayBuffer,
): ProtectedKeyBlob {
  const { iv, ct } = unpackPrfBlob(result.blob);
  const blob = blobFromEncrypted(
    result.meta.keyInfo.keyId,
    result.meta.keyInfo.userIds,
    result.meta.keyInfo.algorithm,
    result.meta.publicKeyArmored,
    {
      method: "passkey",
      ciphertext: toBase64(ct),
      iv: toBase64(iv),
      credentialId,
      prfSalt: toBase64(prfSalt),
      // storedSecret is HKDF salt, persisted in plaintext alongside ct.
      storedSecret: toBase64(storedSecret),
    },
  );
  if (result.meta.revocationCertificate) {
    blob.revocationCertificate = result.meta.revocationCertificate;
  }
  return blob;
}

async function resolvePasskeyCredential(
  reusePasskeyCredentialId: string | undefined,
  userIdHint: string,
): Promise<string> {
  if (reusePasskeyCredentialId) return reusePasskeyCredentialId;
  const reg = await registerPasskey(userIdHint, userIdHint);
  if (!reg.prfEnabled) {
    throw new Error(
      "Your authenticator doesn't support PRF. Try a different passkey or use a password instead.",
    );
  }
  return reg.credentialId;
}

// ── public API ───────────────────────────────────────────────────────

export type ProtectionInput =
  | {
      method: "password";
      password: string;
      /** If true, immediately unlock the new blob into KEY_STORE so the
       *  caller can use the key without re-prompting. The unlock goes
       *  through the standard `unlockWithPassword` path so KEY_STORE
       *  insertion is always tied to a user-initiated unlock action. */
      cache?: boolean;
    }
  | {
      method: "passkey";
      reusePasskeyCredentialId?: string;
      /** See above. Reuses the just-obtained PRF output -- no second
       *  WebAuthn prompt. */
      cache?: boolean;
      /** Skip the WebAuthn ceremony entirely by reusing a PRF output
       *  already obtained for `reusePasskeyCredentialId` (e.g. during
       *  onboarding where the master setup just authenticated). The
       *  returned blob will carry `prfSalt` so later unlocks
       *  re-authenticate with the same WebAuthn challenge and reproduce
       *  the same PRF output. A fresh `storedSecret` is still generated
       *  per blob to keep the derived AES key distinct from the master
       *  / other blobs. Caller owns `prfOutput`'s lifetime; this fn
       *  does NOT zero it. */
      prfReuse?: {
        prfOutput: Uint8Array;
        prfSalt: ArrayBuffer;
      };
    };

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
  if (protection.method === "password") {
    if (!protection.password || protection.password.length < 8) {
      throw new Error("Password must be at least 8 characters");
    }
    const passwordBytes = new TextEncoder().encode(protection.password);
    try {
      const result = await generateProtectedWithPassword(
        keyOpts,
        passwordBytes,
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
      );
      const blob = buildPasswordBlob(result);
      let handle: number | undefined;
      if (protection.cache) {
        const { salt, iv, ct } = unpackPasswordBlob(result.blob);
        handle = await unlockWithPassword(
          ct,
          iv,
          salt,
          result.meta.keyInfo.keyId,
          passwordBytes,
          ARGON2_MEMORY_KIB,
          ARGON2_ITERATIONS,
          ARGON2_PARALLELISM,
        );
      }
      return { blob, handle };
    } finally {
      passwordBytes.fill(0);
    }
  }

  const userIdHint =
    common.userIdHint ?? `${keyOpts.name} <${keyOpts.email}>`;
  const credentialId =
    protection.prfReuse !== undefined && protection.reusePasskeyCredentialId
      ? protection.reusePasskeyCredentialId
      : await resolvePasskeyCredential(
          protection.reusePasskeyCredentialId,
          userIdHint,
        );

  // PRF + prfSalt: either reuse from caller (no new WebAuthn dialog)
  // or run our own ceremony. `storedSecret` is always fresh per blob
  // so the derived AES key is unique even when prfOutput is shared.
  let prfSalt: ArrayBuffer;
  let prfOutput: Uint8Array;
  let ownsPrfOutput: boolean;
  if (protection.prfReuse) {
    prfSalt = protection.prfReuse.prfSalt;
    prfOutput = protection.prfReuse.prfOutput;
    ownsPrfOutput = false; // caller zeros it
  } else {
    prfSalt = generatePrfSalt();
    ({ prfOutput } = await authenticateAndGetPrf(credentialId, prfSalt));
    ownsPrfOutput = true;
  }

  const storedSecret = generateStoredSecret();
  const storedSecretBytes = new Uint8Array(storedSecret);
  try {
    const result = await generateProtectedWithPrf(
      keyOpts,
      prfOutput,
      storedSecretBytes,
    );
    const blob = buildPasskeyBlob(result, credentialId, prfSalt, storedSecret);
    let handle: number | undefined;
    if (protection.cache) {
      const { iv, ct } = unpackPrfBlob(result.blob);
      handle = await unlockWithPrf(
        ct,
        iv,
        prfOutput,
        storedSecretBytes,
        result.meta.keyInfo.keyId,
      );
    }
    return { blob, handle };
  } finally {
    if (ownsPrfOutput) prfOutput.fill(0);
  }
}

/**
 * Import an armored private key (optionally passphrase-protected) and
 * re-protect it under the chosen method. Plaintext cert exists only
 * inside the wasm call. Same KEY_STORE invariants as
 * `generateAndProtect` w/r/t the optional `cache` flag.
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

  if (protection.method === "password") {
    if (!protection.password || protection.password.length < 8) {
      throw new Error("Password must be at least 8 characters");
    }
    const passwordBytes = new TextEncoder().encode(protection.password);
    try {
      const result = await protectImportedWithPassword(
        armoredPrivateKey,
        sourcePassphraseBytes,
        passwordBytes,
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
      );
      const blob = buildPasswordBlob(result);
      let handle: number | undefined;
      if (protection.cache) {
        const { salt, iv, ct } = unpackPasswordBlob(result.blob);
        handle = await unlockWithPassword(
          ct,
          iv,
          salt,
          result.meta.keyInfo.keyId,
          passwordBytes,
          ARGON2_MEMORY_KIB,
          ARGON2_ITERATIONS,
          ARGON2_PARALLELISM,
        );
      }
      return { blob, handle };
    } finally {
      passwordBytes.fill(0);
      if (sourcePassphraseBytes.length > 0) sourcePassphraseBytes.fill(0);
    }
  }

  const userIdHint = common.userIdHint ?? "Imported PGP Key";
  const credentialId = await resolvePasskeyCredential(
    protection.reusePasskeyCredentialId,
    userIdHint,
  );
  const prfSalt = generatePrfSalt();
  const storedSecret = generateStoredSecret();
  const storedSecretBytes = new Uint8Array(storedSecret);
  const { prfOutput } = await authenticateAndGetPrf(credentialId, prfSalt);
  try {
    const result = await protectImportedWithPrf(
      armoredPrivateKey,
      sourcePassphraseBytes,
      prfOutput,
      storedSecretBytes,
    );
    const blob = buildPasskeyBlob(result, credentialId, prfSalt, storedSecret);
    let handle: number | undefined;
    if (protection.cache) {
      const { iv, ct } = unpackPrfBlob(result.blob);
      handle = await unlockWithPrf(
        ct,
        iv,
        prfOutput,
        storedSecretBytes,
        result.meta.keyInfo.keyId,
      );
    }
    return { blob, handle };
  } finally {
    prfOutput.fill(0);
    if (sourcePassphraseBytes.length > 0) sourcePassphraseBytes.fill(0);
  }
}
