import type { KeyInfo } from "../pgp/types";
import {
  encryptHandleWithPassword,
  encryptHandleWithPrf,
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

function toBase64(bytes: ArrayBufferView | ArrayBuffer): string {
  const view =
    bytes instanceof ArrayBuffer
      ? new Uint8Array(bytes)
      : new Uint8Array(
          bytes.buffer,
          bytes.byteOffset,
          bytes.byteLength,
        );
  let binary = "";
  for (const byte of view) binary += String.fromCharCode(byte);
  return btoa(binary);
}

interface ProtectHandleOpts {
  /** Handle for a cert already stored in WASM. Caller owns its lifetime. */
  handle: number;
  keyInfo: KeyInfo;
  publicKeyArmored: string;
  revocationCertificate?: string;
  method: "password" | "passkey";
  password?: string;
  reusePasskeyCredentialId?: string;
}

/**
 * Build a ProtectedKeyBlob from a stored cert handle without ever
 * surfacing the cert's plaintext secret material to JS. AES-GCM
 * encryption runs inside WASM against the cert's serialized bytes.
 */
export async function protectHandleAndBuildBlob(
  opts: ProtectHandleOpts,
): Promise<ProtectedKeyBlob> {
  const { handle, keyInfo, publicKeyArmored, method, password } = opts;

  if (method === "password") {
    if (!password || password.length < 8) {
      throw new Error("Password must be at least 8 characters");
    }
    const passwordBytes = new TextEncoder().encode(password);
    let packed: Uint8Array;
    try {
      packed = await encryptHandleWithPassword(
        handle,
        passwordBytes,
        keyInfo.keyId,
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
      );
    } finally {
      passwordBytes.fill(0);
    }

    const salt = packed.slice(0, 16);
    const iv = packed.slice(16, 28);
    const ciphertext = packed.slice(28);

    const blob = blobFromEncrypted(
      keyInfo.keyId,
      keyInfo.userIds,
      keyInfo.algorithm,
      publicKeyArmored,
      {
        method: "password",
        ciphertext: toBase64(ciphertext),
        iv: toBase64(iv),
        salt: toBase64(salt),
      },
    );
    blob.revocationCertificate = opts.revocationCertificate;
    return blob;
  }

  let credentialId: string;
  if (opts.reusePasskeyCredentialId) {
    credentialId = opts.reusePasskeyCredentialId;
  } else {
    const userId = keyInfo.userIds[0] || keyInfo.keyId.slice(-16);
    const reg = await registerPasskey(userId, userId);
    if (!reg.prfEnabled) {
      throw new Error(
        "Your authenticator doesn't support PRF. Try a different passkey or use a password instead.",
      );
    }
    credentialId = reg.credentialId;
  }

  const prfSalt = generatePrfSalt();
  const storedSecret = generateStoredSecret();

  const { prfOutput } = await authenticateAndGetPrf(credentialId, prfSalt);
  // storedSecret is persisted in the blob (HKDF salt) -- not a secret itself.
  let packed: Uint8Array;
  try {
    packed = await encryptHandleWithPrf(
      handle,
      prfOutput,
      new Uint8Array(storedSecret),
      keyInfo.keyId,
    );
  } finally {
    prfOutput.fill(0);
  }

  const iv = packed.slice(0, 12);
  const ciphertext = packed.slice(12);

  const blob = blobFromEncrypted(
    keyInfo.keyId,
    keyInfo.userIds,
    keyInfo.algorithm,
    publicKeyArmored,
    {
      method: "passkey",
      ciphertext: toBase64(ciphertext),
      iv: toBase64(iv),
      credentialId,
      prfSalt: toBase64(prfSalt),
      storedSecret: toBase64(storedSecret),
    },
  );
  blob.revocationCertificate = opts.revocationCertificate;
  return blob;
}
