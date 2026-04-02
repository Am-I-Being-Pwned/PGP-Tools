import type { KeyInfo } from "../pgp/types";
import * as wasmApi from "../pgp/wasm";
import type { ProtectedKeyBlob } from "../storage/keyring";
import { blobFromEncrypted } from "../storage/keyring";
import { encryptWithPasskey, encryptWithPassword } from "./encrypt-private-key";
import {
  authenticateAndGetPrf,
  deriveKeyFromPrf,
  generatePrfSalt,
  generateStoredSecret,
  registerPasskey,
} from "./webauthn-prf";

export interface ProtectAndStoreResult {
  blob: ProtectedKeyBlob;
  /** WASM key handle for the decrypted private key, if caching was requested. */
  keyHandle?: number;
}

/**
 * Encrypt a private key and build a ProtectedKeyBlob.
 * Handles the full passkey registration + PRF flow or password encryption.
 * Optionally caches the decrypted key in WASM and returns the handle.
 */
export async function protectAndStoreKey(opts: {
  privateKeyArmored: string;
  publicKeyArmored: string;
  keyInfo: KeyInfo;
  method: "passkey" | "password";
  password?: string;
  revocationCertificate?: string;
  /** Reuse an existing passkey credential instead of registering a new one. */
  reusePasskeyCredentialId?: string;
  /** If true, also store the decrypted key in WASM and return the handle. */
  cacheKey?: boolean;
}): Promise<ProtectAndStoreResult> {
  const { privateKeyArmored, publicKeyArmored, keyInfo, method, password } =
    opts;

  if (method === "password" && (!password || password.length < 8)) {
    throw new Error("Password must be at least 8 characters");
  }

  if (method === "passkey") {
    let credentialId: string;

    if (opts.reusePasskeyCredentialId) {
      // Reuse existing passkey credential — no new registration.
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

    // Fresh salts ensure a unique derived key even when reusing the credential.
    const prfSalt = generatePrfSalt();
    const storedSecret = generateStoredSecret();
    let prfOutput: Uint8Array | undefined;
    let aesKey: CryptoKey;
    try {
      ({ prfOutput } = await authenticateAndGetPrf(credentialId, prfSalt));
      aesKey = await deriveKeyFromPrf(prfOutput, storedSecret);
    } finally {
      prfOutput?.fill(0);
    }

    const encrypted = await encryptWithPasskey(
      privateKeyArmored,
      aesKey,
      credentialId,
      prfSalt,
      storedSecret,
      keyInfo.keyId,
    );

    const blob = blobFromEncrypted(
      keyInfo.keyId,
      keyInfo.userIds,
      keyInfo.algorithm,
      publicKeyArmored,
      encrypted,
    );
    blob.revocationCertificate = opts.revocationCertificate;

    let keyHandle: number | undefined;
    if (opts.cacheKey) {
      keyHandle = await wasmApi.storeKey(privateKeyArmored);
    }

    return { blob, keyHandle };
  }

  const encrypted = await encryptWithPassword(
    privateKeyArmored,
    password ?? "",
    keyInfo.keyId,
  );

  const blob = blobFromEncrypted(
    keyInfo.keyId,
    keyInfo.userIds,
    keyInfo.algorithm,
    publicKeyArmored,
    encrypted,
  );
  blob.revocationCertificate = opts.revocationCertificate;

  let keyHandle: number | undefined;
  if (opts.cacheKey) {
    keyHandle = await wasmApi.storeKey(privateKeyArmored);
  }

  return { blob, keyHandle };
}
