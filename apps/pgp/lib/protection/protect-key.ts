import type { KeyInfo } from "../pgp/types";
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

/**
 * Encrypt a private key and build a ProtectedKeyBlob.
 * Handles the full passkey registration + PRF flow or password encryption.
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
}): Promise<ProtectedKeyBlob> {
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
    const { prfOutput } = await authenticateAndGetPrf(credentialId, prfSalt);
    const aesKey = await deriveKeyFromPrf(prfOutput, storedSecret);
    prfOutput.fill(0);

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
    return blob;
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
  return blob;
}
