/**
 * Encrypted-private-key blob formats, AAD-bound via
 * `gpg-tools:{method}:{keyId}`. A format change must be coordinated with
 * the writer, reader and WASM `unlockWith*` paths.
 */

export interface PasswordEncryptedBlob {
  method: "password";
  ciphertext: string; // base64
  iv: string; // base64
  salt: string; // base64 (Argon2id salt)
}

export interface PasskeyEncryptedBlob {
  method: "passkey";
  ciphertext: string; // base64
  iv: string; // base64
  credentialId: string; // base64url
  prfSalt: string; // base64
  storedSecret: string; // base64 - mixed with PRF output via HKDF
}

export type EncryptedBlob = PasswordEncryptedBlob | PasskeyEncryptedBlob;
