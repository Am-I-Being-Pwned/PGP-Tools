/**
 * Wire-format types for the encrypted-private-key blobs that go into the
 * keyring. Both fields are AAD-bound to the key fingerprint via
 * `gpg-tools:{method}:{keyId}` -- changing the format means coordinating
 * `protect-flow.ts` (writer), `useKeySession.ts` (reader), and the
 * `unlockWith*` paths in WASM.
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
