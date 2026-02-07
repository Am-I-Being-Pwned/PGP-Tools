import { fromBase64, toBase64 } from "../encoding";
import { deriveKeyFromPassword, generateSalt } from "./password-kdf";

const IV_LENGTH = 12;

// ── low-level AES-GCM encrypt/decrypt with a CryptoKey ──────────────

/** Build AAD that binds ciphertext to a specific key + method.
 *  Prevents swapping encrypted blobs between key entries. */
function buildAad(keyId: string, method: string): ArrayBuffer {
  return new TextEncoder().encode(`gpg-tools:${method}:${keyId}`).buffer;
}

async function aesEncrypt(
  plaintext: string,
  key: CryptoKey,
  aad: ArrayBuffer,
): Promise<{ ciphertext: ArrayBuffer; iv: ArrayBuffer }> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH)).buffer;
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    key,
    encoded,
  );
  encoded.fill(0);
  return { ciphertext, iv };
}

async function aesDecrypt(
  ciphertext: ArrayBuffer,
  iv: ArrayBuffer,
  key: CryptoKey,
  aad: ArrayBuffer,
): Promise<string> {
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    key,
    ciphertext,
  );
  return new TextDecoder().decode(decrypted);
}

// ── password path (Argon2id) ────────────────────────────────────────

export interface PasswordEncryptedBlob {
  method: "password";
  ciphertext: string; // base64
  iv: string; // base64
  salt: string; // base64 (Argon2id salt)
}

export async function encryptWithPassword(
  armoredPrivateKey: string,
  password: string,
  keyId: string,
): Promise<PasswordEncryptedBlob> {
  const salt = generateSalt();
  const key = await deriveKeyFromPassword(password, salt);
  const aad = buildAad(keyId, "password");
  const { ciphertext, iv } = await aesEncrypt(armoredPrivateKey, key, aad);
  return {
    method: "password",
    ciphertext: toBase64(ciphertext),
    iv: toBase64(iv),
    salt: toBase64(salt),
  };
}

export async function decryptWithPassword(
  blob: PasswordEncryptedBlob,
  password: string,
  keyId: string,
): Promise<string> {
  const key = await deriveKeyFromPassword(password, fromBase64(blob.salt));
  const aad = buildAad(keyId, "password");
  return aesDecrypt(fromBase64(blob.ciphertext), fromBase64(blob.iv), key, aad);
}

// ── passkey (WebAuthn PRF) path ──────────────────────────────────────

export interface PasskeyEncryptedBlob {
  method: "passkey";
  ciphertext: string; // base64
  iv: string; // base64
  credentialId: string; // base64url
  prfSalt: string; // base64
  storedSecret: string; // base64 - mixed with PRF output via HKDF
}

export async function encryptWithPasskey(
  armoredPrivateKey: string,
  aesKey: CryptoKey,
  credentialId: string,
  prfSalt: ArrayBuffer,
  storedSecret: ArrayBuffer,
  keyId: string,
): Promise<PasskeyEncryptedBlob> {
  const aad = buildAad(keyId, "passkey");
  const { ciphertext, iv } = await aesEncrypt(armoredPrivateKey, aesKey, aad);
  return {
    method: "passkey",
    ciphertext: toBase64(ciphertext),
    iv: toBase64(iv),
    credentialId,
    prfSalt: toBase64(prfSalt),
    storedSecret: toBase64(storedSecret),
  };
}

export async function decryptWithPasskey(
  blob: PasskeyEncryptedBlob,
  aesKey: CryptoKey,
  keyId: string,
): Promise<string> {
  const aad = buildAad(keyId, "passkey");
  return aesDecrypt(
    fromBase64(blob.ciphertext),
    fromBase64(blob.iv),
    aesKey,
    aad,
  );
}

// ── union type ───────────────────────────────────────────────────────

export type EncryptedBlob = PasswordEncryptedBlob | PasskeyEncryptedBlob;
