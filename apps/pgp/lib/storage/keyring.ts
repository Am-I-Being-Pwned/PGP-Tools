import type {
  EncryptedBlob,
  PasskeyEncryptedBlob,
  PasswordEncryptedBlob,
} from "../protection/encrypt-private-key";
import { STORAGE_KEYRING } from "../constants";
import {
  encryptContacts,
  decryptContacts,
  hasContactsSession,
} from "../pgp/wasm";
import { getItem, removeItem, setItem, withLock } from "./engine";

// ── protection discriminated union ───────────────────────────────────

interface PasswordProtection {
  method: "password";
  kdfSalt: string;
}

interface PasskeyProtection {
  method: "passkey";
  credentialId: string;
  prfSalt: string;
  storedSecret: string;
}

type Protection = PasswordProtection | PasskeyProtection;

// ── key blob ─────────────────────────────────────────────────────────

export interface ProtectedKeyBlob {
  version: 1;
  keyId: string;
  userIds: string[];
  algorithm: string;
  publicKeyArmored: string;
  revocationCertificate?: string;
  protection: Protection;
  encryptedPrivateKey: string; // base64 ciphertext
  iv: string; // base64
  createdAt: number;
  lastUsedAt: number;
}

// ── constructors ─────────────────────────────────────────────────────

export function blobFromEncrypted(
  keyId: string,
  userIds: string[],
  algorithm: string,
  publicKeyArmored: string,
  encrypted: EncryptedBlob,
): ProtectedKeyBlob {
  const protection: Protection =
    encrypted.method === "passkey"
      ? {
          method: "passkey",
          credentialId: encrypted.credentialId,
          prfSalt: encrypted.prfSalt,
          storedSecret: encrypted.storedSecret,
        }
      : {
          method: "password",
          kdfSalt: encrypted.salt,
        };

  return {
    version: 1,
    keyId,
    userIds,
    algorithm,
    publicKeyArmored,
    protection,
    encryptedPrivateKey: encrypted.ciphertext,
    iv: encrypted.iv,
    createdAt: Date.now(),
    lastUsedAt: Date.now(),
  };
}

/** Reconstruct an EncryptedBlob from a stored ProtectedKeyBlob. */
export function encryptedBlobFromProtected(
  blob: ProtectedKeyBlob,
): EncryptedBlob {
  if (blob.protection.method === "passkey") {
    return {
      method: "passkey",
      ciphertext: blob.encryptedPrivateKey,
      iv: blob.iv,
      credentialId: blob.protection.credentialId,
      prfSalt: blob.protection.prfSalt,
      storedSecret: blob.protection.storedSecret,
    } satisfies PasskeyEncryptedBlob;
  }
  return {
    method: "password",
    ciphertext: blob.encryptedPrivateKey,
    iv: blob.iv,
    salt: blob.protection.kdfSalt,
  } satisfies PasswordEncryptedBlob;
}

// ── encrypted storage ───────────────────────────────────────────────
// AES-256-GCM encrypted blob via WASM contacts session key.
// Same scheme as contacts — tamper = decryption failure.

interface EncryptedKeyringBlob {
  iv: string;
  ciphertext: string;
}

function isEncryptedKeyringBlob(v: unknown): v is EncryptedKeyringBlob {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return typeof o.iv === "string" && typeof o.ciphertext === "string";
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function isValidBlob(v: unknown): v is ProtectedKeyBlob {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.keyId === "string" &&
    typeof o.publicKeyArmored === "string" &&
    typeof o.encryptedPrivateKey === "string" &&
    typeof o.iv === "string" &&
    typeof o.protection === "object" &&
    o.protection !== null &&
    typeof (o.protection as Record<string, unknown>).method === "string"
  );
}

// Migration: old format stored a string[] index + per-key plaintext entries.
function keyItemKey(keyId: string): string {
  return `${STORAGE_KEYRING}:${keyId}`;
}

async function migratePlaintextKeyring(ids: unknown[]): Promise<void> {
  const keys: ProtectedKeyBlob[] = [];
  const keysToRemove: string[] = [];

  for (const id of ids) {
    if (typeof id !== "string") continue;
    const key = keyItemKey(id);
    const k = await getItem<unknown>(key);
    if (isValidBlob(k)) keys.push(k);
    keysToRemove.push(key);
  }

  if (keys.length > 0) {
    await saveAll(keys);
  } else {
    await removeItem(STORAGE_KEYRING);
  }

  for (const key of keysToRemove) {
    await removeItem(key);
  }
}

async function loadEncrypted(): Promise<ProtectedKeyBlob[]> {
  if (!(await hasContactsSession())) return [];

  const blob = await getItem<unknown>(STORAGE_KEYRING);
  if (!blob) return [];

  // Migrate old plaintext format if present
  if (!isEncryptedKeyringBlob(blob)) {
    if (Array.isArray(blob)) {
      await migratePlaintextKeyring(blob as unknown[]);
      return loadEncrypted();
    }
    return [];
  }

  const iv = fromBase64(blob.iv);
  const ciphertext = fromBase64(blob.ciphertext);

  const plaintext = await decryptContacts(ciphertext, iv);
  const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));

  if (!Array.isArray(parsed)) return [];
  return parsed.filter(isValidBlob);
}

async function saveAll(keys: ProtectedKeyBlob[]): Promise<void> {
  if (!(await hasContactsSession())) {
    throw new Error("Cannot save keyring: no active contacts session");
  }

  const plaintext = new TextEncoder().encode(JSON.stringify(keys));
  const packed = await encryptContacts(plaintext);

  const iv = packed.slice(0, 12);
  const ciphertext = packed.slice(12);

  const blob: EncryptedKeyringBlob = {
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
  };

  await setItem(STORAGE_KEYRING, blob);
}

// ── CRUD (all mutations serialized via withLock) ─────────────────────

export async function getKeyring(): Promise<ProtectedKeyBlob[]> {
  return loadEncrypted();
}

export async function saveKeyring(keyring: ProtectedKeyBlob[]): Promise<void> {
  await saveAll(keyring);
}

export async function addKey(blob: ProtectedKeyBlob): Promise<void> {
  await withLock(STORAGE_KEYRING, async () => {
    const keyring = await loadEncrypted();
    const updated = [
      ...keyring.filter((k) => k.keyId !== blob.keyId),
      blob,
    ];
    await saveAll(updated);
  });
}

export async function removeKey(keyId: string): Promise<void> {
  await withLock(STORAGE_KEYRING, async () => {
    const keyring = await loadEncrypted();
    const updated = keyring.filter((k) => k.keyId !== keyId);
    if (updated.length === 0) {
      await removeItem(STORAGE_KEYRING);
    } else {
      await saveAll(updated);
    }
  });
}

export async function updateLastUsed(keyId: string): Promise<void> {
  await withLock(STORAGE_KEYRING, async () => {
    const keyring = await loadEncrypted();
    const key = keyring.find((k) => k.keyId === keyId);
    if (key) {
      key.lastUsedAt = Date.now();
      await saveAll(keyring);
    }
  });
}
