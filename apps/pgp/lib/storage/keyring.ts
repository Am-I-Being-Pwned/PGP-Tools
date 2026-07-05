import type {
  EncryptedBlob,
  PasskeyEncryptedBlob,
  PasswordEncryptedBlob,
} from "../protection/encrypt-private-key";
import { STORAGE_KEYRING } from "../constants";
import { loadEncryptedArray, saveEncryptedArray } from "./encrypted-store";
import { removeItem, withLock } from "./engine";

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
  /** Local, user-set display name. Never touches the certificate: the
   *  User IDs remain the cryptographic identity; this is just what the
   *  UI shows. Cleared (undefined) reverts to the first User ID. */
  alias?: string;
  publicKeyArmored: string;
  revocationCertificate?: string;
  /** Non-blocking flag from key parsing (e.g. relies on a SHA-1 binding
   *  signature). Shown as a warning badge; the key is still usable. */
  securityWarning?: string;
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
// Same scheme as contacts — see encrypted-store.ts.

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

const KEYRING_STORE = {
  storageKey: STORAGE_KEYRING,
  isValid: isValidBlob,
  label: "keyring",
};

function loadEncrypted(): Promise<ProtectedKeyBlob[]> {
  return loadEncryptedArray(KEYRING_STORE);
}

function saveAll(keys: ProtectedKeyBlob[]): Promise<void> {
  return saveEncryptedArray(KEYRING_STORE, keys);
}

// ── CRUD (all mutations serialized via withLock) ─────────────────────

export async function getKeyring(): Promise<ProtectedKeyBlob[]> {
  return loadEncrypted();
}

export async function addKey(blob: ProtectedKeyBlob): Promise<void> {
  await withLock(STORAGE_KEYRING, async () => {
    const keyring = await loadEncrypted();
    const updated = [...keyring.filter((k) => k.keyId !== blob.keyId), blob];
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

/** Set (or clear, with an empty/blank value) a key's local display
 *  alias. Non-destructive: only the stored metadata changes. */
export async function updateAlias(keyId: string, alias: string): Promise<void> {
  const trimmed = alias.trim();
  await withLock(STORAGE_KEYRING, async () => {
    const keyring = await loadEncrypted();
    const key = keyring.find((k) => k.keyId === keyId);
    if (key) {
      key.alias = trimmed || undefined;
      await saveAll(keyring);
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
