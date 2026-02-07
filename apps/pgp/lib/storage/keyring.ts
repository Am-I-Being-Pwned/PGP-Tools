import type {
  EncryptedBlob,
  PasskeyEncryptedBlob,
  PasswordEncryptedBlob,
} from "../protection/encrypt-private-key";
import { STORAGE_KEYRING } from "../constants";
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

// ── CRUD (all mutations serialized via withLock) ─────────────────────

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

/** Per-key storage key */
function keyItemKey(keyId: string): string {
  return `${STORAGE_KEYRING}:${keyId}`;
}

export async function getKeyring(): Promise<ProtectedKeyBlob[]> {
  const ids = (await getItem<string[]>(STORAGE_KEYRING)) ?? [];
  if (ids.length === 0) return [];

  const keys: ProtectedKeyBlob[] = [];
  for (const id of ids) {
    const k = await getItem<unknown>(keyItemKey(id));
    if (isValidBlob(k)) keys.push(k);
  }
  return keys;
}

export async function saveKeyring(keyring: ProtectedKeyBlob[]): Promise<void> {
  const ids: string[] = [];
  for (const k of keyring) {
    await setItem(keyItemKey(k.keyId), k);
    ids.push(k.keyId);
  }
  await setItem(STORAGE_KEYRING, ids);
}

export async function addKey(blob: ProtectedKeyBlob): Promise<void> {
  await withLock(STORAGE_KEYRING, async () => {
    const keyring = await getKeyring();
    const ids = keyring.map((k) => k.keyId);

    if (!ids.includes(blob.keyId)) {
      ids.push(blob.keyId);
    }

    await setItem(keyItemKey(blob.keyId), blob);
    await setItem(STORAGE_KEYRING, ids);
  });
}

export async function removeKey(keyId: string): Promise<void> {
  await withLock(STORAGE_KEYRING, async () => {
    const keyring = await getKeyring();
    const ids = keyring.filter((k) => k.keyId !== keyId).map((k) => k.keyId);
    await removeItem(keyItemKey(keyId));
    await setItem(STORAGE_KEYRING, ids);
  });
}

export async function updateLastUsed(keyId: string): Promise<void> {
  await withLock(STORAGE_KEYRING, async () => {
    const k = await getItem<unknown>(keyItemKey(keyId));
    if (isValidBlob(k)) {
      k.lastUsedAt = Date.now();
      await setItem(keyItemKey(keyId), k);
    }
  });
}
