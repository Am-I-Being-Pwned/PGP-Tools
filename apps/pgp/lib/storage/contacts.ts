import { STORAGE_CONTACTS } from "../constants";
import {
  encryptContacts,
  decryptContacts,
  hasContactsSession,
} from "../pgp/wasm";
import { getItem, removeItem, setItem } from "./engine";

export interface PublicContactKey {
  keyId: string;
  userIds: string[];
  algorithm: string;
  armoredPublicKey: string;
  addedAt: number;
  lastUsedAt: number;
  expiresAt?: number | null;
}

function isValidContact(v: unknown): v is PublicContactKey {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.keyId === "string" &&
    typeof o.armoredPublicKey === "string" &&
    Array.isArray(o.userIds)
  );
}

// AES-256-GCM encrypted blob via WASM contacts session key.
// AAD: "gpg-tools:contacts:master" — tamper = decryption failure.
interface EncryptedContactsBlob {
  iv: string;
  ciphertext: string;
}

function isEncryptedBlob(v: unknown): v is EncryptedContactsBlob {
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

// Migration: old format stored a string[] index + per-key plaintext entries.
function contactItemKey(keyId: string): string {
  return `${STORAGE_CONTACTS}:${keyId}`;
}

async function migratePlaintextContacts(ids: unknown[]): Promise<void> {
  const contacts: PublicContactKey[] = [];
  const keysToRemove: string[] = [];

  for (const id of ids) {
    if (typeof id !== "string") continue;
    const key = contactItemKey(id);
    const c = await getItem<unknown>(key);
    if (isValidContact(c)) contacts.push(c);
    keysToRemove.push(key);
  }

  if (contacts.length > 0) {
    await saveAll(contacts);
  } else {
    await removeItem(STORAGE_CONTACTS);
  }

  for (const key of keysToRemove) {
    await removeItem(key);
  }
}

export async function loadContacts(): Promise<PublicContactKey[]> {
  if (!(await hasContactsSession())) return [];

  const blob = await getItem<unknown>(STORAGE_CONTACTS);
  if (!blob) return [];

  // Migrate old plaintext format if present
  if (!isEncryptedBlob(blob)) {
    if (Array.isArray(blob)) {
      await migratePlaintextContacts(blob as unknown[]);
      return loadContacts();
    }
    return [];
  }

  const iv = fromBase64(blob.iv);
  const ciphertext = fromBase64(blob.ciphertext);

  const plaintext = await decryptContacts(ciphertext, iv);
  const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));

  if (!Array.isArray(parsed)) return [];
  return parsed.filter(isValidContact);
}

async function saveAll(contacts: PublicContactKey[]): Promise<void> {
  if (!(await hasContactsSession())) {
    throw new Error("Cannot save contacts: no active contacts session");
  }

  const plaintext = new TextEncoder().encode(JSON.stringify(contacts));
  const packed = await encryptContacts(plaintext);

  const iv = packed.slice(0, 12);
  const ciphertext = packed.slice(12);

  const blob: EncryptedContactsBlob = {
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
  };

  await setItem(STORAGE_CONTACTS, blob);
}

export async function saveContacts(
  contacts: PublicContactKey[],
): Promise<void> {
  await saveAll(contacts);
}

export async function saveContact(contact: PublicContactKey): Promise<void> {
  const existing = await loadContacts();
  const updated = [
    ...existing.filter((c) => c.keyId !== contact.keyId),
    contact,
  ];
  await saveAll(updated);
}

export async function removeContact(keyId: string): Promise<void> {
  const existing = await loadContacts();
  const updated = existing.filter((c) => c.keyId !== keyId);
  if (updated.length === 0) {
    await removeItem(STORAGE_CONTACTS);
  } else {
    await saveAll(updated);
  }
}

export async function deleteContactsBlob(): Promise<void> {
  await removeItem(STORAGE_CONTACTS);
}
