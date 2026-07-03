import { STORAGE_CONTACTS } from "../constants";
import { removeItem } from "./engine";
import { loadEncryptedArray, saveEncryptedArray } from "./encrypted-store";

export interface PublicContactKey {
  keyId: string;
  userIds: string[];
  algorithm: string;
  armoredPublicKey: string;
  addedAt: number;
  lastUsedAt: number;
  expiresAt?: number | null;
  /** Non-blocking flag from key parsing (e.g. relies on a SHA-1 binding
   *  signature). Shown as a warning badge; the key is still usable. */
  securityWarning?: string;
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
// Same scheme as the keyring — see encrypted-store.ts.
const CONTACTS_STORE = {
  storageKey: STORAGE_CONTACTS,
  isValid: isValidContact,
  label: "contacts",
};

export async function loadContacts(): Promise<PublicContactKey[]> {
  return loadEncryptedArray(CONTACTS_STORE);
}

function saveAll(contacts: PublicContactKey[]): Promise<void> {
  return saveEncryptedArray(CONTACTS_STORE, contacts);
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
