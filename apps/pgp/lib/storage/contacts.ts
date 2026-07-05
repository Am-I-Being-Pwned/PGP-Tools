import { STORAGE_CONTACTS } from "../constants";
import {
  loadEncryptedArray,
  normalizePadding,
  saveEncryptedArray,
} from "./encrypted-store";
import { removeItem } from "./engine";

export interface PublicContactKey {
  keyId: string;
  userIds: string[];
  algorithm: string;
  armoredPublicKey: string;
  addedAt: number;
  lastUsedAt: number;
  expiresAt?: number | null;
  /** Whether this contact can be encrypted to (has a usable encryption
   *  key). False for sign-only keys, which are still valid contacts for
   *  signature verification but must not appear as encryption recipients.
   *  `undefined` on legacy records until backfilled -- treat as `true`. */
  usableForEncryption?: boolean;
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

/** One-time upgrade of an unpadded contacts blob to canonical padding. */
export function normalizeContactsPadding(): Promise<void> {
  return normalizePadding(CONTACTS_STORE);
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
