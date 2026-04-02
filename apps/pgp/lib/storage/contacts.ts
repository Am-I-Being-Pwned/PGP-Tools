import { STORAGE_CONTACTS } from "../constants";
import { getItem, removeItem, setItem } from "./engine";

// ── public contact type ─────────────────────────────────────────────

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

/** Per-contact storage key. */
function contactItemKey(keyId: string): string {
  return `${STORAGE_CONTACTS}:${keyId}`;
}

// ── CRUD (index + per-item keys to stay within sync quota) ──────────

export async function loadContacts(): Promise<PublicContactKey[]> {
  const ids = (await getItem<string[]>(STORAGE_CONTACTS)) ?? [];
  if (ids.length === 0) return [];

  const contacts: PublicContactKey[] = [];
  for (const id of ids) {
    const c = await getItem<unknown>(contactItemKey(id));
    if (isValidContact(c)) contacts.push(c);
  }
  return contacts;
}

export async function saveContacts(
  contacts: PublicContactKey[],
): Promise<void> {
  // Write each contact under its own key
  for (const c of contacts) {
    await setItem(contactItemKey(c.keyId), c);
  }
  // Write the index
  const ids = contacts.map((c) => c.keyId);
  await setItem(STORAGE_CONTACTS, ids);
}

export async function saveContact(contact: PublicContactKey): Promise<void> {
  await setItem(contactItemKey(contact.keyId), contact);
  const ids = (await getItem<string[]>(STORAGE_CONTACTS)) ?? [];
  if (!ids.includes(contact.keyId)) {
    ids.push(contact.keyId);
    await setItem(STORAGE_CONTACTS, ids);
  }
}

export async function removeContact(keyId: string): Promise<void> {
  await removeItem(contactItemKey(keyId));
  const ids = (await getItem<string[]>(STORAGE_CONTACTS)) ?? [];
  const updated = ids.filter((id) => id !== keyId);
  if (updated.length === 0) {
    await removeItem(STORAGE_CONTACTS);
  } else {
    await setItem(STORAGE_CONTACTS, updated);
  }
}

/** Delete all contact data from storage. */
export async function deleteContactsBlob(): Promise<void> {
  const ids = (await getItem<string[]>(STORAGE_CONTACTS)) ?? [];
  for (const id of ids) {
    await removeItem(contactItemKey(id));
  }
  await removeItem(STORAGE_CONTACTS);
}
