import { STORAGE_CONTACTS } from "../constants";
import { getItem, removeItem, setItem, withLock } from "./engine";

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

/** Per-contact storage key */
function contactKey(keyId: string): string {
  return `${STORAGE_CONTACTS}:${keyId}`;
}

export async function getContacts(): Promise<PublicContactKey[]> {
  const ids = (await getItem<string[]>(STORAGE_CONTACTS)) ?? [];
  if (ids.length === 0) return [];

  const contacts: PublicContactKey[] = [];
  for (const id of ids) {
    const c = await getItem<unknown>(contactKey(id));
    if (isValidContact(c)) contacts.push(c);
  }
  return contacts;
}

export async function addContact(contact: PublicContactKey): Promise<void> {
  await withLock(STORAGE_CONTACTS, async () => {
    const contacts = await getContacts();
    const ids = contacts.map((c) => c.keyId);

    if (!ids.includes(contact.keyId)) {
      ids.push(contact.keyId);
    }

    await setItem(contactKey(contact.keyId), contact);
    await setItem(STORAGE_CONTACTS, ids);
  });
}

export async function removeContact(keyId: string): Promise<void> {
  await withLock(STORAGE_CONTACTS, async () => {
    const contacts = await getContacts();
    const ids = contacts.filter((c) => c.keyId !== keyId).map((c) => c.keyId);
    await removeItem(contactKey(keyId));
    await setItem(STORAGE_CONTACTS, ids);
  });
}
