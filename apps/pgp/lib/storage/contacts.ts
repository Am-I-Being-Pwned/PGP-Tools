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

// ── plaintext CRUD ──────────────────────────────────────────────────

export async function loadContacts(): Promise<PublicContactKey[]> {
  const raw = await getItem<unknown>(STORAGE_CONTACTS);
  if (!Array.isArray(raw)) return [];
  return raw.filter(isValidContact);
}

export async function saveContacts(
  contacts: PublicContactKey[],
): Promise<void> {
  await setItem(STORAGE_CONTACTS, contacts);
}

/** Delete the contacts blob from storage. */
export async function deleteContactsBlob(): Promise<void> {
  await removeItem(STORAGE_CONTACTS);
}
