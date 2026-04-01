import { STORAGE_CONTACTS } from "../constants";
import { fromBase64, toBase64 } from "../encoding";
import * as wasmApi from "../pgp/wasm";
import { getItem, removeItem, setItem, withLock } from "./engine";

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

// ── encrypted blob stored in chrome.storage ─────────────────────────

export interface EncryptedContactsBlob {
  version: 1;
  ciphertext: string; // base64
  iv: string; // base64
}

function isEncryptedBlob(v: unknown): v is EncryptedContactsBlob {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    o.version === 1 &&
    typeof o.ciphertext === "string" &&
    typeof o.iv === "string"
  );
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

/** Per-contact storage key (legacy format only). */
function legacyContactKey(keyId: string): string {
  return `${STORAGE_CONTACTS}:${keyId}`;
}

// ── encrypted CRUD (all crypto happens in WASM session) ─────────────

export async function loadAndDecryptContacts(): Promise<PublicContactKey[]> {
  const raw = await getItem<unknown>(STORAGE_CONTACTS);
  if (!isEncryptedBlob(raw)) return [];

  const plaintext = await wasmApi.decryptContacts(
    new Uint8Array(fromBase64(raw.ciphertext)),
    new Uint8Array(fromBase64(raw.iv)),
  );

  const json = new TextDecoder().decode(plaintext);
  const parsed: unknown = JSON.parse(json);
  if (!Array.isArray(parsed)) return [];
  return parsed.filter(isValidContact);
}

export async function encryptAndSaveContacts(
  contacts: PublicContactKey[],
): Promise<void> {
  const json = new TextEncoder().encode(JSON.stringify(contacts));
  const packed = await wasmApi.encryptContacts(json);

  // Packed format: [12-byte IV][ciphertext]
  const iv = packed.slice(0, 12);
  const ciphertext = packed.slice(12);

  const blob: EncryptedContactsBlob = {
    version: 1,
    ciphertext: toBase64(ciphertext.buffer),
    iv: toBase64(iv.buffer),
  };
  await setItem(STORAGE_CONTACTS, blob);
}

export async function addContactEncrypted(
  contact: PublicContactKey,
): Promise<void> {
  await withLock(STORAGE_CONTACTS, async () => {
    const contacts = await loadAndDecryptContacts();
    if (!contacts.some((c) => c.keyId === contact.keyId)) {
      contacts.push(contact);
    }
    await encryptAndSaveContacts(contacts);
  });
}

export async function removeContactEncrypted(
  keyId: string,
): Promise<void> {
  await withLock(STORAGE_CONTACTS, async () => {
    const contacts = await loadAndDecryptContacts();
    const filtered = contacts.filter((c) => c.keyId !== keyId);
    if (filtered.length === 0) {
      await removeItem(STORAGE_CONTACTS);
    } else {
      await encryptAndSaveContacts(filtered);
    }
  });
}

// ── migration from legacy plaintext format ──────────────────────────

/** Check whether the stored contacts are in the old plaintext format. */
export async function hasLegacyContacts(): Promise<boolean> {
  const raw = await getItem<unknown>(STORAGE_CONTACTS);
  return Array.isArray(raw);
}

/** Read contacts from the legacy per-key plaintext format. */
async function readLegacyContacts(): Promise<PublicContactKey[]> {
  const ids = (await getItem<string[]>(STORAGE_CONTACTS)) ?? [];
  if (ids.length === 0) return [];

  const contacts: PublicContactKey[] = [];
  for (const id of ids) {
    const c = await getItem<unknown>(legacyContactKey(id));
    if (isValidContact(c)) contacts.push(c);
  }
  return contacts;
}

/** Migrate plaintext contacts to encrypted format and clean up old keys. */
export async function migrateLegacyContacts(): Promise<void> {
  await withLock(STORAGE_CONTACTS, async () => {
    const raw = await getItem<unknown>(STORAGE_CONTACTS);
    if (!Array.isArray(raw)) return; // already migrated or empty

    const contacts = await readLegacyContacts();
    await encryptAndSaveContacts(contacts);

    // Clean up old per-contact keys
    for (const id of raw as string[]) {
      await removeItem(legacyContactKey(id));
    }
  });
}

/** Check whether any encrypted contacts blob exists in storage. */
export async function hasEncryptedContacts(): Promise<boolean> {
  const raw = await getItem<unknown>(STORAGE_CONTACTS);
  return isEncryptedBlob(raw);
}

/** Delete the contacts blob entirely. */
export async function clearContacts(): Promise<void> {
  await removeItem(STORAGE_CONTACTS);
}
