/**
 * Shared load/save for the encrypted JSON-array blobs that back the
 * keyring and contacts stores.
 *
 * Both stores use the same scheme: the array is serialised to JSON,
 * encrypted with AES-256-GCM under the in-WASM contacts session key,
 * and persisted as `{ iv, ciphertext }` (base64). Tampering with the
 * stored blob makes decryption fail.
 *
 * Also handles the one legacy migration both stores share: the old
 * plaintext format kept a `string[]` index at the storage key plus one
 * plaintext entry per item at `${storageKey}:${id}`.
 */

import { fromBase64, toBase64, unpackIvCiphertext } from "../encoding";
import {
  decryptContacts,
  encryptContacts,
  hasContactsSession,
} from "../pgp/wasm";
import { getItem, removeItem, setItem } from "./engine";

interface EncryptedStoreBlob {
  iv: string;
  ciphertext: string;
}

function isEncryptedStoreBlob(v: unknown): v is EncryptedStoreBlob {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return typeof o.iv === "string" && typeof o.ciphertext === "string";
}

export interface EncryptedStore<T> {
  /** chrome.storage key the encrypted blob lives under. */
  storageKey: string;
  /** Runtime validator applied to every deserialised item. */
  isValid: (v: unknown) => v is T;
  /** Human label for error messages ("keyring", "contacts"). */
  label: string;
}

export async function loadEncryptedArray<T>(
  store: EncryptedStore<T>,
): Promise<T[]> {
  if (!(await hasContactsSession())) return [];

  const blob = await getItem<unknown>(store.storageKey);
  if (!blob) return [];

  // Migrate old plaintext format if present
  if (!isEncryptedStoreBlob(blob)) {
    if (Array.isArray(blob)) {
      await migrateLegacyPlaintext(store, blob as unknown[]);
      return loadEncryptedArray(store);
    }
    return [];
  }

  const plaintext = await decryptContacts(
    fromBase64(blob.ciphertext),
    fromBase64(blob.iv),
  );
  const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));

  if (!Array.isArray(parsed)) return [];
  return parsed.filter(store.isValid);
}

export async function saveEncryptedArray<T>(
  store: EncryptedStore<T>,
  items: T[],
): Promise<void> {
  if (!(await hasContactsSession())) {
    throw new Error(`Cannot save ${store.label}: no active contacts session`);
  }

  const plaintext = new TextEncoder().encode(JSON.stringify(items));
  const packed = await encryptContacts(plaintext);
  const { iv, ciphertext } = unpackIvCiphertext(packed);

  await setItem<EncryptedStoreBlob>(store.storageKey, {
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
  });
}

async function migrateLegacyPlaintext<T>(
  store: EncryptedStore<T>,
  ids: unknown[],
): Promise<void> {
  const items: T[] = [];
  const keysToRemove: string[] = [];

  for (const id of ids) {
    if (typeof id !== "string") continue;
    const key = `${store.storageKey}:${id}`;
    const item = await getItem<unknown>(key);
    if (store.isValid(item)) items.push(item);
    keysToRemove.push(key);
  }

  if (items.length > 0) {
    await saveEncryptedArray(store, items);
  } else {
    await removeItem(store.storageKey);
  }

  for (const key of keysToRemove) {
    await removeItem(key);
  }
}
