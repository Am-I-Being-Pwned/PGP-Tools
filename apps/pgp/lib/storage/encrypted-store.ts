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

import type { StorageLocation } from "./preferences";
import { fromBase64, toBase64, unpackIvCiphertext } from "../encoding";
import {
  decryptContacts,
  encryptContacts,
  hasContactsSession,
} from "../pgp/wasm";
import {
  currentStorageLocation,
  getItem,
  removeItem,
  setItem,
  withLock,
} from "./engine";
import { isCanonicalPadding, padPlaintext, unpadPlaintext } from "./padding";

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
  // Strip length-hiding padding (no-op for legacy unpadded blobs).
  const json = unpadPlaintext(plaintext);
  const parsed: unknown = JSON.parse(new TextDecoder().decode(json));

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

  // Pad to a coarse size bucket so the stored blob length hides the item
  // count. Skipped on `sync`, whose 8 KB/item cap can't absorb padding.
  const json = new TextEncoder().encode(JSON.stringify(items));
  const pad = (await currentStorageLocation()) === "local";
  const plaintext = padPlaintext(json, pad);
  const packed = await encryptContacts(plaintext);
  const { iv, ciphertext } = unpackIvCiphertext(packed);

  await setItem<EncryptedStoreBlob>(store.storageKey, {
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
  });
}

function area(loc: StorageLocation) {
  return loc === "sync" ? chrome.storage.sync : chrome.storage.local;
}

/**
 * Copy one encrypted blob to another storage area, re-packing it for the
 * destination. A raw byte-copy would carry a `local` blob's length-hiding
 * padding to `sync`, where the padded ciphertext can exceed the 8 KB/item
 * quota. So we decrypt, strip
 * padding, re-pad for the destination (`local` pads, `sync` doesn't),
 * re-encrypt, and write.
 *
 * This does NOT remove the source -- the caller commits the move by
 * switching the active location, then calls `purgeEncryptedBlob` on the
 * old area. Sequencing it that way means a crash before the commit leaves
 * the originals in place and reads still find them; a crash after leaves
 * only harmless duplicates. Requires an active session. A value that
 * isn't an encrypted blob (absent, or a not-yet-migrated legacy format)
 * is copied verbatim so nothing is dropped.
 */
export async function copyEncryptedBlobRepacked(
  storageKey: string,
  from: StorageLocation,
  to: StorageLocation,
): Promise<void> {
  if (from === to) return;
  const raw: unknown = (await area(from).get(storageKey))[storageKey];
  if (raw === undefined) return;

  if (!isEncryptedStoreBlob(raw)) {
    await area(to).set({ [storageKey]: raw });
    return;
  }

  const plaintext = await decryptContacts(
    fromBase64(raw.ciphertext),
    fromBase64(raw.iv),
  );
  const json = unpadPlaintext(plaintext);
  const packed = await encryptContacts(padPlaintext(json, to === "local"));
  const { iv, ciphertext } = unpackIvCiphertext(packed);

  await area(to).set({
    [storageKey]: { iv: toBase64(iv), ciphertext: toBase64(ciphertext) },
  });
}

/** Remove a blob from a specific area. Used after a location switch to
 *  drop the old-area copies left by `copyEncryptedBlobRepacked`. */
export async function purgeEncryptedBlob(
  storageKey: string,
  from: StorageLocation,
): Promise<void> {
  await area(from).remove(storageKey);
}

/**
 * Rewrite a store's blob in canonical padded form if it isn't already
 * (e.g. it was saved before padding existed, or on a different area).
 * Best-effort, one-time upgrade so length-hiding takes effect without
 * waiting for the next mutation.
 *
 * Safety: this NEVER changes the stored items -- it decrypts, keeps the
 * exact same JSON bytes, and re-encrypts with canonical padding. It runs
 * under the store's own `withLock` and re-reads inside the lock, so it
 * serialises with `addKey`/`removeKey`/etc. and cannot clobber a
 * concurrent write. It must NOT be called from inside another hold of the
 * same lock (the mutation paths already re-pad on save, so they never
 * need it). If it's already canonical it writes nothing (idempotent).
 */
export async function normalizePadding<T>(
  store: EncryptedStore<T>,
): Promise<void> {
  if (!(await hasContactsSession())) return;
  await withLock(store.storageKey, async () => {
    const blob = await getItem<unknown>(store.storageKey);
    if (!isEncryptedStoreBlob(blob)) return; // absent, or legacy plaintext

    const plaintext = await decryptContacts(
      fromBase64(blob.ciphertext),
      fromBase64(blob.iv),
    );
    const pad = (await currentStorageLocation()) === "local";
    if (isCanonicalPadding(plaintext, pad)) return; // nothing to do

    // Same JSON bytes, canonical padding, fresh IV.
    const json = unpadPlaintext(plaintext);
    const packed = await encryptContacts(padPlaintext(json, pad));
    const { iv, ciphertext } = unpackIvCiphertext(packed);
    await setItem<EncryptedStoreBlob>(store.storageKey, {
      iv: toBase64(iv),
      ciphertext: toBase64(ciphertext),
    });
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
