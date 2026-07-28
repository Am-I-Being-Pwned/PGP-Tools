/**
 * Shared load/save for the encrypted JSON-array blobs that back the
 * keyring and contacts stores.
 *
 * Both stores use the same scheme: the array is serialised to JSON,
 * sealed with AES-256-GCM for the store's own storage key as the domain
 * (see `envelope.ts`), and persisted as `{ iv, ciphertext }` (base64).
 * Tampering with the stored blob makes decryption fail -- and so does
 * moving an intact blob to a different storage key, because the key is
 * what the subkey and AAD are derived from.
 *
 * Two legacy formats are read transparently:
 *  - the pre-domain-separation envelope (one shared key + one shared AAD
 *    across every store), handled by `openEnvelope`'s fallback. Mutations
 *    re-seal under the new scheme; `normalizePadding` upgrades a store
 *    that is only ever read. Reads never write, so an upgrade can't race
 *    a concurrent mutation.
 *  - the original plaintext format: a `string[]` index at the storage key
 *    plus one plaintext entry per item at `${storageKey}:${id}`.
 */

import type { StoredEnvelope } from "./envelope";
import type { StorageLocation } from "./preferences";
import { hasContactsSession } from "../pgp/wasm";
import { getChunked, removeChunked, setChunked } from "./chunked";
import {
  currentStorageLocation,
  getItem,
  removeItem,
  setItem,
  withLock,
} from "./engine";
import { isStoredEnvelope, openEnvelope, sealEnvelope } from "./envelope";
import { isCanonicalPadding, padPlaintext, unpadPlaintext } from "./padding";

export interface EncryptedStore<T> {
  /** browser.storage key the encrypted blob lives under. */
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
  if (!isStoredEnvelope(blob)) {
    if (Array.isArray(blob)) {
      await migrateLegacyPlaintext(store, blob as unknown[]);
      return loadEncryptedArray(store);
    }
    return [];
  }

  // Deliberately does NOT re-seal a legacy blob: this runs both inside and
  // outside the store's `withLock` (the mutation paths call it under the
  // lock), so a write here could either deadlock or clobber a concurrent
  // mutation. `saveEncryptedArray` and `normalizePadding` own the upgrade.
  const { plaintext } = await openEnvelope(store.storageKey, blob);
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

  await setItem<StoredEnvelope>(
    store.storageKey,
    await sealEnvelope(store.storageKey, plaintext),
  );
}

function area(loc: StorageLocation) {
  return loc === "sync" ? browser.storage.sync : browser.storage.local;
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
  // getChunked/setChunked so a blob that was split to fit sync's 8 KB/item
  // cap is reassembled on read and re-split on write to the destination.
  const raw: unknown = await getChunked(area(from), storageKey);
  if (raw === undefined) return;

  if (!isStoredEnvelope(raw)) {
    await setChunked(area(to), storageKey, raw, to === "sync");
    return;
  }

  // The sealing domain is the storage KEY, not the area, so the same
  // domain is used on both sides of the move -- and a legacy blob is
  // upgraded to the domain-bound scheme on the way across.
  const { plaintext } = await openEnvelope(storageKey, raw);
  const json = unpadPlaintext(plaintext);

  await setChunked(
    area(to),
    storageKey,
    await sealEnvelope(storageKey, padPlaintext(json, to === "local")),
    to === "sync",
  );
}

/** Remove a blob (and any sync chunk items behind it) from a specific
 *  area. Used after a location switch to drop the old-area copies left by
 *  `copyEncryptedBlobRepacked`, and to roll back on a failed migration. */
export async function purgeEncryptedBlob(
  storageKey: string,
  from: StorageLocation,
): Promise<void> {
  await removeChunked(area(from), storageKey);
}

/**
 * Rewrite a store's blob in canonical form if it isn't already: canonical
 * length-hiding padding (e.g. it was saved before padding existed, or on a
 * different area) AND the domain-bound sealing envelope (it was saved
 * before domain separation existed). Best-effort, one-time upgrade so both
 * take effect without waiting for the next mutation.
 *
 * This is the ONLY eager migration path for a store the user never
 * mutates -- an install that reads its keyring for months and never adds a
 * key would otherwise sit on a legacy blob forever. `loadEncryptedArray`
 * can't do it (it runs inside the store's lock on the mutation paths), so
 * it lives here, where the lock is ours.
 *
 * Safety: this NEVER changes the stored items -- it decrypts, keeps the
 * exact same JSON bytes, and re-seals. It runs under the store's own
 * `withLock` and re-reads inside the lock, so it serialises with
 * `addKey`/`removeKey`/etc. and cannot clobber a concurrent write. It must
 * NOT be called from inside another hold of the same lock (the mutation
 * paths already re-pad and re-seal on save, so they never need it). If the
 * blob is already canonical AND already domain-bound it writes nothing
 * (idempotent).
 */
export async function normalizePadding<T>(
  store: EncryptedStore<T>,
): Promise<void> {
  if (!(await hasContactsSession())) return;
  await withLock(store.storageKey, async () => {
    const blob = await getItem<unknown>(store.storageKey);
    if (!isStoredEnvelope(blob)) return; // absent, or legacy plaintext

    const { plaintext, legacy } = await openEnvelope(store.storageKey, blob);
    const pad = (await currentStorageLocation()) === "local";
    // A legacy envelope must be rewritten even when its padding is already
    // canonical -- the padding is not what needs upgrading.
    if (!legacy && isCanonicalPadding(plaintext, pad)) return;

    // Same JSON bytes, canonical padding, domain-bound seal, fresh IV.
    const json = unpadPlaintext(plaintext);
    await setItem<StoredEnvelope>(
      store.storageKey,
      await sealEnvelope(store.storageKey, padPlaintext(json, pad)),
    );
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
