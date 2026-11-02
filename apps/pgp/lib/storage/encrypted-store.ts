/**
 * Shared load/save for the encrypted JSON-array blobs behind the keyring
 * and contacts stores: AES-256-GCM sealed with the storage key as the
 * domain (`envelope.ts`), so tampering or moving a blob to another key
 * fails to decrypt. The sealed array carries a generation (`integrity.ts`).
 *
 * The pre-domain-separation envelope is still read (`openEnvelope`);
 * mutations and `normalizePadding` re-seal it. Reads never write.
 *
 * The original plaintext format (index + per-item entries) is deliberately
 * NOT read: migrating it sealed attacker-writable plaintext into the vault
 * on every unlock (a planted "verified" contact or "own" key). It now reads
 * as an absent store, reported as tampering where this device has seen one.
 */

import type { StoredEnvelope } from "./envelope";
import type { StorageLocation } from "./preferences";
import { hasContactsSession } from "../pgp/wasm";
import { getChunked, removeChunked, setChunked } from "./chunked";
import { currentStorageLocation, getItem, setItem, withLock } from "./engine";
import { isStoredEnvelope, openEnvelope, sealEnvelope } from "./envelope";
import {
  claimGeneration,
  noteAbsent,
  observeGeneration,
  recordWrite,
  splitGeneration,
  withGeneration,
} from "./integrity";
import { notifyStoreChanged } from "./live-list";
import { isCanonicalPadding, padPlaintext, unpadPlaintext } from "./padding";

export interface EncryptedStore<T> {
  storageKey: string;
  isValid: (v: unknown) => v is T;
  /** Human label for error messages ("keyring", "contacts"). */
  label: string;
}

export async function loadEncryptedArray<T>(
  store: EncryptedStore<T>,
): Promise<T[]> {
  if (!(await hasContactsSession())) return [];

  const blob = await getItem<unknown>(store.storageKey);
  if (!isStoredEnvelope(blob)) {
    // Absent or not ours (incl. the retired plaintext index). Stores are never
    // removed once written, so a seen store going missing is reported.
    await noteAbsent(store.storageKey);
    return [];
  }

  // Never re-seal here: this also runs under the store's lock, so a write
  // could deadlock or clobber a concurrent mutation.
  const { plaintext } = await openEnvelope(store.storageKey, blob);
  const json = unpadPlaintext(plaintext);
  const parsed: unknown = JSON.parse(new TextDecoder().decode(json));

  if (!Array.isArray(parsed)) return [];
  const { gen, items } = splitGeneration(parsed);
  await observeGeneration(store.storageKey, gen);
  return items.filter(store.isValid);
}

export async function saveEncryptedArray<T>(
  store: EncryptedStore<T>,
  items: T[],
): Promise<void> {
  if (!(await hasContactsSession())) {
    throw new Error(`Cannot save ${store.label}: no active contacts session`);
  }

  // Padding hides the item count; skipped on `sync` (8 KB/item cap).
  const gen = await claimGeneration(store.storageKey);
  const json = new TextEncoder().encode(
    JSON.stringify(withGeneration(items, gen)),
  );
  const pad = (await currentStorageLocation()) === "local";
  const plaintext = padPlaintext(json, pad);

  await setItem<StoredEnvelope>(
    store.storageKey,
    await sealEnvelope(store.storageKey, plaintext),
  );
  await recordWrite(store.storageKey, gen);
  notifyStoreChanged(store.storageKey);
}

function area(loc: StorageLocation) {
  return loc === "sync" ? chrome.storage.sync : chrome.storage.local;
}

/**
 * Copy one blob to another area, re-padding for the destination (a `local`
 * blob's padding can exceed sync's 8 KB/item quota). Does NOT remove the
 * source: the caller commits by switching location, then purges, so a crash
 * leaves originals or harmless duplicates. Non-envelope values are copied
 * verbatim. The generation rides along unchanged, so a move is not a
 * rollback.
 */
export async function copyEncryptedBlobRepacked(
  storageKey: string,
  from: StorageLocation,
  to: StorageLocation,
): Promise<void> {
  if (from === to) return;
  const raw: unknown = await getChunked(area(from), storageKey);
  if (raw === undefined) return;

  if (!isStoredEnvelope(raw)) {
    await setChunked(area(to), storageKey, raw, to === "sync");
    return;
  }

  // The domain is the storage KEY, not the area; legacy blobs upgrade here.
  const { plaintext } = await openEnvelope(storageKey, raw);
  const json = unpadPlaintext(plaintext);

  await setChunked(
    area(to),
    storageKey,
    await sealEnvelope(storageKey, padPlaintext(json, to === "local")),
    to === "sync",
  );
}

/** Remove a blob (and its sync chunks) from a specific area. */
export async function purgeEncryptedBlob(
  storageKey: string,
  from: StorageLocation,
): Promise<void> {
  await removeChunked(area(from), storageKey);
}

/**
 * One-time rewrite to canonical padding and the domain-bound envelope, for
 * stores that are read but never mutated. Never changes the items (same
 * JSON bytes). Runs under the store's own `withLock` and re-reads inside it,
 * so it must NOT be called while holding that lock. Idempotent.
 */
export async function normalizePadding<T>(
  store: EncryptedStore<T>,
): Promise<void> {
  if (!(await hasContactsSession())) return;
  await withLock(store.storageKey, async () => {
    const blob = await getItem<unknown>(store.storageKey);
    if (!isStoredEnvelope(blob)) return; // absent, or not ours

    const { plaintext, legacy } = await openEnvelope(store.storageKey, blob);
    const pad = (await currentStorageLocation()) === "local";
    // A legacy envelope needs rewriting even with canonical padding.
    if (!legacy && isCanonicalPadding(plaintext, pad)) return;

    const json = unpadPlaintext(plaintext);
    await setItem<StoredEnvelope>(
      store.storageKey,
      await sealEnvelope(store.storageKey, padPlaintext(json, pad)),
    );
  });
}
