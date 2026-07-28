import type { Browser } from "wxt/browser";

/**
 * Transparent per-item chunking for browser.storage.
 *
 * browser.storage.sync caps each item at QUOTA_BYTES_PER_ITEM (8 KB),
 * measured as the JSON-stringified value plus the key's length. A single
 * encrypted keyring / contacts / settings blob (base64 { iv, ciphertext })
 * sails past that once a couple of private keys are stored -- which is why
 * switching a populated vault from "this device only" to "sync across
 * devices" threw `Resource::kQuotaBytesPerItem quota exceeded`.
 *
 * This layer lets every caller keep using one logical key while an
 * oversized value's JSON is spread across as many sibling items as needed.
 * A small manifest ({ __sc: N }) is written at the original key; chunk i
 * lives at `${key}::sc${i}`. Reads reassemble transparently; removes drop
 * the manifest and every chunk.
 *
 * `chunk` is passed false on `local`, whose per-item quota is effectively
 * unbounded -- there the value is written verbatim so length-hiding
 * padding is preserved and no chunk items are ever created.
 */

export type StorageArea =
  Browser.storage.LocalStorageArea | Browser.storage.SyncStorageArea;

/** Manifest written in place of an oversized value. `__sc` is the chunk
 *  count; `__len` is the total length of the reassembled JSON string. No
 *  real stored value carries these fields, so `__sc` is an unambiguous
 *  marker. `__len` binds the chunks to this manifest: browser.storage.sync
 *  propagates each item to other devices independently, so a reader can
 *  briefly see this manifest before every chunk arrives (or alongside a
 *  stale chunk of a different length). Verifying the reassembled length
 *  lets `getChunked` reject such a torn read instead of returning a
 *  truncated value. */
interface ChunkManifest {
  __sc: number;
  __len: number;
}

/**
 * Max JSON bytes per chunk item. Deliberately well under the 8192-byte
 * cap so the key name (~30 chars) and the JSON quoting of the chunk
 * string leave ample headroom.
 */
const CHUNK_BUDGET = 6144;

function isManifest(v: unknown): v is ChunkManifest {
  return (
    typeof v === "object" &&
    v !== null &&
    typeof (v as Record<string, unknown>).__sc === "number"
  );
}

/** Raised when a chunk manifest is present but its chunks can't be fully,
 *  coherently reassembled (a chunk is missing, or the reassembled length
 *  disagrees with the manifest -- typically a cross-device sync mid-flight).
 *  Callers get a throw rather than a silently truncated/empty value, so a
 *  read-modify-write can abort instead of clobbering the stored data. */
export class IncompleteChunkedValueError extends Error {
  constructor(key: string, detail: string) {
    super(`chunked value "${key}" is incomplete: ${detail}`);
    this.name = "IncompleteChunkedValueError";
  }
}

function chunkKey(key: string, i: number): string {
  return `${key}::sc${i}`;
}

async function removeChunkItems(
  area: StorageArea,
  key: string,
  from: number,
  to: number,
): Promise<void> {
  const keys: string[] = [];
  for (let i = from; i < to; i++) keys.push(chunkKey(key, i));
  if (keys.length > 0) await area.remove(keys);
}

/**
 * Write `value` under `key`. When `chunk` is true and the value would
 * exceed the per-item budget, split it across sibling items behind a
 * manifest; otherwise store it verbatim. Either way, any chunk items left
 * over from a previously larger value are removed, so `key` never keeps
 * stale fragments.
 */
export async function setChunked(
  area: StorageArea,
  key: string,
  value: unknown,
  chunk: boolean,
): Promise<void> {
  // How many chunk items the key currently holds -- needed to delete any
  // stragglers when the new value is smaller (or no longer chunked).
  const existing = (await area.get(key))[key];
  const prevChunks = isManifest(existing) ? existing.__sc : 0;

  const serialized = JSON.stringify(value);

  // Fits in one item (or a location without a per-item cap): store as-is.
  if (!chunk || key.length + serialized.length + 2 <= CHUNK_BUDGET) {
    await area.set({ [key]: value });
    if (prevChunks > 0) await removeChunkItems(area, key, 0, prevChunks);
    return;
  }

  const parts: string[] = [];
  for (let i = 0; i < serialized.length; i += CHUNK_BUDGET) {
    parts.push(serialized.slice(i, i + CHUNK_BUDGET));
  }

  // Single set() so the manifest and its chunks land together; on a quota
  // failure the whole write rejects rather than leaving a dangling
  // manifest. The manifest is written last in insertion order but that's
  // irrelevant within one atomic set().
  const writes: Record<string, unknown> = {};
  parts.forEach((p, i) => {
    writes[chunkKey(key, i)] = p;
  });
  writes[key] = {
    __sc: parts.length,
    __len: serialized.length,
  } satisfies ChunkManifest;
  await area.set(writes);

  // Drop chunk items left behind by a previously larger value.
  if (prevChunks > parts.length) {
    await removeChunkItems(area, key, parts.length, prevChunks);
  }
}

/**
 * Read `key`, reassembling a chunked value if a manifest is present.
 * Returns undefined when the key is genuinely absent (no manifest).
 *
 * Throws `IncompleteChunkedValueError` when a manifest IS present but its
 * chunks can't be coherently reassembled (a chunk missing, or the length
 * disagrees with the manifest). This is deliberate: returning undefined
 * there would let a read-modify-write caller treat a mid-sync torn read as
 * "empty" and overwrite the real data. A throw makes the caller abort.
 */
export async function getChunked(
  area: StorageArea,
  key: string,
): Promise<unknown> {
  const head = (await area.get(key))[key];
  if (!isManifest(head)) return head; // verbatim value, or undefined

  const chunkKeys = Array.from({ length: head.__sc }, (_, i) =>
    chunkKey(key, i),
  );
  const stored = await area.get(chunkKeys);
  let serialized = "";
  for (const ck of chunkKeys) {
    const part = stored[ck];
    if (typeof part !== "string") {
      throw new IncompleteChunkedValueError(key, `missing chunk ${ck}`);
    }
    serialized += part;
  }
  if (serialized.length !== head.__len) {
    throw new IncompleteChunkedValueError(
      key,
      `length ${serialized.length} != manifest ${head.__len}`,
    );
  }
  return JSON.parse(serialized);
}

/** Remove `key` and, if it held a manifest, every chunk item under it. */
export async function removeChunked(
  area: StorageArea,
  key: string,
): Promise<void> {
  const head = (await area.get(key))[key];
  if (isManifest(head)) await removeChunkItems(area, key, 0, head.__sc);
  await area.remove(key);
}

/** True for a browser.storage quota error (per-item or total). Used to
 *  turn the raw `...quota exceeded` throw into a friendly message. */
export function isQuotaExceeded(e: unknown): boolean {
  const msg = e instanceof Error ? e.message : String(e);
  return /quota/i.test(msg);
}
