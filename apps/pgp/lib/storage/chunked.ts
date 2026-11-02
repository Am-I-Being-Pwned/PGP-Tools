/**
 * Transparent per-item chunking for chrome.storage. `sync` caps items at
 * 8 KB, so an oversized value's JSON is split across `${key}::sc${i}`
 * behind a `{ __sc: N }` manifest at `key`. `chunk` is false on `local`:
 * values are written verbatim there so length-hiding padding survives.
 */

export type StorageArea =
  chrome.storage.LocalStorageArea | chrome.storage.SyncStorageArea;

/** `__sc` is the chunk count (no real value carries it); `__len` is the
 *  reassembled length, so a torn cross-device sync read (missing or stale
 *  chunk) is rejected instead of returning a truncated value. */
interface ChunkManifest {
  __sc: number;
  __len: number;
}

/** Well under the 8192-byte cap to leave room for the key and JSON quoting. */
const CHUNK_BUDGET = 6144;

function isManifest(v: unknown): v is ChunkManifest {
  return (
    typeof v === "object" &&
    v !== null &&
    typeof (v as Record<string, unknown>).__sc === "number"
  );
}

/** A manifest is present but its chunks don't reassemble coherently. Thrown
 *  (never an empty value) so a read-modify-write aborts instead of
 *  clobbering the stored data. */
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

/** Write `value` under `key`, chunking when needed. Always removes chunk
 *  items left over from a previously larger value. */
export async function setChunked(
  area: StorageArea,
  key: string,
  value: unknown,
  chunk: boolean,
): Promise<void> {
  const existing = (await area.get(key))[key];
  const prevChunks = isManifest(existing) ? existing.__sc : 0;

  const serialized = JSON.stringify(value);

  if (!chunk || key.length + serialized.length + 2 <= CHUNK_BUDGET) {
    await area.set({ [key]: value });
    if (prevChunks > 0) await removeChunkItems(area, key, 0, prevChunks);
    return;
  }

  const parts: string[] = [];
  for (let i = 0; i < serialized.length; i += CHUNK_BUDGET) {
    parts.push(serialized.slice(i, i + CHUNK_BUDGET));
  }

  // One set() so a quota failure can't leave a dangling manifest.
  const writes: Record<string, unknown> = {};
  parts.forEach((p, i) => {
    writes[chunkKey(key, i)] = p;
  });
  writes[key] = {
    __sc: parts.length,
    __len: serialized.length,
  } satisfies ChunkManifest;
  await area.set(writes);

  if (prevChunks > parts.length) {
    await removeChunkItems(area, key, parts.length, prevChunks);
  }
}

/**
 * Read `key`, reassembling a chunked value. Undefined only when the key is
 * genuinely absent; throws `IncompleteChunkedValueError` on a torn read,
 * so a read-modify-write caller can't treat it as "empty" and overwrite.
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

/** True for a chrome.storage quota error (per-item or total). */
export function isQuotaExceeded(e: unknown): boolean {
  const msg = e instanceof Error ? e.message : String(e);
  return /quota/i.test(msg);
}
