import type { StorageLocation } from "./preferences";
import { STORAGE_DEVICE_LOCATION, STORAGE_PREFERENCES } from "../constants";
import { getChunked, removeChunked, setChunked } from "./chunked";

/**
 * Thin wrapper over chrome.storage that routes reads/writes to the
 * user's chosen location (local or sync).
 *
 * ## Where the location comes from
 *
 * This device's own record (`STORAGE_DEVICE_LOCATION`, in
 * chrome.storage.local, never synced) decides. The sync bootstrap's
 * `storageLocation` is only the default for a device that has no record
 * yet -- a new device of a sync vault, or the first run after an upgrade
 * from a build without one -- and `vault-state.ts` records the location
 * as soon as it is unambiguous.
 *
 * The bootstrap used to decide outright, and anyone signed in to the
 * user's Google account can write it: setting it to "sync" and planting
 * any validly shaped master protection there routed a LOCAL vault's
 * lock screen to the planted one, which nothing unlocks, and the real
 * vault was never mentioned. It also meant one device switching to sync
 * re-routed every other device, whatever it had stored. Where a
 * device's vault lives is a fact about the device.
 *
 * Every value read back is normalised strictly: exactly "sync" is sync,
 * anything else is local. (`?? "local"` let a planted "SYNC" through as
 * a third location that matched neither area.)
 *
 * Includes a per-key mutex to prevent read-modify-write races and
 * a cached location to avoid redundant storage reads.
 */

const locks = new Map<string, Promise<void>>();

export async function withLock<T>(
  key: string,
  fn: () => Promise<T>,
): Promise<T> {
  const prev = locks.get(key) ?? Promise.resolve();
  let resolve: (() => void) | undefined;
  const next = new Promise<void>((r) => {
    resolve = r;
  });
  locks.set(key, next);
  try {
    await prev;
    return await fn();
  } finally {
    resolve?.();
    if (locks.get(key) === next) locks.delete(key);
  }
}

/**
 * {@link withLock}, but held across every extension page of this origin
 * (two panel windows, the reader tab) through the Web Locks API, which
 * `withLock` -- one Map per page -- is not. For the read-check-write
 * sequences whose interleaving across windows does real damage: the
 * master protection's "refuse if one exists" check and its write, and
 * the integrity ledger's read-modify-write (a lost update there drops a
 * revocation from the floor). Falls back to `withLock` where Web Locks
 * is absent (unit tests in Node).
 *
 * Never nest a shared lock inside itself; the ledger's is always the
 * innermost lock taken, so no two pages can wait on each other.
 */
export function withSharedLock<T>(
  key: string,
  fn: () => Promise<T>,
): Promise<T> {
  const webLocks = (
    globalThis as { navigator?: { locks?: Pick<LockManager, "request"> } }
  ).navigator?.locks;
  if (typeof webLocks?.request !== "function") return withLock(key, fn);
  return webLocks.request(`pgp-tools:${key}`, fn);
}

/** Strict normalisation of a stored location value. */
export function asStorageLocation(v: unknown): StorageLocation {
  return v === "sync" ? "sync" : "local";
}

let cachedLocation: StorageLocation | null = null;

/** This device's own record of its vault's location, or null when it has
 *  none yet. Only a literal "local" or "sync" counts as a record. */
export async function pinnedStorageLocation(): Promise<StorageLocation | null> {
  const result = await chrome.storage.local.get(STORAGE_DEVICE_LOCATION);
  const v: unknown = result[STORAGE_DEVICE_LOCATION];
  return v === "local" || v === "sync" ? v : null;
}

/** Record where this device's vault lives. */
export async function pinStorageLocation(loc: StorageLocation): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_DEVICE_LOCATION]: loc });
  cachedLocation = null;
}

/** Forget this device's record (the vault is being erased). */
export async function unpinStorageLocation(): Promise<void> {
  await chrome.storage.local.remove(STORAGE_DEVICE_LOCATION);
  cachedLocation = null;
}

/** The `chrome.storage` the change listener below is registered on (the
 *  global is swapped per test, so this is tracked rather than a flag). */
let watching: unknown = null;

/**
 * Drop the cached location whenever another page changes what it is
 * resolved from: this device's record, or the sync bootstrap. Each panel
 * window, and the reader tab, has its own copy of this module, so a
 * storage switch in one window used to leave the others reading and
 * writing the OLD area -- whose copies the switch then purges -- until
 * they were closed. Registered lazily (the first resolve), once per
 * `chrome.storage`.
 */
function watchLocationChanges(): void {
  const storage = (globalThis as { chrome?: typeof chrome }).chrome?.storage;
  if (!storage || watching === storage) return;
  watching = storage;
  const onChanged = (storage as Partial<typeof chrome.storage>).onChanged;
  onChanged?.addListener((changes, areaName) => {
    if (
      (areaName === "local" && STORAGE_DEVICE_LOCATION in changes) ||
      (areaName === "sync" && STORAGE_PREFERENCES in changes)
    ) {
      cachedLocation = null;
    }
  });
}

async function resolveLocation(): Promise<StorageLocation> {
  watchLocationChanges();
  if (cachedLocation) return cachedLocation;
  const pinned = await pinnedStorageLocation();
  if (pinned) {
    cachedLocation = pinned;
    return pinned;
  }
  const result = await chrome.storage.sync.get(STORAGE_PREFERENCES);
  const prefs = result[STORAGE_PREFERENCES] as
    { storageLocation?: unknown } | undefined;
  cachedLocation = asStorageLocation(prefs?.storageLocation);
  return cachedLocation;
}

/** Call after the user changes storage location in preferences. */
export function invalidateLocationCache(): void {
  cachedLocation = null;
}

/** The user's current storage area. Used by the encrypted stores to
 *  decide padding: `local` has a generous quota so blobs are padded to
 *  hide item counts; `sync` caps items at 8 KB, so padding is skipped
 *  there to stay under the limit. */
export function currentStorageLocation(): Promise<StorageLocation> {
  return resolveLocation();
}

function area(
  location: StorageLocation,
): chrome.storage.LocalStorageArea | chrome.storage.SyncStorageArea {
  return location === "sync" ? chrome.storage.sync : chrome.storage.local;
}

export async function getItem<T>(key: string): Promise<T | undefined> {
  const loc = await resolveLocation();
  return (await getChunked(area(loc), key)) as T | undefined;
}

export async function setItem<T>(key: string, value: T): Promise<void> {
  const loc = await resolveLocation();
  // Chunk on `sync` (8 KB/item cap); store verbatim on `local` (no cap,
  // and its length-hiding padding must survive intact).
  await setChunked(area(loc), key, value, loc === "sync");
}

export async function removeItem(key: string): Promise<void> {
  const loc = await resolveLocation();
  await removeChunked(area(loc), key);
}
