import type { StorageLocation } from "./preferences";
import { STORAGE_DEVICE_LOCATION, STORAGE_PREFERENCES } from "../constants";
import { getChunked, removeChunked, setChunked } from "./chunked";

/**
 * Routes chrome.storage reads/writes to this device's vault location, with
 * a per-key mutex and a cached location.
 *
 * The location is this device's own record (`STORAGE_DEVICE_LOCATION`,
 * local, never synced). The sync bootstrap's `storageLocation` is only the
 * default for a device with no record: anyone in the user's Google account
 * can write it, so letting it decide would route a local vault's lock
 * screen to a planted protection. Values are normalised strictly: exactly
 * "sync" is sync, anything else is local.
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
 * via Web Locks (falls back to `withLock` without it, e.g. Node tests).
 * For read-check-write sequences whose cross-window interleaving does real
 * damage: master protection's "refuse if one exists" + write, and the
 * integrity ledger's read-modify-write.
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

/** This device's record of its vault location (only literal "local" or
 *  "sync" counts), or null. */
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

/** The `chrome.storage` the listener is registered on (swapped per test). */
let watching: unknown = null;

/**
 * Drop the cached location when another page changes this device's record
 * or the sync bootstrap; otherwise other windows keep using the OLD area
 * after a switch purges it.
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

/** The current storage area. `local` blobs are padded to hide item
 *  counts; `sync` (8 KB/item) skips padding. */
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
  // Chunk on `sync`; verbatim on `local` so padding survives.
  await setChunked(area(loc), key, value, loc === "sync");
}

export async function removeItem(key: string): Promise<void> {
  const loc = await resolveLocation();
  await removeChunked(area(loc), key);
}
