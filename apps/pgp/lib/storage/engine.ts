import type { StorageLocation } from "./preferences";
import { STORAGE_PREFERENCES } from "../constants";

/**
 * Thin wrapper over chrome.storage that routes reads/writes to the
 * user's chosen location (local or sync).
 *
 * The location is itself stored in chrome.storage.sync (so it's always
 * reachable regardless of the current choice).
 *
 * Includes a per-key mutex to prevent read-modify-write races and
 * a cached location to avoid redundant storage reads.
 */

// ── mutex ────────────────────────────────────────────────────────────

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

// ── cached storage location ──────────────────────────────────────────

let cachedLocation: StorageLocation | null = null;

async function resolveLocation(): Promise<StorageLocation> {
  if (cachedLocation) return cachedLocation;
  const result = await chrome.storage.sync.get(STORAGE_PREFERENCES);
  const prefs = result[STORAGE_PREFERENCES] as
    | { storageLocation?: StorageLocation }
    | undefined;
  cachedLocation = prefs?.storageLocation ?? "local";
  return cachedLocation;
}

/** Call after the user changes storage location in preferences. */
export function invalidateLocationCache(): void {
  cachedLocation = null;
}

function area(
  location: StorageLocation,
): chrome.storage.LocalStorageArea | chrome.storage.SyncStorageArea {
  return location === "sync" ? chrome.storage.sync : chrome.storage.local;
}

// ── CRUD ─────────────────────────────────────────────────────────────

export async function getItem<T>(key: string): Promise<T | undefined> {
  const loc = await resolveLocation();
  const result = await area(loc).get(key);
  return result[key] as T | undefined;
}

export async function setItem<T>(key: string, value: T): Promise<void> {
  const loc = await resolveLocation();
  await area(loc).set({ [key]: value });
}

export async function removeItem(key: string): Promise<void> {
  const loc = await resolveLocation();
  await area(loc).remove(key);
}

export async function migrate(
  keys: string[],
  from: StorageLocation,
  to: StorageLocation,
): Promise<void> {
  if (from === to) return;
  const source = area(from);
  const dest = area(to);

  // Collect all keys including per-item sub-keys (e.g. pgp_keyring:abc123)
  const allKeys = [...keys];
  const indexData = await source.get(keys);
  for (const key of keys) {
    const index = indexData[key];
    if (Array.isArray(index)) {
      for (const id of index) {
        if (typeof id === "string") {
          allKeys.push(`${key}:${id}`);
        }
      }
    }
  }

  const data = await source.get(allKeys);
  if (Object.keys(data).length > 0) {
    await dest.set(data);
  }
  await source.remove(allKeys);
  invalidateLocationCache();
}
