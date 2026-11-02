import { STORAGE_PREFERENCES, STORAGE_SETTINGS } from "~/lib/constants";
import { hasContactsSession } from "~/lib/pgp/wasm";
import { currentStorageLocation } from "./engine";
import {
  DEFAULT_PREFERENCES,
  getPreferences,
  savePreferences,
  strictestPreferences,
  type PgpPreferences,
} from "./preferences";

/**
 * The panel's single in-memory copy of the preferences. A failed save
 * re-reads storage so the UI never shows a value the next unlock won't; a
 * read that started before a write is dropped.
 */

type Listener = () => void;

let snapshot: PgpPreferences = DEFAULT_PREFERENCES;
const listeners = new Set<Listener>();

let writeEpoch = 0;
let writesInFlight = 0;
/** Re-read once writes settle, or a dropped read (e.g. at unlock) never lands. */
let reloadDropped = false;

function commit(next: PgpPreferences): void {
  if (samePreferences(snapshot, next)) return;
  snapshot = next;
  for (const l of listeners) l();
}

function samePreferences(a: PgpPreferences, b: PgpPreferences): boolean {
  if (a === b) return true;
  const keys = Object.keys(a) as (keyof PgpPreferences)[];
  if (keys.length !== Object.keys(b).length) return false;
  return keys.every((k) => {
    const x = a[k];
    const y = b[k];
    if (Array.isArray(x) && Array.isArray(y)) {
      return x.length === y.length && x.every((v, i) => v === y[i]);
    }
    return x === y;
  });
}

function onStorageChanged(
  changes: Record<string, chrome.storage.StorageChange>,
  area: chrome.storage.AreaName,
): void {
  if (area !== "local" && area !== "sync") return;
  if (!(STORAGE_SETTINGS in changes) && !(STORAGE_PREFERENCES in changes)) {
    return;
  }
  void reload();
}

/** Stable identity until a value actually changes. */
function get(): PgpPreferences {
  return snapshot;
}

function subscribe(listener: Listener): () => void {
  if (listeners.size === 0) {
    chrome.storage.onChanged.addListener(onStorageChanged);
  }
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
    if (listeners.size === 0) {
      chrome.storage.onChanged.removeListener(onStorageChanged);
    }
  };
}

/**
 * Without a session only bootstrap fields are taken (locked reads are
 * defaults). A failed read yields the strictest preset, never the defaults.
 */
async function reload(): Promise<PgpPreferences | null> {
  const epoch = writeEpoch;
  let read: PgpPreferences | null;
  let next: PgpPreferences;
  try {
    // Checked on both sides: a lock mid-read would pass defaults as real.
    const before = await hasContactsSession();
    read = await getPreferences();
    const settingsReadable = before && (await hasContactsSession());
    next = settingsReadable
      ? read
      : {
          ...snapshot,
          storageLocation: read.storageLocation,
          onboardingComplete: read.onboardingComplete,
        };
  } catch {
    read = null;
    const storageLocation = await currentStorageLocation().catch(
      () => snapshot.storageLocation,
    );
    next = { ...strictestPreferences(), storageLocation };
  }
  if (epoch === writeEpoch && writesInFlight === 0) commit(next);
  else reloadDropped = true;
  return read;
}

export interface UpdateOptions {
  /** False for changes the next unlock acts on: commit only once saved. */
  optimistic?: boolean;
}

async function update(
  patch: Partial<PgpPreferences>,
  { optimistic = true }: UpdateOptions = {},
): Promise<void> {
  writeEpoch++;
  writesInFlight++;
  if (optimistic) commit({ ...snapshot, ...patch });
  let saved = false;
  try {
    await savePreferences(patch);
    saved = true;
  } finally {
    writesInFlight--;
    if (!saved) {
      reloadDropped = false;
      await reload();
    } else {
      if (!optimistic) commit({ ...snapshot, ...patch });
      if (writesInFlight === 0 && reloadDropped) {
        reloadDropped = false;
        void reload();
      }
    }
  }
}

export const preferencesStore = { get, subscribe, reload, update };

export function resetPreferencesStoreForTests(): void {
  snapshot = DEFAULT_PREFERENCES;
  writeEpoch = 0;
  writesInFlight = 0;
  reloadDropped = false;
  if (listeners.size > 0) {
    chrome.storage.onChanged.removeListener(onStorageChanged);
  }
  listeners.clear();
}
