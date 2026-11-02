import type { PgpPreferences } from "./preferences";
import { STORAGE_PREFERENCES, STORAGE_SETTINGS } from "../constants";
import { hasContactsSession } from "../pgp/wasm";
import { currentStorageLocation } from "./engine";
import {
  DEFAULT_PREFERENCES,
  getPreferences,
  savePreferences,
  strictestPreferences,
} from "./preferences";

/**
 * The panel's one in-memory copy of the preferences, kept in step with
 * storage. Everything that renders a preference reads it from here (via
 * `usePreferences`) and every change goes through {@link update}, so a
 * toggle in one view is seen by every other view without re-reads,
 * version counters, or parent-held copies.
 *
 * It wraps `getPreferences`/`savePreferences` and adds nothing to what
 * they decide: the sealed settings blob, the bootstrap, the legacy
 * migration and the strictest-preset fallback all stay theirs.
 *
 * Writes are optimistic: the snapshot moves first and, if the save
 * rejects, is read back from storage so the UI never shows a value the
 * next unlock would not. A read that started before a write and lands
 * after it is dropped -- it cannot hold the write -- and the write's own
 * storage change re-reads afterwards.
 */

type Listener = () => void;

let snapshot: PgpPreferences = DEFAULT_PREFERENCES;
const listeners = new Set<Listener>();

/** Bumped by every write; a read that saw a different value is stale. */
let writeEpoch = 0;
let writesInFlight = 0;
/** A read was dropped for a write; re-read once the writes settle, or a
 *  change that only that read carried (the unlock-time read, above all)
 *  would never land. */
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

// One listener for the whole panel, held only while something is
// subscribed. It fires for this panel's own saves too; those re-read the
// value already showing, which `commit` drops without a render.
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

/** The current snapshot. Stable identity until a value actually changes. */
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
 * Read the preferences from storage into the snapshot. Encrypted settings
 * read as defaults while the vault is locked, so a read without a session
 * takes only the bootstrap fields and keeps the settings already held --
 * a change made in another window while this one is locked must not drop
 * it to the defaults (a 15-minute auto-lock, caching on) for the moment
 * between unlock and the read the unlock makes.
 *
 * A read that fails outright puts the strictest preset in the snapshot,
 * never the defaults: a rejected read used to be dropped, and a Paranoid
 * user ran on a 15-minute auto-lock with no sign anything was wrong. The
 * location there is where this device's vault actually lives, so Settings
 * never offers to "move" it to where it already is. Returns null in that
 * case so callers can tell.
 */
async function reload(): Promise<PgpPreferences | null> {
  const epoch = writeEpoch;
  let read: PgpPreferences | null;
  let next: PgpPreferences;
  try {
    // A session on both sides of the read: a lock landing mid-read would
    // otherwise let defaults through as the real settings.
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
  /** Move the snapshot only once the save has landed. For a change the
   *  next unlock acts on, where even a moment of the UI showing a value
   *  storage does not hold is wrong. Default: move first. */
  optimistic?: boolean;
}

/**
 * Save a change and show it. Rejects if the save does, after reading the
 * stored values back into the snapshot.
 */
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
      // Show what storage holds, before the caller hears of the failure.
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

/** Test-only: drop the snapshot and any listeners. */
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
