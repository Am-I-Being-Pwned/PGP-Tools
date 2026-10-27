/**
 * Whether a vault exists, and where -- read from the vault itself, never
 * from the plaintext bootstrap.
 *
 * The bootstrap (`pgp_preferences` in sync) carries `onboardingComplete`
 * and `storageLocation`, and anyone signed in to the user's Google
 * account can write both, even for a local-only vault. Trusting the first
 * let them put onboarding back up over an existing vault; the victim set
 * a password and the real master protection was replaced, every key
 * unopenable. Trusting the second lets them point the engine at the
 * wrong area so the vault looks missing, with the same ending.
 *
 * So the panel decides from what is actually stored: a master protection
 * in the configured area is a vault; one only in the OTHER area means the
 * location pointer was changed under the vault (say so, offer to point it
 * back -- no data moves); sealed stores with no master protection
 * anywhere are a vault that can no longer be opened (say so, and offer
 * an explicit, separately confirmed erase). Only when nothing is stored
 * anywhere is it a fresh install.
 *
 * Both areas are ALWAYS read. "The configured area" is this device's own
 * record of its location (`engine.ts`) once there is one; until then it
 * is the bootstrap's forgeable default, and a master protection in BOTH
 * areas is not resolved by picking one: planting any validly shaped
 * protection in sync and pointing the bootstrap there used to route a
 * local vault's lock screen to the planted record, which nothing opens,
 * and never mention the real one. With no record, that is `ambiguous`
 * and the user chooses; the choice (or an unambiguous ready state) is
 * recorded on this device, after which a sync writer cannot move it.
 * When both exist and the record says which, the lock screen still
 * learns of the other (`alternate`) and offers it after a failed unlock,
 * in case it was the record that was tampered with.
 */

import type { MasterProtection } from "./master-protection";
import type { StorageLocation } from "./preferences";
import {
  STORAGE_CONTACTS,
  STORAGE_CRX_KEYS,
  STORAGE_KEYRING,
  STORAGE_MASTER_PROTECTION,
  STORAGE_SETTINGS,
} from "../constants";
import { getChunked, removeChunked } from "./chunked";
import {
  copyEncryptedBlobRepacked,
  purgeEncryptedBlob,
} from "./encrypted-store";
import {
  currentStorageLocation,
  invalidateLocationCache,
  pinnedStorageLocation,
  pinStorageLocation,
  unpinStorageLocation,
} from "./engine";
import { clearHistory } from "./history";
import { resetIntegrityLedger } from "./integrity";
import { masterProtectionIn } from "./master-protection";
import { savePreferences } from "./preferences";

export type VaultState =
  /** Nothing stored anywhere: onboarding. */
  | { kind: "none" }
  /** A vault in the configured area: the lock screen. `alternate` names
   *  the other area when it holds a master protection too. */
  | {
      kind: "ready";
      protection: MasterProtection;
      alternate?: StorageLocation;
    }
  /** A master protection in both areas, and no record on this device of
   *  which is its own: the user chooses. */
  | { kind: "ambiguous" }
  /** No vault where the bootstrap points, but one in the other area. */
  | { kind: "elsewhere"; location: StorageLocation }
  /** Sealed stores, but no master protection in either area. */
  | { kind: "orphaned" };

/** The sealed stores that make an area "hold a vault" even without its
 *  master protection. */
const VAULT_STORES = [
  STORAGE_KEYRING,
  STORAGE_CONTACTS,
  STORAGE_SETTINGS,
  STORAGE_CRX_KEYS,
];

function area(loc: StorageLocation) {
  return loc === "sync" ? chrome.storage.sync : chrome.storage.local;
}

async function holdsVaultData(loc: StorageLocation): Promise<boolean> {
  for (const key of VAULT_STORES) {
    try {
      if ((await getChunked(area(loc), key)) !== undefined) return true;
    } catch {
      // A torn chunked read (sync mid-flight) is still data.
      return true;
    }
  }
  return false;
}

/** How long an apparently orphaned vault must stay that way before it is
 *  called one. A storage switch on another device of a sync vault copies
 *  the master protection first and deletes it last, but sync delivers the
 *  writes one by one, so a second device can briefly see sealed stores
 *  with no master protection; offering Erase on that glimpse would be the
 *  worst possible false positive. Overridable for tests. */
export const ORPHAN_RECHECK_MS = { value: 1500 };

export async function resolveVaultState(): Promise<VaultState> {
  const first = await resolveOnce();
  if (first.kind !== "orphaned") return first;
  await new Promise((r) => setTimeout(r, ORPHAN_RECHECK_MS.value));
  // Still orphaned after the wait is an orphan; anything else (the master
  // protection arrived) is that state instead.
  return resolveOnce();
}

async function resolveOnce(): Promise<VaultState> {
  const pinned = await pinnedStorageLocation();
  const here = await currentStorageLocation();
  const other: StorageLocation = here === "local" ? "sync" : "local";

  const protection = await masterProtectionIn(here);
  const otherProtection = await masterProtectionIn(other);
  if (protection && otherProtection) {
    if (!pinned) return { kind: "ambiguous" };
    return { kind: "ready", protection, alternate: other };
  }
  if (protection) {
    // Unambiguous: record it, so a later bootstrap write cannot move it.
    if (!pinned) await pinStorageLocation(here);
    return { kind: "ready", protection };
  }
  if (otherProtection) {
    return { kind: "elsewhere", location: other };
  }
  if ((await holdsVaultData(here)) || (await holdsVaultData(other))) {
    return { kind: "orphaned" };
  }
  return { kind: "none" };
}

/** Point this device (and the bootstrap) at the area the vault is
 *  actually in. Moves no data -- a real location change goes through
 *  Settings, which copies every blob first. */
export async function adoptVaultLocation(loc: StorageLocation): Promise<void> {
  await savePreferences({ storageLocation: loc, onboardingComplete: true });
  invalidateLocationCache();
}

/**
 * Erase every vault blob in BOTH areas, plus history and the integrity
 * ledger, so onboarding can start a new vault. The one sanctioned way
 * past {@link saveMasterProtection}'s refusal, and only offered for an
 * orphaned vault (sealed stores, no master protection anywhere), which
 * can no longer be opened by anyone. The UI puts it behind a confirm.
 */
export async function eraseVault(): Promise<void> {
  for (const loc of ["local", "sync"] as const) {
    for (const key of [...VAULT_STORES, STORAGE_MASTER_PROTECTION]) {
      await removeChunked(area(loc), key);
    }
  }
  await clearHistory();
  await resetIntegrityLedger();
  await unpinStorageLocation();
}

/**
 * Move the vault from one storage area to the other (Settings' storage
 * switch). Every engine-routed blob moves, or it strands in the old area:
 * the master protection especially -- leave it behind and the switched
 * vault has keys it can never unlock.
 *
 * Order, and why:
 *  1. Copy, MASTER PROTECTION FIRST, then the stores (each re-packed for
 *     the destination: padding differs by area). Originals untouched.
 *  2. Commit: record the new location (bootstrap, then this device's own
 *     record -- see `writeBoot`). Reads now resolve to the destination.
 *  3. Purge the old area's copies, MASTER PROTECTION LAST. Best-effort:
 *     the move is committed, so a failure only leaves duplicates.
 *
 * The master protection brackets the stores so that no moment exists at
 * which an area holds sealed stores without one: another device of a
 * sync vault seeing that state mid-switch would call the vault orphaned
 * and offer to erase it (`resolveVaultState` also waits for a re-check).
 *
 * A failure before the commit rolls back: the destination copies are
 * removed (master protection last again), and this device's location is
 * put back where it was, so it can never be left routed to the area the
 * rollback just emptied. Throws the original error.
 */
export async function moveVault(
  from: StorageLocation,
  to: StorageLocation,
): Promise<void> {
  if (from === to) return;
  const copyOrder = [STORAGE_MASTER_PROTECTION, ...VAULT_STORES];
  const purgeOrder = [...VAULT_STORES, STORAGE_MASTER_PROTECTION];
  const pinnedBefore = await pinnedStorageLocation();
  let committed = false;
  try {
    for (const key of copyOrder) {
      await copyEncryptedBlobRepacked(key, from, to);
    }
    await savePreferences({ storageLocation: to });
    committed = true;
    invalidateLocationCache();
  } catch (e) {
    if (!committed) {
      for (const key of purgeOrder) {
        try {
          await purgeEncryptedBlob(key, to);
        } catch {
          /* best-effort cleanup */
        }
      }
      try {
        await pinStorageLocation(pinnedBefore ?? from);
      } catch {
        /* the write that failed is the likelier one; nothing more to do */
      }
      invalidateLocationCache();
    }
    throw e;
  }
  for (const key of purgeOrder) {
    try {
      await purgeEncryptedBlob(key, from);
    } catch {
      /* stale originals are harmless; leave them */
    }
  }
}
