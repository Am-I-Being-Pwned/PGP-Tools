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

export async function resolveVaultState(): Promise<VaultState> {
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
