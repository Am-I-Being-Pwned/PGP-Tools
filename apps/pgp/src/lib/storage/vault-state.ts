/**
 * Whether a vault exists, and where -- read from the vault itself, never
 * from the plaintext bootstrap, which a sync writer can forge (trusting it
 * let an attacker re-run onboarding over a vault, or hide it, ending in the
 * real master protection being replaced).
 *
 * Master protection in the configured area: a vault. Only in the other
 * area: the pointer was moved (offer to point back, no data moves). Sealed
 * stores but no master protection: orphaned (offer a confirmed erase).
 * Nothing anywhere: fresh install.
 *
 * Both areas are ALWAYS read. "Configured" is this device's own pinned
 * record (`engine.ts`) once there is one; without it, a master protection
 * in both areas is `ambiguous` and the user chooses -- never resolved by
 * the forgeable bootstrap. With a record, the other is still offered as
 * `alternate` after a failed unlock, in case the record was tampered with.
 */

import {
  STORAGE_CONTACTS,
  STORAGE_CRX_KEYS,
  STORAGE_KEYRING,
  STORAGE_MASTER_PROTECTION,
  STORAGE_SETTINGS,
} from "~/lib/constants";
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
import { masterProtectionIn, type MasterProtection } from "./master-protection";
import { savePreferences, type StorageLocation } from "./preferences";

export type VaultState =
  | { kind: "none" }
  /** `alternate`: the other area also holds a master protection. */
  | {
      kind: "ready";
      protection: MasterProtection;
      alternate?: StorageLocation;
    }
  /** Both areas, and no record on this device: the user chooses. */
  | { kind: "ambiguous" }
  | { kind: "elsewhere"; location: StorageLocation }
  | { kind: "orphaned" };

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

/** Wait before calling a vault orphaned: a storage switch on another sync
 *  device can briefly show stores without the master protection, and
 *  offering Erase on that glimpse is the worst false positive. */
export const ORPHAN_RECHECK_MS = { value: 1500 };

export async function resolveVaultState(): Promise<VaultState> {
  const first = await resolveOnce();
  if (first.kind !== "orphaned") return first;
  await new Promise((r) => setTimeout(r, ORPHAN_RECHECK_MS.value));
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
    // Pin it, so a later bootstrap write cannot move it.
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

/** Moves no data -- a real location change goes through {@link moveVault}. */
export async function adoptVaultLocation(loc: StorageLocation): Promise<void> {
  await savePreferences({ storageLocation: loc, onboardingComplete: true });
  invalidateLocationCache();
}

/**
 * Erase every vault blob in BOTH areas, plus history and the ledger. The
 * only sanctioned way past {@link saveMasterProtection}'s refusal; offered
 * only for an orphaned vault, behind a confirm.
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
 * Move the vault to the other storage area. Every engine-routed blob moves,
 * or it strands (a stranded master protection = unopenable keys).
 *
 *  1. Copy, MASTER PROTECTION FIRST, then the stores (re-packed per area).
 *  2. Commit: record the new location (bootstrap, then the device record).
 *  3. Purge the old copies, MASTER PROTECTION LAST. Best-effort.
 *
 * The bracketing means no area ever holds stores without a master
 * protection, which another sync device would read as orphaned. A failure
 * before the commit removes the copies and restores the location.
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
