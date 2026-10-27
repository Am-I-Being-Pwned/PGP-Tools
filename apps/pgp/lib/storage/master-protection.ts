import type { StorageLocation } from "./preferences";
import { STORAGE_MASTER_PROTECTION } from "../constants";
import { getChunked, setChunked } from "./chunked";
import { currentStorageLocation, getItem, withSharedLock } from "./engine";
import { resetIntegrityLedger } from "./integrity";

//
// Security note: For the passkey path, `storedSecret` and `prfSalt` are
// stored in plaintext in Chrome storage. This is the standard WebAuthn PRF
// pattern — the actual key is derived via HKDF(PRF_output, storedSecret).
// An attacker who obtains Chrome storage still cannot derive the key
// without the authenticator's PRF output (requires biometric/PIN).
// The storedSecret provides defense against a compromised authenticator
// (attacker needs both the authenticator AND Chrome storage).

interface MasterPasskeyProtection {
  method: "passkey";
  credentialId: string; // base64url
  prfSalt: string; // base64
  storedSecret: string; // base64 — see security note above
}

interface MasterPasswordProtection {
  method: "password";
  kdfSalt: string; // base64
  encryptedCanary: string; // base64
  canaryIv: string; // base64
}

export type MasterProtection =
  MasterPasskeyProtection | MasterPasswordProtection;

export function isValidMasterProtection(v: unknown): v is MasterProtection {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  if (o.method === "passkey") {
    return (
      typeof o.credentialId === "string" &&
      typeof o.prfSalt === "string" &&
      typeof o.storedSecret === "string"
    );
  }
  if (o.method === "password") {
    return (
      typeof o.kdfSalt === "string" &&
      typeof o.encryptedCanary === "string" &&
      typeof o.canaryIv === "string"
    );
  }
  return false;
}

export async function getMasterProtection(): Promise<MasterProtection | null> {
  const raw = await getItem<unknown>(STORAGE_MASTER_PROTECTION);
  if (isValidMasterProtection(raw)) return raw;
  return null;
}

/** The master protection stored in a specific area, whatever the
 *  (unauthenticated) bootstrap says the vault's location is. */
export async function masterProtectionIn(
  area: "local" | "sync",
): Promise<MasterProtection | null> {
  const raw: unknown = await getChunked(
    area === "sync" ? chrome.storage.sync : chrome.storage.local,
    STORAGE_MASTER_PROTECTION,
  );
  return isValidMasterProtection(raw) ? raw : null;
}

/** Thrown by {@link saveMasterProtection} when a vault already exists. */
export class VaultExistsError extends Error {
  constructor() {
    super(
      "A vault already exists in this browser's storage; refusing to replace its master protection.",
    );
    this.name = "VaultExistsError";
  }
}

/**
 * Persist the master protection of a NEW vault.
 *
 * Refuses when one already exists in EITHER storage area. Replacing it is
 * the one write that makes every sealed key and contact unopenable at a
 * stroke -- the KDF salt and canary (or the passkey's PRF salt) are gone
 * -- and it used to be reachable by anyone who could write the plaintext
 * sync bootstrap: `onboardingComplete: false` put onboarding back up, and
 * onboarding saved over the real vault without looking. Both areas are
 * checked because `storageLocation` is just as forgeable: a local vault
 * looks absent to an engine pointed at `sync`.
 *
 * The UI checks first and explains (`vault-state.ts`); this is the
 * backstop. The only way past it is {@link eraseVault}, behind its own
 * confirmation.
 *
 * A new vault starts a new integrity ledger: one left by an earlier vault
 * would not open under this one's key and would read as tampering.
 *
 * `location` is the area to create the vault in (default: wherever the
 * engine routes now). Onboarding passes the user's choice and records the
 * location only AFTER this succeeds, so a refusal leaves this device's
 * location exactly as it was. The check and the write hold a lock shared
 * by every panel window (`withSharedLock`): two windows onboarding at
 * once could otherwise both pass the check, and the second write would
 * replace the first vault's protection.
 */
export async function saveMasterProtection(
  mp: MasterProtection,
  location?: StorageLocation,
): Promise<void> {
  await withSharedLock(STORAGE_MASTER_PROTECTION, async () => {
    if (
      (await masterProtectionIn("local")) ||
      (await masterProtectionIn("sync"))
    ) {
      throw new VaultExistsError();
    }
    const loc = location ?? (await currentStorageLocation());
    await resetIntegrityLedger();
    await setChunked(
      loc === "sync" ? chrome.storage.sync : chrome.storage.local,
      STORAGE_MASTER_PROTECTION,
      mp,
      loc === "sync",
    );
  });
}
