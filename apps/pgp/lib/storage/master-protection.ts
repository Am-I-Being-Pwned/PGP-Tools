import type { StorageLocation } from "./preferences";
import { STORAGE_MASTER_PROTECTION } from "../constants";
import { getChunked, setChunked } from "./chunked";
import { currentStorageLocation, getItem, withSharedLock } from "./engine";
import { resetIntegrityLedger, startIntegrityLedger } from "./integrity";

//
// Security: for passkeys, `storedSecret` and `prfSalt` are plaintext in
// storage (standard WebAuthn PRF pattern). The key is HKDF(PRF_output,
// storedSecret), so storage alone is useless without the authenticator,
// and the authenticator alone is useless without storage.

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

/** The master protection in a specific area, regardless of the
 *  (unauthenticated) bootstrap's location. */
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
 * Refuses when one already exists in EITHER area: replacing it makes every
 * sealed key and contact unopenable, and both the bootstrap's
 * `onboardingComplete` and `storageLocation` are forgeable. The UI checks
 * first (`vault-state.ts`); this is the backstop. Only {@link eraseVault}
 * gets past it.
 *
 * Starts a fresh integrity ledger HERE, under the lock and before the
 * protection is written, so it exists before any store write (see
 * `startIntegrityLedger`). The check and write hold `withSharedLock` so two
 * windows onboarding at once can't both pass. Onboarding records
 * `location` only after this succeeds.
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
    await startIntegrityLedger(mp);
    await setChunked(
      loc === "sync" ? chrome.storage.sync : chrome.storage.local,
      STORAGE_MASTER_PROTECTION,
      mp,
      loc === "sync",
    );
  });
}
