export const STORAGE_KEYRING = "pgp_keyring";
export const STORAGE_CONTACTS = "pgp_public_contacts";
/** Plaintext sync bootstrap (`storageLocation`, `onboardingComplete`).
 *  UNAUTHENTICATED, so never trusted to decide whether a vault exists
 *  (`lib/storage/vault-state.ts`). Also the legacy prefs migration source. */
export const STORAGE_PREFERENCES = "pgp_preferences";
/** Local, never synced; authoritative over the sync bootstrap once written
 *  (`lib/storage/engine.ts`). */
export const STORAGE_DEVICE_LOCATION = "pgp_device_location";
/** Encrypted blob of every non-bootstrap preference. */
export const STORAGE_SETTINGS = "pgp_settings";
export const STORAGE_MASTER_PROTECTION = "pgp_master_protection";
/** Freshness ledger; always local, must not follow the vault
 *  (`lib/storage/integrity.ts`). */
export const STORAGE_INTEGRITY = "pgp_integrity";
/** History manifest (segment numbers + sizes only); always local. */
export const STORAGE_HISTORY = "pgp_history";
export const STORAGE_HISTORY_SEGMENT_PREFIX = "pgp_history_seg_";
/** Same double-envelope store as the keyring (`lib/crx/storage.ts`). */
export const STORAGE_CRX_KEYS = "pgp_crx_keys";

/** One item (action chosen at click time) avoids Chrome's auto-submenu. */
export const MENU_OPEN_IN_PGP = "pgp-open";

export const SESSION_PENDING_OP = "pgp_pending_operation";
