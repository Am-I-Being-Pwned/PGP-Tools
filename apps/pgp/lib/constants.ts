export const STORAGE_KEYRING = "pgp_keyring";
export const STORAGE_CONTACTS = "pgp_public_contacts";
/** Plaintext bootstrap (sync): the only prefs readable before unlock --
 *  `storageLocation` (routes all reads) and `onboardingComplete`. Both
 *  are UNAUTHENTICATED (anyone signed in to the Google account can write
 *  them), so neither is trusted to decide whether a vault exists -- see
 *  `lib/storage/vault-state.ts`. Also the legacy full-preferences object
 *  (local area) that predates the split, kept as a one-time, ledger-gated
 *  migration source. */
export const STORAGE_PREFERENCES = "pgp_preferences";
/** This device's own record of where its vault lives ("local" | "sync"),
 *  in chrome.storage.local and never synced. Authoritative once written;
 *  the sync bootstrap's `storageLocation` is only a default for a device
 *  that has none yet -- see `lib/storage/engine.ts`. */
export const STORAGE_DEVICE_LOCATION = "pgp_device_location";
/** Encrypted (AES-256-GCM, padded) blob holding every non-bootstrap
 *  preference. Lives in the user's chosen area; only readable while the
 *  vault session is active. */
export const STORAGE_SETTINGS = "pgp_settings";
export const STORAGE_MASTER_PROTECTION = "pgp_master_protection";
/** Sealed freshness ledger: the highest generation this device has seen
 *  for each sealed store, plus the append-only revocation floor. Always
 *  chrome.storage.local, whatever the vault's location -- see
 *  `lib/storage/integrity.ts` for why it must not follow the vault. */
export const STORAGE_INTEGRITY = "pgp_integrity";
/** Plaintext manifest for the segmented encrypted history store: segment
 *  numbers + byte sizes only, never entry data. Always chrome.storage.local
 *  (sync's total quota is ~100 KB, and history shouldn't leave the device). */
export const STORAGE_HISTORY = "pgp_history";
/** Encrypted history segments live at `pgp_history_seg_<n>`. */
export const STORAGE_HISTORY_SEGMENT_PREFIX = "pgp_history_seg_";
/** RSA-2048 CRX (Chrome extension) signing keys. Same double-envelope
 *  encrypted store as the keyring — see `lib/crx/storage.ts`. */
export const STORAGE_CRX_KEYS = "pgp_crx_keys";

/** Single context-menu item. The action is decided at click time by
 *  inspecting the selection text. Keeping just one item avoids
 *  Chrome's auto-submenu grouping. */
export const MENU_OPEN_IN_PGP = "pgp-open";

/** chrome.storage.session key for the most-recent pending context-menu
 *  operation. Survives service-worker restarts and lets the side panel
 *  pick the op up on mount regardless of timing. */
export const SESSION_PENDING_OP = "pgp_pending_operation";
