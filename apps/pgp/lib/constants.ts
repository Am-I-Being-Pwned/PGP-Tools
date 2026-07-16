export const STORAGE_KEYRING = "pgp_keyring";
export const STORAGE_CONTACTS = "pgp_public_contacts";
/** Plaintext bootstrap (sync): the only prefs readable before unlock --
 *  `storageLocation` (routes all reads) and `onboardingComplete`. Also
 *  the legacy full-preferences object (user area) that predates the
 *  split, kept as a one-time migration source. */
export const STORAGE_PREFERENCES = "pgp_preferences";
/** Encrypted (AES-256-GCM, padded) blob holding every non-bootstrap
 *  preference. Lives in the user's chosen area; only readable while the
 *  vault session is active. */
export const STORAGE_SETTINGS = "pgp_settings";
export const STORAGE_MASTER_PROTECTION = "pgp_master_protection";
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
