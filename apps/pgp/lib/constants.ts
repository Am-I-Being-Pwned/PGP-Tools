export const STORAGE_KEYRING = "pgp_keyring";
export const STORAGE_CONTACTS = "pgp_public_contacts";
export const STORAGE_PREFERENCES = "pgp_preferences";
export const STORAGE_MASTER_PROTECTION = "pgp_master_protection";
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
