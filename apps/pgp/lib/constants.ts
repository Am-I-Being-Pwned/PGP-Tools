export const STORAGE_KEYRING = "pgp_keyring";
export const STORAGE_CONTACTS = "pgp_public_contacts";
export const STORAGE_PREFERENCES = "pgp_preferences";
export const STORAGE_MASTER_PROTECTION = "pgp_master_protection";

/** Single context-menu item. The action is decided at click time by
 *  inspecting the selection text. Keeping just one item avoids
 *  Chrome's auto-submenu grouping. */
export const MENU_OPEN_IN_PGP = "pgp-open";

// Legacy IDs (no longer registered, kept here in case other tooling
// or tests still reference them).
export const MENU_ENCRYPT = "pgp-encrypt";
export const MENU_DECRYPT = "pgp-decrypt";
export const MENU_SIGN = "pgp-sign";
export const MENU_VERIFY = "pgp-verify";
export const MENU_IMPORT_PUBLIC = "pgp-import-public";
export const MENU_IMPORT_PRIVATE = "pgp-import-private";

/** chrome.storage.session key for the most-recent pending context-menu
 *  operation. Survives service-worker restarts and lets the side panel
 *  pick the op up on mount regardless of timing. */
export const SESSION_PENDING_OP = "pgp_pending_operation";
