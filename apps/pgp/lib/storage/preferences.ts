import { STORAGE_PREFERENCES, STORAGE_SETTINGS } from "../constants";
import { fromBase64, toBase64, unpackIvCiphertext } from "../encoding";
import {
  decryptContacts,
  encryptContacts,
  hasContactsSession,
} from "../pgp/wasm";
import {
  currentStorageLocation,
  getItem,
  removeItem,
  setItem,
  withLock,
} from "./engine";
import { padPlaintext, unpadPlaintext } from "./padding";

export type StorageLocation = "local" | "sync";

export type AutoLockTimeout = 2 | 5 | 10 | 15 | 30 | 60; // minutes

export interface PgpPreferences {
  defaultSigningKeyId: string | null;
  armoredOutput: boolean;
  advancedMode: boolean;
  storageLocation: StorageLocation;
  onboardingComplete: boolean;
  autoLockMinutes: AutoLockTimeout;
  signWhenEncrypting: boolean;
  /** When encrypting to a contact, also encrypt to one of the user's own
   *  keys so they can decrypt their own ciphertext later. On by default;
   *  turning it off produces output only the recipient can read. */
  encryptToSelf: boolean;
  activeTab: "workspace" | "keys" | "settings";
  neverCacheKeys: boolean;
  autoDownloadFiles: boolean;
  autoDownloadText: boolean;
  /** Master enable for the inactivity timer. When false, unlocked keys
   *  stay unlocked until the user manually locks, the app closes, or
   *  the OS lockscreen fires. `autoLockMinutes` is only consulted when
   *  this is true. */
  autoLockEnabled: boolean;
  /** When true, lock the moment the side panel isn't visible
   *  (alt-tab / collapsed / window hidden). Instant; no grace. */
  lockOnTabAway: boolean;
  /** Master enable for the CRX (Chrome extension) signing feature. Off by
   *  default; when true the CRX signing UI surfaces in Keys/Settings. */
  crxSigningEnabled: boolean;
  /** Opt-in encrypted history of workspace operations. Off by default. */
  historyEnabled: boolean;
  /** Seconds a sensitive clipboard copy (exported private key, revocation
   *  certificate) survives before the best-effort wipe fires. */
  clipboardWipeSeconds: number;
  /** Fingerprints of recently used encrypt recipients, most recent
   *  first (capped). Orders the recipient picker's suggestions. */
  recentRecipients: string[];
  /** The user's preferred own key: preselected for sign/decrypt and
   *  used as the encrypt-to-self key. Null means no explicit choice
   *  (the first key acts as the implicit default). */
  defaultKeyId: string | null;
}

/** Shipped defaults. Stored blobs are partial overlays on top of these,
 *  so a blob written by an older version (missing newer fields) reads
 *  back with the new fields at their defaults. Exported so callers
 *  (e.g. preset detection) can tell "still on defaults" apart from
 *  "explicitly customized". */
export const DEFAULT_PREFERENCES: PgpPreferences = {
  defaultSigningKeyId: null,
  armoredOutput: true,
  advancedMode: false,
  storageLocation: "local",
  onboardingComplete: false,
  autoLockMinutes: 15,
  signWhenEncrypting: false,
  encryptToSelf: true,
  activeTab: "workspace",
  neverCacheKeys: false,
  autoDownloadFiles: false,
  autoDownloadText: false,
  autoLockEnabled: true,
  lockOnTabAway: false,
  crxSigningEnabled: false,
  historyEnabled: false,
  clipboardWipeSeconds: 60,
  recentRecipients: [],
  defaultKeyId: null,
};

// ── bootstrap vs settings split ──────────────────────────────────────
// `storageLocation` and `onboardingComplete` are the only prefs read
// before the vault is unlocked (the engine needs the former to route
// reads; App needs the latter to pick onboarding vs. lock screen), so
// they stay in a plaintext sync blob. Everything else is encrypted.
// NB: the engine's `resolveLocation` reads `storageLocation` straight
// from sync `STORAGE_PREFERENCES`, so that field must remain there.

type BootPrefs = Pick<PgpPreferences, "storageLocation" | "onboardingComplete">;
type SettingsPrefs = Omit<PgpPreferences, keyof BootPrefs>;

const BOOT_KEYS: (keyof BootPrefs)[] = [
  "storageLocation",
  "onboardingComplete",
];

function isBootKey(k: string): k is keyof BootPrefs {
  return (BOOT_KEYS as string[]).includes(k);
}

interface EncryptedBlob {
  iv: string;
  ciphertext: string;
}

function isEncryptedBlob(v: unknown): v is EncryptedBlob {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return typeof o.iv === "string" && typeof o.ciphertext === "string";
}

/** A stored plaintext object that predates the split still carries the
 *  settings fields (e.g. `advancedMode`); the post-split bootstrap only
 *  has `storageLocation`/`onboardingComplete`. */
function isLegacyFullPrefs(v: unknown): v is Partial<PgpPreferences> {
  return typeof v === "object" && v !== null && "advancedMode" in v;
}

// ── bootstrap (plaintext, sync) ──────────────────────────────────────

async function readBoot(): Promise<Partial<BootPrefs>> {
  const result = await chrome.storage.sync.get(STORAGE_PREFERENCES);
  const stored = result[STORAGE_PREFERENCES] as Partial<BootPrefs> | undefined;
  return stored ?? {};
}

async function writeBoot(patch: Partial<BootPrefs>): Promise<void> {
  const current = await readBoot();
  await chrome.storage.sync.set({
    [STORAGE_PREFERENCES]: { ...current, ...patch },
  });
}

// ── settings (encrypted, user area, padded) ──────────────────────────

async function saveSettings(settings: SettingsPrefs): Promise<void> {
  const json = new TextEncoder().encode(JSON.stringify(settings));
  const pad = (await currentStorageLocation()) === "local";
  const packed = await encryptContacts(padPlaintext(json, pad));
  const { iv, ciphertext } = unpackIvCiphertext(packed);
  await setItem<EncryptedBlob>(STORAGE_SETTINGS, {
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
  });
}

async function loadSettings(): Promise<Partial<SettingsPrefs>> {
  const blob = await getItem<unknown>(STORAGE_SETTINGS);
  if (!isEncryptedBlob(blob)) return {};
  const plaintext = await decryptContacts(
    fromBase64(blob.ciphertext),
    fromBase64(blob.iv),
  );
  const json = unpadPlaintext(plaintext);
  const parsed: unknown = JSON.parse(new TextDecoder().decode(json));
  if (typeof parsed !== "object" || parsed === null) return {};
  return parsed;
}

/**
 * One-time migration of a pre-split plaintext preferences object into the
 * bootstrap + encrypted-settings pair. Requires an active session (to
 * encrypt) and the legacy object to still be present. Idempotent: after
 * it runs the legacy full object is gone, so subsequent reads no-op.
 */
// Once we've confirmed (under a session) that no legacy object remains,
// there's nothing to migrate for the rest of this worker's lifetime --
// getPreferences is called from several effects, so skip the storage
// read + lock on every subsequent call. Resets on worker restart, which
// just re-confirms once.
let migrationSettled = false;

async function migrateLegacyIfNeeded(): Promise<void> {
  if (migrationSettled) return;
  // No session yet: can't encrypt. Don't settle -- retry after unlock.
  if (!(await hasContactsSession())) return;
  // Serialize with settings writes so concurrent getPreferences /
  // savePreferences calls can't double-migrate or interleave.
  await withLock(STORAGE_SETTINGS, async () => {
    // The legacy full object is the migration source AND the marker that
    // cleanup is still owed. Its absence means we're done (fresh install
    // or already migrated), so this is idempotent and self-healing after
    // a crash mid-migration.
    const legacy = await getItem<unknown>(STORAGE_PREFERENCES);
    if (!isLegacyFullPrefs(legacy)) {
      migrationSettled = true;
      return;
    }

    const merged = { ...DEFAULT_PREFERENCES, ...legacy };

    // Encrypt the settings unless a prior (crashed) run already did.
    if (!isEncryptedBlob(await getItem<unknown>(STORAGE_SETTINGS))) {
      await saveSettings(pickSettings(merged));
    }

    // Overwrite (not merge) the sync bootstrap with ONLY the two
    // plaintext fields. Merging would leave the legacy settings fields
    // plaintext in the sync object for sync users -- exactly what we're
    // trying to encrypt away.
    await chrome.storage.sync.set({
      [STORAGE_PREFERENCES]: {
        storageLocation: merged.storageLocation,
        onboardingComplete: merged.onboardingComplete,
      },
    });

    // For local users the legacy full object sits in local storage,
    // separate from the sync bootstrap -- drop it. (Sync users' legacy
    // object WAS the sync bootstrap, just overwritten above.)
    if (merged.storageLocation === "local") {
      await removeItem(STORAGE_PREFERENCES);
    }
    migrationSettled = true;
  });
}

function pickSettings(prefs: PgpPreferences): SettingsPrefs {
  const { storageLocation: _s, onboardingComplete: _o, ...rest } = prefs;
  return rest;
}

// ── public API ───────────────────────────────────────────────────────

export async function getPreferences(): Promise<PgpPreferences> {
  await migrateLegacyIfNeeded();

  const boot = await readBoot();
  const storageLocation = boot.storageLocation ?? "local";

  // Pre-split fallback: a local user's onboardingComplete may still live
  // in the legacy full object rather than the bootstrap.
  let onboardingComplete = boot.onboardingComplete;
  if (onboardingComplete === undefined) {
    const legacy = await getItem<unknown>(STORAGE_PREFERENCES);
    onboardingComplete = isLegacyFullPrefs(legacy)
      ? (legacy.onboardingComplete ?? false)
      : false;
  }

  // Settings are only readable with a session; while locked the caller
  // gets defaults (the locked UI is just the unlock screen, which needs
  // none of them). App re-reads and re-applies on unlock.
  const settings = (await hasContactsSession()) ? await loadSettings() : {};

  return {
    ...DEFAULT_PREFERENCES,
    ...settings,
    storageLocation,
    onboardingComplete,
  };
}

export async function savePreferences(
  prefs: Partial<PgpPreferences>,
): Promise<void> {
  const bootPatch: Partial<BootPrefs> = {};
  const settingsPatch: Partial<SettingsPrefs> = {};
  for (const [k, v] of Object.entries(prefs)) {
    if (isBootKey(k)) {
      (bootPatch as Record<string, unknown>)[k] = v;
    } else {
      (settingsPatch as Record<string, unknown>)[k] = v;
    }
  }

  if (Object.keys(bootPatch).length > 0) {
    await writeBoot(bootPatch);
  }

  if (Object.keys(settingsPatch).length > 0) {
    // Settings writes only happen from the unlocked UI, so a session is
    // present. If somehow locked, skip rather than throw -- losing a
    // toggle is better than a crash, and this path shouldn't occur.
    if (!(await hasContactsSession())) return;
    // Serialize read-merge-write so rapid toggles can't clobber fields.
    await withLock(STORAGE_SETTINGS, async () => {
      const current = await loadSettings();
      await saveSettings({
        ...pickSettings(DEFAULT_PREFERENCES),
        ...current,
        ...settingsPatch,
      });
    });
  }
}
