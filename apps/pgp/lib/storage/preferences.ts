import { STORAGE_PREFERENCES } from "../constants";
import { getItem, setItem } from "./engine";

export type StorageLocation = "local" | "sync";

export type AutoLockTimeout = 5 | 15 | 30 | 60; // minutes

export interface PgpPreferences {
  defaultSigningKeyId: string | null;
  armoredOutput: boolean;
  advancedMode: boolean;
  storageLocation: StorageLocation;
  onboardingComplete: boolean;
  autoLockMinutes: AutoLockTimeout;
  signWhenEncrypting: boolean;
  activeTab: "workspace" | "keys" | "settings";
  neverCacheKeys: boolean;
  autoDownloadFiles: boolean;
  autoDownloadText: boolean;
  /** When true, lock immediately the moment the OS reports idle, instead
   *  of waiting for the configured autoLockMinutes. OS lockscreen always
   *  triggers an immediate lock regardless of this setting. */
  lockImmediatelyOnIdle: boolean;
  /** When true, lock the moment the side panel becomes hidden (alt-tab
   *  / closed). When false, a 60-second grace period applies so quick
   *  tab-switches don't lock. */
  lockImmediatelyOnTabOut: boolean;
}

const DEFAULT_PREFERENCES: PgpPreferences = {
  defaultSigningKeyId: null,
  armoredOutput: true,
  advancedMode: false,
  storageLocation: "local",
  onboardingComplete: false,
  autoLockMinutes: 15,
  signWhenEncrypting: false,
  activeTab: "workspace",
  neverCacheKeys: false,
  autoDownloadFiles: false,
  autoDownloadText: false,
  lockImmediatelyOnIdle: false,
  lockImmediatelyOnTabOut: false,
};

/**
 * storageLocation is always read from chrome.storage.sync so the engine
 * can bootstrap. All other preferences are stored in the user's chosen area.
 */
async function getStorageLocation(): Promise<StorageLocation> {
  const result = await chrome.storage.sync.get(STORAGE_PREFERENCES);
  const stored = result[STORAGE_PREFERENCES] as
    | { storageLocation?: StorageLocation }
    | undefined;
  return stored?.storageLocation ?? "local";
}

export async function getPreferences(): Promise<PgpPreferences> {
  const storageLocation = await getStorageLocation();
  const stored = await getItem<Partial<PgpPreferences>>(STORAGE_PREFERENCES);
  return { ...DEFAULT_PREFERENCES, ...stored, storageLocation };
}

export async function savePreferences(
  prefs: Partial<PgpPreferences>,
): Promise<void> {
  const current = await getPreferences();
  const merged = { ...current, ...prefs };

  // storageLocation is always persisted to sync so the engine can bootstrap
  if (prefs.storageLocation) {
    const syncResult = await chrome.storage.sync.get(STORAGE_PREFERENCES);
    const syncStored = (syncResult[STORAGE_PREFERENCES] ?? {}) as Record<
      string,
      unknown
    >;
    await chrome.storage.sync.set({
      [STORAGE_PREFERENCES]: {
        ...syncStored,
        storageLocation: prefs.storageLocation,
      },
    });
  }

  await setItem(STORAGE_PREFERENCES, merged);
}
