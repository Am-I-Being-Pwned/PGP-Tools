import { clearHistory } from "./storage/history";
import { savePreferences } from "./storage/preferences";

/**
 * The one "entering never-cache" transition (Settings and presets share
 * it): never-cache on, history capture off AND stored history wiped,
 * unlock-on-open off. Persisted here because the next unlock reads the
 * STORED preference. Turning never-cache off restores none of these.
 */
export async function enterNeverCacheMode(): Promise<void> {
  await savePreferences({
    neverCacheKeys: true,
    historyEnabled: false,
    unlockKeysOnOpen: false,
  });
  await clearHistory();
}
