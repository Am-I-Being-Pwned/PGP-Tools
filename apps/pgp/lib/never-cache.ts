import { clearHistory } from "./storage/history";
import { savePreferences } from "./storage/preferences";

/**
 * The single "entering never-cache" transition, shared by the Settings
 * toggle and the security-preset apply path so the two can't diverge:
 * turns `neverCacheKeys` on, disables history capture, and wipes any
 * stored history. Never-cache promises that nothing derived from key
 * use sticks around, so stored history always goes with it, even when
 * capture was already off (old entries could still be sitting there).
 * Turning never-cache off again later does NOT re-enable history.
 */
export async function enterNeverCacheMode(): Promise<void> {
  await savePreferences({ neverCacheKeys: true, historyEnabled: false });
  await clearHistory();
}
