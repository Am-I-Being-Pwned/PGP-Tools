import { clearHistory } from "./storage/history";
import { savePreferences } from "./storage/preferences";

/**
 * The single "entering never-cache" transition, shared by the Settings
 * toggle and the security-preset apply path so the two can't diverge:
 * turns `neverCacheKeys` on, disables history capture, turns
 * `unlockKeysOnOpen` off, and wipes any stored history. Never-cache
 * promises that nothing derived from key use sticks around, so stored
 * history always goes with it, even when capture was already off (old
 * entries could still be sitting there); and unlock-on-open is its
 * opposite -- every master-sealed key live from the first prompt -- so
 * it cannot stay on. It is persisted HERE, not just mirrored into React
 * state, because the next vault unlock reads the STORED preference to
 * decide whether to open keys. Turning never-cache off again later does
 * NOT re-enable history or unlock-on-open.
 */
export async function enterNeverCacheMode(): Promise<void> {
  await savePreferences({
    neverCacheKeys: true,
    historyEnabled: false,
    unlockKeysOnOpen: false,
  });
  await clearHistory();
}
