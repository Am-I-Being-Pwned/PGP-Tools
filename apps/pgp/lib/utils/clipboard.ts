import { getPreferences } from "../storage/preferences";

/** Fallback wipe delay when preferences are unreadable (e.g. vault
 *  locked mid-copy, storage error). Matches the pref default. */
const FALLBACK_WIPE_MS = 60_000;

/** Best-effort clipboard wipe after a delay for copies of sensitive
 *  material (exported private keys, revocation certificates). We can't
 *  read the clipboard to know if the user has since copied something
 *  else (no permission), so the wipe is unconditional -- acceptable to
 *  avoid leaving the material in clipboard history or cloud clipboard
 *  sync.
 *
 *  The timer is module-level on purpose: the whole point of copying is
 *  to close the page and paste elsewhere, so the wipe must survive the
 *  copying component's unmount -- not be cancelled (the material would
 *  linger forever) and not fire early (the paste window would vanish).
 *  A re-copy from anywhere resets the single deadline. */
let clearTimer: ReturnType<typeof setTimeout> | undefined;

function armWipe(delayMs: number): void {
  if (clearTimer) clearTimeout(clearTimer);
  clearTimer = setTimeout(() => {
    void navigator.clipboard.writeText("").catch(() => {
      /* clipboard API may have been revoked; nothing to do */
    });
  }, delayMs);
}

/**
 * Schedule the clipboard wipe. With no argument the delay comes from the
 * `clipboardWipeSeconds` preference, read at call time (falling back to
 * 60 s if preferences are unreadable); pass `delayMs` to override.
 * Synchronous for callers either way -- the pref read arms the timer
 * when it resolves.
 */
export function scheduleClipboardClear(delayMs?: number): void {
  if (delayMs !== undefined) {
    armWipe(delayMs);
    return;
  }
  void getPreferences()
    .then((prefs) => armWipe(prefs.clipboardWipeSeconds * 1000))
    .catch(() => armWipe(FALLBACK_WIPE_MS));
}
