/** Best-effort clipboard wipe after `delayMs` for copies of sensitive
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

export function scheduleClipboardClear(delayMs = 60_000): void {
  if (clearTimer) clearTimeout(clearTimer);
  clearTimer = setTimeout(() => {
    void navigator.clipboard.writeText("").catch(() => {
      /* clipboard API may have been revoked; nothing to do */
    });
  }, delayMs);
}
