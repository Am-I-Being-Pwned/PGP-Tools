/**
 * Tagged logger for auto-lock lifecycle events. Prints to console.info
 * with a `[lock]` prefix so DevTools can filter the lock trace from
 * other output. Logs include timer durations, state transitions, and
 * event sources -- never secret material.
 *
 * Toggle off by setting `globalThis.__LOCK_LOG__ = false` in DevTools.
 */

type LockEvent =
  | "prefs"
  | "master.lock"
  | "master.timer-arm"
  | "master.timer-fire"
  | "master.timer-clear"
  | "session.lock-all"
  | "session.lock-key"
  | "session.timer-arm"
  | "session.timer-fire"
  | "session.timer-clear"
  | "session.handle-unlocked"
  | "session.lock-if-no-cache"
  | "session.get-handle"
  | "activity.reset"
  | "tab-away.lock"
  | "os-lockscreen.lock";

declare global {
  // eslint-disable-next-line no-var
  var __LOCK_LOG__: boolean | undefined;
}

export function lockLog(
  event: LockEvent,
  details?: Record<string, unknown>,
): void {
  if (globalThis.__LOCK_LOG__ === false) return;
  // eslint-disable-next-line no-console
  console.info(`[lock] ${event}`, details ?? "");
}
