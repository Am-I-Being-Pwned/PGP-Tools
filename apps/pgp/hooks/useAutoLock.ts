import { useCallback, useEffect, useEffectEvent, useRef } from "react";

import type { useKeySession } from "./useKeySession";

interface AutoLockOptions {
  session: ReturnType<typeof useKeySession>;
  vaultOpen: boolean;
  lock: (auto: boolean) => Promise<void>;
  autoLockEnabled: boolean;
  autoLockMinutes: number;
  lockOnTabAway: boolean;
}

/** Activity resets the idle timer at most this often. */
const ACTIVITY_THROTTLE_MS = 30_000;

/**
 * The system-initiated locks: the idle timer (reset by activity), focus
 * leaving this window when tab-away lock is on, and the OS lock screen.
 * Returns the idle timer's reset, which an unlock also calls.
 */
export function useAutoLock({
  session,
  vaultOpen,
  lock,
  autoLockEnabled,
  autoLockMinutes,
  lockOnTabAway,
}: AutoLockOptions): () => void {
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const resetTimer = useCallback(() => {
    if (timerRef.current) clearTimeout(timerRef.current);
    if (!autoLockEnabled) return;
    timerRef.current = setTimeout(
      () => void lock(true),
      autoLockMinutes * 60 * 1000,
    );
  }, [autoLockEnabled, autoLockMinutes, lock]);

  useEffect(() => {
    if (!vaultOpen) return;
    resetTimer();
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [vaultOpen, resetTimer]);

  const lockEverything = useEffectEvent(() => {
    if (session.unlockedKeyIds.size > 0) session.lockAll();
    if (vaultOpen) void lock(true);
  });

  const lastActivityRef = useRef(0);
  const onActivity = useEffectEvent(() => {
    const now = Date.now();
    if (now - lastActivityRef.current < ACTIVITY_THROTTLE_MS) return;
    lastActivityRef.current = now;
    if (vaultOpen) resetTimer();
    if (session.unlockedKeyIds.size > 0) session.resetLockTimer();
  });
  useEffect(() => {
    const handler = () => onActivity();
    document.addEventListener("keydown", handler);
    document.addEventListener("pointerdown", handler);
    return () => {
      document.removeEventListener("keydown", handler);
      document.removeEventListener("pointerdown", handler);
    };
  }, []);

  // `windows.onFocusChanged`, not visibilitychange: it ignores system
  // overlays such as the WebAuthn dialog, which re-locked mid-unlock.
  const onFocusChanged = useEffectEvent(
    (windowId: number, ownWindowId: number | null) => {
      if (!lockOnTabAway || ownWindowId === null || windowId === ownWindowId) {
        return;
      }
      lockEverything();
    },
  );
  useEffect(() => {
    let ownWindowId: number | null = null;
    let cancelled = false;
    void chrome.windows.getCurrent().then((win) => {
      if (!cancelled) ownWindowId = win.id ?? null;
    });
    const handler = (windowId: number) => onFocusChanged(windowId, ownWindowId);
    chrome.windows.onFocusChanged.addListener(handler);
    return () => {
      cancelled = true;
      chrome.windows.onFocusChanged.removeListener(handler);
    };
  }, []);

  // OS lock screen: always lock. Only "locked", never chrome.idle's "idle".
  useEffect(() => {
    const handler = (state: "idle" | "active" | "locked") => {
      if (state === "locked") lockEverything();
    };
    chrome.idle.onStateChanged.addListener(handler);
    return () => chrome.idle.onStateChanged.removeListener(handler);
  }, []);

  return resetTimer;
}
