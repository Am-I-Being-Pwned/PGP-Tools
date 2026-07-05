import type { PointerEvent } from "react";
import { useEffect, useRef } from "react";

const LONG_PRESS_MS = 500;
// Ignore sub-pixel jitter from a mouse hold, but let a touch-scroll (which
// moves well past this) cancel the gesture.
const MOVE_TOLERANCE_PX = 10;

/**
 * Detect a press-and-hold gesture. `onLongPress` fires after ~500ms unless the
 * pointer lifts or moves past a small tolerance first. Returns pointer handlers
 * to spread on the target plus `consumeClick()` -- call it at the top of the
 * element's onClick to swallow the click that ends a long-press. `enabled`
 * gates the gesture (e.g. off once already in selection mode).
 */
export function useLongPress(onLongPress: () => void, enabled: boolean) {
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const fired = useRef(false);
  const start = useRef<{ x: number; y: number } | null>(null);

  useEffect(() => () => clearTimeout(timer.current), []);

  const cancel = () => {
    clearTimeout(timer.current);
    start.current = null;
  };

  return {
    handlers: {
      onPointerDown: (e: PointerEvent) => {
        if (!enabled) return;
        fired.current = false;
        start.current = { x: e.clientX, y: e.clientY };
        timer.current = setTimeout(() => {
          fired.current = true;
          onLongPress();
        }, LONG_PRESS_MS);
      },
      onPointerMove: (e: PointerEvent) => {
        const s = start.current;
        if (
          s &&
          Math.hypot(e.clientX - s.x, e.clientY - s.y) > MOVE_TOLERANCE_PX
        ) {
          cancel();
        }
      },
      onPointerUp: cancel,
      onPointerLeave: cancel,
    },
    /** True if this click ends a long-press and should be ignored. */
    consumeClick: () => {
      if (fired.current) {
        fired.current = false;
        return true;
      }
      return false;
    },
  };
}
