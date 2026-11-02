import { useEffect, useRef, type PointerEvent } from "react";

const LONG_PRESS_MS = 500;
// Ignore mouse jitter, but let a touch-scroll cancel the gesture.
const MOVE_TOLERANCE_PX = 10;

/** Press-and-hold (~500ms). Call `consumeClick()` at the top of onClick to
 *  swallow the click that ends a long-press. */
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
    consumeClick: () => {
      if (fired.current) {
        fired.current = false;
        return true;
      }
      return false;
    },
  };
}
