import { useEffect, useRef } from "react";

import { isFullyVisible, verticalBounds } from "~/lib/utils/scrollport";

/** Retry times in ms. A smooth scroll is cancelled by any competing scroll
 *  (focus restore, list reflow), so visible cards are skipped and the last
 *  attempt is instant; it must outlast the slide-out (~300ms). */
const RETRY_MS = [0, 250, 600] as const;

/**
 * Scrolls a freshly imported card into view and returns the fade-out ring
 * class. A tuple, not an object: react-hooks/refs flags reading a ref off
 * an object during render.
 */
export function useJustImported(
  active?: boolean,
): [React.RefObject<HTMLDivElement | null>, string | undefined] {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!active) return;
    let cancelled = false;

    const attempt = (behavior: ScrollBehavior) => {
      const el = ref.current;
      if (cancelled || !el?.isConnected) return;
      const { rect, bounds } = verticalBounds(el);
      if (isFullyVisible(rect, bounds)) return;
      el.scrollIntoView({ block: "nearest", behavior });
    };

    // Never fight the user once they have scrolled the list themselves.
    const yieldToUser = () => {
      cancelled = true;
    };
    const events = ["wheel", "touchstart", "keydown"] as const;
    for (const type of events) {
      window.addEventListener(type, yieldToUser, { passive: true });
    }

    const timers = RETRY_MS.map((ms, i) =>
      setTimeout(
        () => attempt(i === RETRY_MS.length - 1 ? "auto" : "smooth"),
        ms,
      ),
    );

    return () => {
      cancelled = true;
      for (const t of timers) clearTimeout(t);
      for (const type of events) {
        window.removeEventListener(type, yieldToUser);
      }
    };
  }, [active]);

  return [ref, active ? "just-imported" : undefined];
}
