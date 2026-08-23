import { useEffect, useRef } from "react";

import { isFullyVisible, verticalBounds } from "../../lib/utils/scrollport";

/** When the scroll is retried, in ms after the card lands.
 *
 *  A smooth scroll is CANCELLABLE: any competing scroll while it is
 *  running silently aborts it, and an import produces several -- the
 *  import panel's focus restore as it closes, and the list reflowing as
 *  the new card takes its place. Losing that race is exactly the
 *  symptom "it highlights it but it doesn't scroll down to it", so each
 *  attempt re-checks whether the card is actually visible and the last
 *  one is instant, which nothing can interrupt. Attempts on an
 *  already-visible card are skipped, so the common case still costs one
 *  scroll. The last must outlast the panel's slide-out (~300ms). */
const RETRY_MS = [0, 250, 600] as const;

/**
 * Marks a card as freshly imported: scrolls it into view and returns the
 * class that runs the fade-out ring (see `.just-imported` in style.css).
 *
 * The point is to answer "where did my key go?" without a dialog -- the
 * import panel slides away and the eye is taken straight to the row that
 * changed. Owning the scroll here (rather than in KeysView) keeps it
 * next to the card that actually knows its own DOM node.
 *
 * Returns a tuple rather than an object so the ref reaches the element
 * as a plain binding: react-hooks/refs (rightly) flags reading a ref off
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
      // A card removed mid-retry (the list refreshed, the user deleted
      // it) has nothing to reveal; scrolling to a detached node would
      // move the list for no reason.
      if (cancelled || !el?.isConnected) return;
      const { rect, bounds } = verticalBounds(el);
      if (isFullyVisible(rect, bounds)) return;
      // `nearest` so revealing a card just below the fold lifts it to
      // the edge rather than yanking the list to centre it.
      el.scrollIntoView({ block: "nearest", behavior });
    };

    // A retry must never fight the user: once they have taken hold of the
    // list themselves, where they are looking is their decision, not ours.
    const yieldToUser = () => {
      cancelled = true;
    };
    const events = ["wheel", "touchstart", "keydown"] as const;
    for (const type of events) {
      window.addEventListener(type, yieldToUser, { passive: true });
    }

    const timers = RETRY_MS.map((ms, i) =>
      // The last attempt is instant: by then the panel has gone and
      // nothing else is scrolling, so this is the one that has to land.
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
