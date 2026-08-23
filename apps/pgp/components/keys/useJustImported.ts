import { useEffect, useRef } from "react";

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
    // `nearest` so an already-visible card doesn't jump the list around;
    // only an off-screen one actually scrolls.
    ref.current?.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [active]);

  return [ref, active ? "just-imported" : undefined];
}
