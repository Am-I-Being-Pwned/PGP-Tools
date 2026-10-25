import type { RefObject } from "react";
import { useLayoutEffect, useState } from "react";

/** The row overflows its own box (content pushed past the edge). */
function rowOverflows(row: HTMLElement): boolean {
  return row.scrollWidth > row.clientWidth + 1;
}

/**
 * How far a row has to compact itself to fit: 0 is the full layout, and
 * each level up is a cheaper rendering the caller defines (drop a counter,
 * then swap a label for an icon). Measured, not guessed from a width
 * breakpoint, because the row's natural width depends on the language:
 * "Clear text" and "Effacer le texte" need different room, and a
 * breakpoint tuned for one is wrong for the next translation.
 *
 * The row measured is `ref`'s closest `[data-slot="block"]` (the strip a
 * Block draws), or `ref` itself with `self`. Runs in layout effects, so
 * the levels it steps through are never painted. `deps` are whatever
 * changes the row's content width.
 */
export function useFitLevel(
  ref: RefObject<HTMLElement | null>,
  maxLevel: number,
  deps: readonly unknown[],
  {
    self = false,
    overflows = rowOverflows,
  }: { self?: boolean; overflows?: (row: HTMLElement) => boolean } = {},
): number {
  const [level, setLevel] = useState(0);
  // Width the row had when it last fitted at the current level; growing
  // past it is the only reason to try a fuller layout again.
  const [fitWidth, setFitWidth] = useState(0);

  const rowOf = (): HTMLElement | null => {
    const el = ref.current;
    if (!el || self) return el;
    return el.closest<HTMLElement>('[data-slot="block"]') ?? el;
  };

  // Content changed: start over from the full layout and step down again.
  useLayoutEffect(() => {
    setLevel(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  // After each level (or content) change, step down once more if the row
  // still overflows. Bounded by `maxLevel`.
  useLayoutEffect(() => {
    const row = rowOf();
    if (!row) return;
    if (level < maxLevel && overflows(row)) setLevel(level + 1);
    else setFitWidth(row.clientWidth);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ref, level, maxLevel, ...deps]);

  useLayoutEffect(() => {
    const row = rowOf();
    if (!row) return;
    const ro = new ResizeObserver(() => {
      if (row.clientWidth > fitWidth + 1) setLevel(0);
      else if (overflows(row)) setLevel((l) => Math.min(l + 1, maxLevel));
    });
    ro.observe(row);
    return () => ro.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ref, maxLevel, fitWidth]);

  return level;
}
