import { useLayoutEffect, useState, type RefObject } from "react";

/** The row overflows its own box (content pushed past the edge). */
function rowOverflows(row: HTMLElement): boolean {
  return row.scrollWidth > row.clientWidth + 1;
}

/**
 * How far a row must compact to fit (0 = full layout). Measured, not a
 * width breakpoint, because natural width depends on the language. Measures
 * `ref`'s closest `[data-slot="block"]` (or `ref` with `self`) in layout
 * effects, so intermediate levels are never painted.
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
  // Growing past the last-fitted width is the only reason to retry fuller.
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
