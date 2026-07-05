import { useCallback, useRef, useState } from "react";

export interface StackEntry<R> {
  /** Stable identity for React keys — survives stack mutations, so a
   *  panel keeps its mount (and slide state) when entries below it are
   *  dropped. */
  id: number;
  route: R;
}

/**
 * Minimal navigation stack for slide-over subpages. Every entry renders
 * as a panel layered over the base view; `pop` is the back button,
 * `clear` jumps home, `collapseToTop` drops everything beneath the
 * current panel (used after a destructive action succeeds, so the
 * panel's own slide-out reveals the base view rather than a stale page).
 */
export function useNavStack<R>() {
  const nextId = useRef(1);
  const [stack, setStack] = useState<StackEntry<R>[]>([]);

  const push = useCallback((route: R) => {
    setStack((s) => [...s, { id: nextId.current++, route }]);
  }, []);

  const pop = useCallback(() => {
    setStack((s) => s.slice(0, -1));
  }, []);

  const clear = useCallback(() => {
    setStack([]);
  }, []);

  const collapseToTop = useCallback(() => {
    setStack((s) => s.slice(-1));
  }, []);

  return { stack, push, pop, clear, collapseToTop };
}
