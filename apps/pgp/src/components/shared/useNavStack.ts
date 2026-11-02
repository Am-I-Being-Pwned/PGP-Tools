import { useCallback, useRef, useState } from "react";

export interface StackEntry<R> {
  /** Stable React key, so a panel keeps its mount when entries below drop. */
  id: number;
  route: R;
}

/** `collapseToTop` is for after a destructive action, so the panel's own
 *  slide-out reveals the base view rather than a stale page. */
export function useNavStack<R>() {
  const nextId = useRef(1);
  const [stack, setStack] = useState<StackEntry<R>[]>([]);

  const push = useCallback((route: R) => {
    setStack((s) => [...s, { id: nextId.current++, route }]);
  }, []);

  const pop = useCallback(() => {
    setStack((s) => s.slice(0, -1));
  }, []);

  /** What a panel's own close must use: a deferred `pop` (after the
   *  slide-out) would remove whatever is on top THEN. */
  const remove = useCallback((id: number) => {
    setStack((s) => s.filter((e) => e.id !== id));
  }, []);

  const clear = useCallback(() => {
    setStack([]);
  }, []);

  const collapseToTop = useCallback(() => {
    setStack((s) => s.slice(-1));
  }, []);

  return { stack, push, pop, remove, clear, collapseToTop };
}
