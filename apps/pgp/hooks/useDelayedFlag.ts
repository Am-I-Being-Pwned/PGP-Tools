import { useEffect, useState } from "react";

/** Default hold-off before a loading label may appear. Operations that
 *  finish faster than this never flash a loading state (Linear's
 *  deferred-fallback rule). */
export const DEFAULT_DELAY_MS = 150;

/** Framework-free core of {@link useDelayedFlag}: reports `true` via
 *  `onChange` only after `update(true)` has been in effect for
 *  `delayMs` without an intervening `update(false)`; reports `false`
 *  immediately on deactivation. Extracted so the timing semantics are
 *  unit-testable without a React renderer. */
export function createDelayedFlag(
  delayMs: number,
  onChange: (value: boolean) => void,
): { update: (active: boolean) => void; dispose: () => void } {
  let timer: ReturnType<typeof setTimeout> | undefined;
  let value = false;

  const update = (active: boolean): void => {
    if (!active) {
      clearTimeout(timer);
      timer = undefined;
      if (value) {
        value = false;
        onChange(false);
      }
      return;
    }
    if (value || timer !== undefined) return;
    timer = setTimeout(() => {
      timer = undefined;
      value = true;
      onChange(true);
    }, delayMs);
  };

  const dispose = (): void => {
    clearTimeout(timer);
    timer = undefined;
  };

  return { update, dispose };
}

/**
 * Deferred loading flag: returns `false` immediately whenever `active`
 * is false, and flips to `true` only once `active` has been
 * continuously true for `delayMs`. Use it for loading LABELS so
 * sub-{@link DEFAULT_DELAY_MS} operations never flicker a spinner or
 * "Processing..." text (the control itself should still disable
 * immediately off the raw flag).
 */
export function useDelayedFlag(
  active: boolean,
  delayMs = DEFAULT_DELAY_MS,
): boolean {
  const [shown, setShown] = useState(false);

  useEffect(() => {
    const flag = createDelayedFlag(delayMs, setShown);
    flag.update(active);
    return () => flag.dispose();
  }, [active, delayMs]);

  // `active && shown` (not just `shown`) so deactivation reads false in
  // the very same render, before the effect has re-run.
  return active && shown;
}
