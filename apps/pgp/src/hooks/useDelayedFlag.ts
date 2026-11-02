import { useEffect, useState } from "react";

export const DEFAULT_DELAY_MS = 150;

/** Framework-free core of {@link useDelayedFlag}, for unit tests. */
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
 * True only once `active` has held for `delayMs`; false immediately. For
 * loading LABELS only -- controls should still disable off the raw flag.
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

  // `active &&` so deactivation reads false in the same render.
  return active && shown;
}
