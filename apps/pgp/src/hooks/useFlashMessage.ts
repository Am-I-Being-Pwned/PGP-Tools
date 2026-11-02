import { useEffect, useRef, useState } from "react";

/** A short-lived inline message ("Public key copied"): shown, then
 *  cleared after `ms`; a new message restarts the clock. */
export function useFlashMessage(
  ms = 2000,
): [message: string | null, flash: (message: string) => void] {
  const [message, setMessage] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  const flash = (next: string) => {
    setMessage(next);
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setMessage(null), ms);
  };
  return [message, flash];
}
