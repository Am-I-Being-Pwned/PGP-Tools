import { useEffect, useState, useSyncExternalStore } from "react";

import {
  isPasskeyPromptOpen,
  subscribePasskeyPrompt,
} from "../lib/protection/webauthn-prf";

/** After this long with the prompt still open, assume the user may not
 *  be able to see it (Windows Hello likes to open behind the browser). */
const SLOW_AFTER_MS = 3_000;

/**
 * Whether a passkey prompt is open anywhere in this page, and whether it
 * has been open long enough to suggest it is hidden. Buttons that start
 * a ceremony stay disabled while `open` is true: re-clicking would only
 * supersede the prompt the user is already looking for.
 */
export function usePasskeyPrompt(): { open: boolean; slow: boolean } {
  const open = useSyncExternalStore(
    subscribePasskeyPrompt,
    isPasskeyPromptOpen,
    () => false,
  );
  const [slow, setSlow] = useState(false);
  useEffect(() => {
    setSlow(false);
    if (!open) return;
    const timer = setTimeout(() => setSlow(true), SLOW_AFTER_MS);
    return () => clearTimeout(timer);
  }, [open]);
  return { open, slow };
}
