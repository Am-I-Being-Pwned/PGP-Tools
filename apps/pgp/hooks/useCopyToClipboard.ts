import { toast } from "../lib/toast";
import {
  clipboardWipeDelayMs,
  scheduleClipboardClear,
} from "../lib/utils/clipboard";

/** Options for {@link copyToClipboard}. */
export interface CopyOptions {
  /** Success toast reads "<label> copied" (plus the wipe countdown for
   *  sensitive copies). Omit when the caller renders its own success
   *  feedback (inline check icon etc.) -- failures always toast. */
  label?: string;
  /** Sensitive material (private keys, revocation certificates):
   *  schedule the pref-driven clipboard wipe after the copy. */
  sensitive?: boolean;
  /** Override the wipe delay; defaults to the `clipboardWipeSeconds`
   *  preference. Only meaningful with `sensitive`. */
  wipeDelayMs?: number;
}

/** Clipboard writes reject when the side panel isn't the focused
 *  document (Chrome gates the API on focus). Surfaced, not swallowed. */
const COPY_FAILED_MESSAGE =
  "Copy failed - click the extension panel first, then try again.";

/** One toast slot for all clipboard feedback: rapid successive copies
 *  update in place instead of stacking. */
const COPY_TOAST_ID = "clipboard-copy";

/**
 * Shared clipboard write with uniform feedback: dedups the success
 * toast, schedules the preference-driven wipe for sensitive material
 * (announcing the actual countdown), and surfaces the panel-not-focused
 * rejection as a visible error toast instead of swallowing it. Returns
 * whether the write landed, so callers with their own success UI (2s
 * check icons) can key off it.
 */
export async function copyToClipboard(
  text: string,
  options: CopyOptions = {},
): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    toast.error(COPY_FAILED_MESSAGE, { id: COPY_TOAST_ID });
    return false;
  }
  const { label, sensitive, wipeDelayMs } = options;
  if (sensitive) {
    const delayMs = wipeDelayMs ?? (await clipboardWipeDelayMs());
    scheduleClipboardClear(delayMs);
    if (label) {
      toast.success(
        `${label} copied - clipboard clears in ${Math.round(delayMs / 1000)}s`,
        { id: COPY_TOAST_ID },
      );
    }
  } else if (label) {
    toast.success(`${label} copied`, { id: COPY_TOAST_ID });
  }
  return true;
}

const api = { copy: copyToClipboard };

/**
 * Hook form of {@link copyToClipboard} for components:
 * `const { copy } = useCopyToClipboard()`. The returned object is
 * stable across renders, so `copy` is safe in effect deps.
 */
export function useCopyToClipboard(): { copy: typeof copyToClipboard } {
  return api;
}
