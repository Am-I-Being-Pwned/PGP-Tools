import { t } from "../lib/i18n";
import { toast } from "../lib/toast";

/** Options for {@link copyToClipboard}. */
export interface CopyOptions {
  /** Success toast reads "<label> copied". Omit when the caller renders
   *  its own success feedback (inline check icon etc.) -- failures
   *  always toast. */
  label?: string;
  /** Sensitive material (private keys, revocation certificates): the
   *  toast says it stays on the clipboard and in any clipboard history.
   *  Nothing is wiped -- see T-CLIPBOARD-EXFIL for why that is said
   *  rather than attempted. */
  sensitive?: boolean;
}

/** One toast slot for all clipboard feedback: rapid successive copies
 *  update in place instead of stacking. */
const COPY_TOAST_ID = "clipboard-copy";

/**
 * Shared clipboard write with uniform feedback: dedups the success
 * toast, says where sensitive material now lives (the clipboard and any
 * clipboard history), and surfaces the panel-not-focused rejection as a
 * visible error toast instead of swallowing it. Returns
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
    // Clipboard writes reject when the side panel isn't the focused
    // document (Chrome gates the API on focus). Surfaced, not swallowed.
    toast.error(t("app_copy_failed"), { id: COPY_TOAST_ID });
    return false;
  }
  const { label, sensitive } = options;
  if (label) {
    toast.success(t("app_copied", { label }), {
      id: COPY_TOAST_ID,
      ...(sensitive ? { description: t("app_copied_sensitive_note") } : {}),
    });
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
