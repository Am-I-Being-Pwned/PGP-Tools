import { t } from "../lib/i18n";
import { toast } from "../lib/toast";

export interface CopyOptions {
  /** Success toast "<label> copied"; omit if the caller shows its own. */
  label?: string;
  /** Toast says it stays on the clipboard/history; nothing is wiped
   *  (T-CLIPBOARD-EXFIL). */
  sensitive?: boolean;
}

/** One toast slot so rapid copies update in place. */
const COPY_TOAST_ID = "clipboard-copy";

/** Clipboard write with uniform feedback. Returns whether it landed. */
export async function copyToClipboard(
  text: string,
  options: CopyOptions = {},
): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Rejects when the side panel isn't focused; surfaced, not swallowed.
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

/** Hook form of {@link copyToClipboard}; `copy` is stable. */
export function useCopyToClipboard(): { copy: typeof copyToClipboard } {
  return api;
}
