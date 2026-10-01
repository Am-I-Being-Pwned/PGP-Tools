import { LoaderIcon } from "lucide-react";

import { usePasskeyPrompt } from "../../hooks/usePasskeyPrompt";
import { t } from "../../lib/i18n";
import { cancelPasskeyPrompt } from "../../lib/protection/webauthn-prf";

/**
 * Stands in for a passkey button while the browser's passkey dialog is
 * open: a spinner, a Cancel that actually closes the dialog, and -- once
 * it has been a few seconds -- a pointer to where the dialog might be
 * hiding. Renders nothing when no prompt is open.
 */
export function PasskeyWaiting({ className }: { className?: string }) {
  const { open, slow } = usePasskeyPrompt();
  if (!open) return null;
  return (
    <div className={className} role="status" aria-live="polite">
      <div className="text-muted-foreground flex items-center justify-center gap-2 text-sm">
        <LoaderIcon className="h-4 w-4 animate-spin" aria-hidden />
        <span>{t("shared_passkey_waiting")}</span>
      </div>
      {slow && (
        <p className="text-muted-foreground mt-2 text-center text-xs">
          {t("shared_passkey_waiting_hint")}
        </p>
      )}
      <div className="mt-2 text-center">
        <button
          type="button"
          onClick={cancelPasskeyPrompt}
          className="text-muted-foreground hover:text-foreground text-xs underline transition-colors"
        >
          {t("common_cancel")}
        </button>
      </div>
    </div>
  );
}
