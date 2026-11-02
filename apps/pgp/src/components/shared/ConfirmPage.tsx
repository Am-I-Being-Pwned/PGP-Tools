import { useState } from "react";
import { TriangleAlertIcon } from "lucide-react";

import { Input } from "@amibeingpwned/ui";

import { confirmTextMatches } from "~/lib/confirm-text";
import { t } from "~/lib/i18n";
import { SubPage } from "./SubPage";

interface ConfirmPageProps {
  title: string;
  confirmLabel: string;
  onConfirm: () => void | Promise<void>;
  onCancel: () => void;
  /** Destructive button stays disabled until this exact text is typed. */
  confirmPromptText?: string;
  beforeConfirmTextMessage?: string;
  children: React.ReactNode;
}

/** Deliberately keyboard-inert: confirming takes a click (Escape cancels). */
export function ConfirmPage({
  title,
  confirmLabel,
  onConfirm,
  onCancel,
  confirmPromptText,
  beforeConfirmTextMessage,
  children,
}: ConfirmPageProps) {
  const [typed, setTyped] = useState("");
  const confirmBlocked =
    confirmPromptText !== undefined &&
    !confirmTextMatches(confirmPromptText, typed);

  return (
    <SubPage
      title={title}
      onClose={onCancel}
      bodyClassName="p-3"
      actions={[
        {
          type: "destructive",
          text: confirmLabel,
          onClick: () => onConfirm(),
          closeOnSuccess: true,
          disabled: confirmBlocked,
        },
        { type: "outline", text: t("common_cancel") },
      ]}
    >
      {(api) => (
        <div className="m-auto w-full space-y-3">
          <div className="flex items-start gap-2 rounded-xl bg-[#2a1517] p-3">
            <TriangleAlertIcon className="text-bad mt-0.5 h-4 w-4 shrink-0" />
            <div className="min-w-0 flex-1 text-xs">{children}</div>
          </div>
          {confirmPromptText !== undefined && (
            <div className="space-y-2">
              {beforeConfirmTextMessage && (
                <p className="text-muted-foreground text-xs">
                  {beforeConfirmTextMessage}
                </p>
              )}
              <p className="text-xs">
                {t("shared_confirm_type_before")} <b>{confirmPromptText}</b>{" "}
                {t("shared_confirm_type_after")}
              </p>
              <Input
                type="text"
                autoFocus
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                onKeyDown={(e) => {
                  // runAction respects disabled, so Enter on a mismatch no-ops.
                  if (e.key === "Enter") api.runAction(0);
                }}
                aria-label={t("shared_confirm_type_aria", {
                  text: confirmPromptText,
                })}
              />
            </div>
          )}
        </div>
      )}
    </SubPage>
  );
}
