import { useState } from "react";
import { TriangleAlertIcon } from "lucide-react";

import { confirmTextMatches } from "../../lib/confirm-text";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { SubPage } from "./SubPage";

interface ConfirmPageProps {
  title: string;
  /** Destructive button label, e.g. "Delete key". */
  confirmLabel: string;
  /** Runs the action; the caller closes/unmounts everything after. */
  onConfirm: () => void | Promise<void>;
  /** Called after the cancel slide-out finishes. */
  onCancel: () => void;
  /** When set, the destructive button stays disabled until the user types
   *  this exact text into a confirmation input (whitespace-trimmed). Use
   *  for the highest-stakes deletes, e.g. anything with a private key. */
  confirmPromptText?: string;
  /** Optional extra line rendered above the type-to-confirm input. */
  beforeConfirmTextMessage?: string;
  /** What's at stake: subject summary + consequence copy. */
  children: React.ReactNode;
}

/**
 * Full-panel destructive-action confirmation, so "a decision that
 * deserves its own screen" looks the same everywhere. On success the
 * page slides back out; on failure it stays put and shows why.
 */
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
        { type: "outline", text: "Cancel" },
      ]}
    >
      {(api) => (
        // m-auto centers the decision block vertically when it fits,
        // and degrades to normal scrolling when it doesn't.
        <div className="m-auto w-full space-y-3">
          <div className="border-destructive/30 bg-destructive/5 flex items-start gap-2 rounded-md border p-3">
            <TriangleAlertIcon className="text-destructive mt-0.5 h-4 w-4 shrink-0" />
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
                To confirm, type <b>{confirmPromptText}</b> below
              </p>
              <input
                type="text"
                autoFocus
                value={typed}
                onChange={(e) => setTyped(e.target.value)}
                onKeyDown={(e) => {
                  // runAction respects the disabled flag, so Enter on a
                  // mismatch is a no-op; Escape still closes via SlideOver.
                  if (e.key === "Enter") api.runAction(0);
                }}
                aria-label={`Type "${confirmPromptText}" to confirm`}
                className={INPUT_CLASS}
              />
            </div>
          )}
        </div>
      )}
    </SubPage>
  );
}
