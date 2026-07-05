import { TriangleAlertIcon } from "lucide-react";

import { SubPage } from "./SubPage";

interface ConfirmPageProps {
  title: string;
  /** Destructive button label, e.g. "Delete key". */
  confirmLabel: string;
  /** Runs the action; the caller closes/unmounts everything after. */
  onConfirm: () => void | Promise<void>;
  /** Called after the cancel slide-out finishes. */
  onCancel: () => void;
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
  children,
}: ConfirmPageProps) {
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
        },
        { type: "outline", text: "Cancel" },
      ]}
    >
      {/* m-auto centers the decision block vertically when it fits,
          and degrades to normal scrolling when it doesn't. */}
      <div className="m-auto w-full">
        <div className="border-destructive/30 bg-destructive/5 flex items-start gap-2 rounded-md border p-3">
          <TriangleAlertIcon className="text-destructive mt-0.5 h-4 w-4 shrink-0" />
          <div className="min-w-0 flex-1 text-xs">{children}</div>
        </div>
      </div>
    </SubPage>
  );
}
