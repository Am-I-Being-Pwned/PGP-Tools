import { useState } from "react";
import { TriangleAlertIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import { SlideOverHeader, SlideOverPanel, useSlideOver } from "./SlideOver";

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
 * Full-panel destructive-action confirmation, using the same slide-over
 * pattern as the key details page so "a decision that deserves its own
 * screen" looks the same everywhere.
 */
export function ConfirmPage({
  title,
  confirmLabel,
  onConfirm,
  onCancel,
  children,
}: ConfirmPageProps) {
  const { entered, close } = useSlideOver(onCancel);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // On success, slide back out (close() unmounts via onCancel after the
  // animation); on failure, stay put and show why.
  const handleConfirm = async () => {
    setBusy(true);
    setError(null);
    try {
      await onConfirm();
      close();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Something went wrong.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <SlideOverPanel entered={entered} ariaLabel={title}>
      <SlideOverHeader title={title} onBack={close} />
      <div className="flex flex-1 flex-col overflow-y-auto p-3">
        {/* m-auto centers the decision block vertically when it fits,
            and degrades to normal scrolling when it doesn't. */}
        <div className="m-auto w-full space-y-4">
          <div className="border-destructive/30 bg-destructive/5 flex items-start gap-2 rounded-md border p-3">
            <TriangleAlertIcon className="text-destructive mt-0.5 h-4 w-4 shrink-0" />
            <div className="min-w-0 flex-1 text-xs">{children}</div>
          </div>
          {error && <p className="text-destructive text-xs">{error}</p>}
          <div className="space-y-2">
            <Button
              variant="destructive"
              className="w-full"
              disabled={busy}
              onClick={() => void handleConfirm()}
            >
              {busy ? "..." : confirmLabel}
            </Button>
            <Button
              variant="outline"
              className="w-full"
              disabled={busy}
              onClick={close}
            >
              Cancel
            </Button>
          </div>
        </div>
      </div>
    </SlideOverPanel>
  );
}
