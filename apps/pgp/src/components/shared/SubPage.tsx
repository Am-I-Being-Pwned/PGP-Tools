import { useState } from "react";

import { Button, type ShortcutSpec } from "@amibeingpwned/ui";

import { useAsyncAction, useDelayedFlag, useShortcut } from "~/hooks";
import { t } from "~/lib/i18n";
import { SlideOverHeader, SlideOverPanel, useSlideOver } from "./SlideOver";

/** mod+Enter submits the primary footer action, even from inputs. */
const SUBMIT_SHORTCUT: ShortcutSpec = { mod: true, key: "Enter" };

export interface SubPageAction {
  type?: "primary" | "outline" | "destructive";
  text: string;
  busyText?: string;
  disabled?: boolean;
  /** Omit for a plain close button. Reject/throw to stay open with the
   *  error shown. */
  onClick?: (api: SubPageApi) => void | Promise<void>;
  closeOnSuccess?: boolean;
}

export interface SubPageApi {
  close: () => void;
  busy: boolean;
  /** No-op while busy or if that action is disabled. */
  runAction: (index: number) => void;
}

const VARIANT: Record<
  NonNullable<SubPageAction["type"]>,
  "default" | "outline" | "destructive"
> = {
  primary: "default",
  outline: "outline",
  destructive: "destructive",
};

interface SubPageProps {
  title: string;
  onClose: () => void;
  /** Omit when the body owns its actions. */
  actions?: SubPageAction[];
  headerActions?: React.ReactNode;
  bodyClassName?: string;
  children: React.ReactNode | ((api: SubPageApi) => React.ReactNode);
}

/** The app's one modal surface. A rejected footer action shows above the
 *  footer and the page stays open. */
export function SubPage({
  title,
  onClose,
  actions,
  headerActions,
  bodyClassName,
  children,
}: SubPageProps) {
  const { entered, close, isTop } = useSlideOver(onClose);
  const [busyIndex, setBusyIndex] = useState<number | null>(null);
  const footer = useAsyncAction(t("shared_something_went_wrong"));
  const error = footer.error;
  const [showDetail, setShowDetail] = useState(false);

  const busy = busyIndex !== null;
  // Label swap deferred so sub-150ms actions never flash a loading state.
  const showBusyLabel = useDelayedFlag(busy);

  const runAction = (index: number) => {
    const action = actions?.[index];
    if (!action || footer.inFlight || action.disabled) return;
    if (!action.onClick) {
      close();
      return;
    }
    setShowDetail(false);
    void footer.run(async () => {
      setBusyIndex(index);
      try {
        await action.onClick?.(api);
        if (action.closeOnSuccess) close();
      } finally {
        setBusyIndex(null);
      }
    });
  };

  const api: SubPageApi = { close, busy, runAction };

  // Never a destructive action (ConfirmPage must be clicked), and only on
  // the topmost slide-over.
  const shortcutIndex =
    actions?.findIndex((a) => (a.type ?? "primary") === "primary") ?? -1;
  useShortcut(
    SUBMIT_SHORTCUT,
    () => {
      if (isTop()) runAction(shortcutIndex);
    },
    { enabled: shortcutIndex !== -1, allowInSlideOver: true },
  );

  return (
    <SlideOverPanel entered={entered} ariaLabel={title} onDismiss={close}>
      <SlideOverHeader title={title} onBack={close}>
        {headerActions}
      </SlideOverHeader>
      <div
        className={`flex flex-1 flex-col overflow-y-auto ${bodyClassName ?? "p-4"}`}
      >
        {typeof children === "function" ? children(api) : children}
      </div>
      {actions && actions.length > 0 && (
        // The footer is a fixed strip like the header: chrome shade and a
        // hairline, so the body above reads as the one card on the page.
        <div className="bg-chrome space-y-2 border-t border-white/[0.06] p-3">
          {error && (
            <div className="space-y-1" role="alert">
              <p className="text-bad text-xs">{error.message}</p>
              {error.detail && (
                <button
                  type="button"
                  className="text-muted-foreground text-xs underline underline-offset-2"
                  onClick={() => setShowDetail((v) => !v)}
                >
                  {showDetail
                    ? t("shared_hide_technical_details")
                    : t("shared_show_technical_details")}
                </button>
              )}
              {showDetail && error.detail && (
                <p className="text-muted-foreground font-mono text-xs break-all">
                  {error.detail}
                </p>
              )}
            </div>
          )}
          {actions.map((action, i) => (
            <Button
              key={i}
              variant={VARIANT[action.type ?? "primary"]}
              className="w-full"
              disabled={busy || action.disabled}
              onClick={() => runAction(i)}
              shortcut={i === shortcutIndex ? SUBMIT_SHORTCUT : undefined}
            >
              {busyIndex === i && showBusyLabel
                ? (action.busyText ?? "...")
                : action.text}
            </Button>
          ))}
        </div>
      )}
    </SlideOverPanel>
  );
}
