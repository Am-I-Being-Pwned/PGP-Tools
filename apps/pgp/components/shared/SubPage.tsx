import { useState } from "react";

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";
import { Button } from "@amibeingpwned/ui/button";

import type { PresentedError } from "../../lib/errors/present";
import { useDelayedFlag } from "../../hooks/useDelayedFlag";
import { useShortcut } from "../../hooks/useShortcut";
import { presentError } from "../../lib/errors/present";
import { SlideOverHeader, SlideOverPanel, useSlideOver } from "./SlideOver";

/** mod+Enter submits the primary footer action from anywhere on the
 *  page, including focused inputs (plain Enter-to-submit stays opt-in
 *  per field via `runAction`). */
const SUBMIT_SHORTCUT: ShortcutSpec = { mod: true, key: "Enter" };

/** A footer button. Order in the array is render order (top to bottom). */
export interface SubPageAction {
  /** Visual weight; maps to a Button variant. Defaults to "primary". */
  type?: "primary" | "outline" | "destructive";
  text: string;
  /** Label swapped in while an async onClick is in flight. */
  busyText?: string;
  disabled?: boolean;
  /** Omit for a plain close button (e.g. Cancel). Reject/throw to stay
   *  open with the error shown above the footer. */
  onClick?: (api: SubPageApi) => void | Promise<void>;
  /** Slide out after onClick resolves. */
  closeOnSuccess?: boolean;
}

export interface SubPageApi {
  /** Slide out, then fire onClose (where the parent unmounts the page). */
  close: () => void;
  /** True while any footer action's onClick is in flight. */
  busy: boolean;
  /** Trigger a footer action by index — e.g. Enter-to-submit from an
   *  input. No-op while busy or if that action is disabled. */
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
  /** Called after the slide-out finishes; the parent unmounts the page. */
  onClose: () => void;
  /** Stacked full-width footer buttons. Omit when the body owns its
   *  actions (multi-step flows, inline unlock rows, ...). */
  actions?: SubPageAction[];
  /** Right-aligned extras in the header bar. */
  headerActions?: React.ReactNode;
  /** Classes for the scrollable body (padding etc.). Defaults to p-4. */
  bodyClassName?: string;
  children: React.ReactNode | ((api: SubPageApi) => React.ReactNode);
}

/**
 * The app's one modal surface: a full-screen slide-over subpage with a
 * back-arrow header, a scrollable body, and an optional footer of
 * stacked action buttons. Anything that used to be a Dialog renders as
 * one of these — pushed on a nav stack (KeysView) or mounted
 * conditionally (Settings, lock screen).
 *
 * Footer actions get shared busy handling: while one onClick is in
 * flight every footer button disables, the running one shows its
 * `busyText`, and a rejection surfaces as an error line above the
 * footer (the page stays open).
 */
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
  const [error, setError] = useState<PresentedError | null>(null);
  const [showDetail, setShowDetail] = useState(false);

  const busy = busyIndex !== null;
  // Buttons disable immediately off `busy`; the busyText label swap is
  // deferred so sub-150ms actions never flash a loading state.
  const showBusyLabel = useDelayedFlag(busy);

  const runAction = (index: number) => {
    const action = actions?.[index];
    if (!action || busy || action.disabled) return;
    if (!action.onClick) {
      close();
      return;
    }
    setError(null);
    setShowDetail(false);
    setBusyIndex(index);
    void (async () => {
      try {
        await action.onClick?.(api);
        if (action.closeOnSuccess) close();
      } catch (e) {
        setError(presentError(e, "Something went wrong. Try again."));
      } finally {
        setBusyIndex(null);
      }
    })();
  };

  const api: SubPageApi = { close, busy, runAction };

  // mod+Enter drives the primary footer action -- but never a
  // destructive one (ConfirmPage et al. must be clicked deliberately),
  // and only on the topmost slide-over when panels stack.
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
    <SlideOverPanel entered={entered} ariaLabel={title}>
      <SlideOverHeader title={title} onBack={close}>
        {headerActions}
      </SlideOverHeader>
      <div
        className={`flex flex-1 flex-col overflow-y-auto ${bodyClassName ?? "p-4"}`}
      >
        {typeof children === "function" ? children(api) : children}
      </div>
      {actions && actions.length > 0 && (
        <div className="border-border space-y-2 border-t p-4">
          {error && (
            <div className="space-y-1" role="alert">
              <p className="text-destructive text-xs">{error.message}</p>
              {error.detail && (
                <button
                  type="button"
                  className="text-muted-foreground text-xs underline underline-offset-2"
                  onClick={() => setShowDetail((v) => !v)}
                >
                  {showDetail
                    ? "Hide technical details"
                    : "Show technical details"}
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
