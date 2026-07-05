import { useState } from "react";

import { Button } from "@amibeingpwned/ui/button";

import { SlideOverHeader, SlideOverPanel, useSlideOver } from "./SlideOver";

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
  const { entered, close } = useSlideOver(onClose);
  const [busyIndex, setBusyIndex] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  const busy = busyIndex !== null;

  const runAction = (index: number) => {
    const action = actions?.[index];
    if (!action || busy || action.disabled) return;
    if (!action.onClick) {
      close();
      return;
    }
    setError(null);
    setBusyIndex(index);
    void (async () => {
      try {
        await action.onClick?.(api);
        if (action.closeOnSuccess) close();
      } catch (e) {
        setError(
          e instanceof Error && e.message
            ? e.message
            : "Something went wrong.",
        );
      } finally {
        setBusyIndex(null);
      }
    })();
  };

  const api: SubPageApi = { close, busy, runAction };

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
            <p className="text-destructive text-xs" role="alert">
              {error}
            </p>
          )}
          {actions.map((action, i) => (
            <Button
              key={i}
              variant={VARIANT[action.type ?? "primary"]}
              className="w-full"
              disabled={busy || action.disabled}
              onClick={() => runAction(i)}
            >
              {busyIndex === i ? (action.busyText ?? "...") : action.text}
            </Button>
          ))}
        </div>
      )}
    </SlideOverPanel>
  );
}
