import { createElement } from "react";
import { toast as sonnerToast } from "sonner";

/**
 * Options accepted by every {@link toast} method. A subset of sonner's
 * options: everything the app actually uses, plus the stable `id` that
 * makes dedup explicit at the call site.
 */
export interface ToastOptions {
  /** Stable id for repeat-prone toasts: re-firing with the same id
   *  updates the existing toast in place instead of stacking a
   *  duplicate (sonner's documented dedup mechanism). */
  id?: string;
  /** Secondary line under the message. */
  description?: string;
  /** Auto-dismiss override in ms. */
  duration?: number;
  /** Single action button. */
  action?: { label: string; onClick: () => void };
}

type Severity = "success" | "info" | "warning" | "error";

/** Severities that should interrupt a screen reader. Sonner 2.x renders
 *  its whole region with aria-live="polite" and offers no per-toast
 *  role option, so errors/warnings wrap their message in a
 *  role="alert" element -- inserting one into the DOM triggers an
 *  assertive announcement regardless of the surrounding region. */
const ASSERTIVE: readonly Severity[] = ["warning", "error"];

function show(
  severity: Severity,
  message: string,
  options?: ToastOptions,
): string | number {
  const node = ASSERTIVE.includes(severity)
    ? createElement("span", { role: "alert" }, message)
    : message;
  return sonnerToast[severity](node, options);
}

/**
 * Thin wrapper over sonner used by all app code (never import sonner's
 * `toast` directly). Same success/info/warning/error surface, plus:
 * pass a stable {@link ToastOptions.id} wherever the same toast can
 * plausibly fire twice in a row (copy shortcuts, re-run imports,
 * repeated failures) so it updates in place instead of stacking; and
 * warnings/errors are announced assertively to screen readers.
 */
export const toast = {
  /** Neutral toast without a severity icon (sonner's bare `toast()`). */
  message(message: string, options?: ToastOptions): string | number {
    return sonnerToast(message, options);
  },
  /** Green success toast. */
  success(message: string, options?: ToastOptions): string | number {
    return show("success", message, options);
  },
  /** Neutral informational toast. */
  info(message: string, options?: ToastOptions): string | number {
    return show("info", message, options);
  },
  /** Warning toast, announced assertively (role="alert"). */
  warning(message: string, options?: ToastOptions): string | number {
    return show("warning", message, options);
  },
  /** Error toast, announced assertively (role="alert"). */
  error(message: string, options?: ToastOptions): string | number {
    return show("error", message, options);
  },
  /** Dismiss one toast by id, or all toasts when called bare. */
  dismiss(id?: string | number): string | number | undefined {
    return sonnerToast.dismiss(id);
  },
};
