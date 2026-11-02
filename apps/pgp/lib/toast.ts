import { createElement } from "react";
import { toast as sonnerToast } from "sonner";

export interface ToastOptions {
  /** Same id updates the existing toast instead of stacking a duplicate. */
  id?: string;
  description?: string;
  duration?: number;
  action?: { label: string; onClick: () => void };
}

type Severity = "success" | "info" | "warning" | "error";

/** Sonner's region is aria-live="polite" with no per-toast role, so these
 *  wrap the message in role="alert" to be announced assertively. */
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

/** Use this, never sonner's `toast` directly. Pass a stable `id` wherever
 *  the same toast can fire twice in a row. */
export const toast = {
  message(message: string, options?: ToastOptions): string | number {
    return sonnerToast(message, options);
  },
  success(message: string, options?: ToastOptions): string | number {
    return show("success", message, options);
  },
  info(message: string, options?: ToastOptions): string | number {
    return show("info", message, options);
  },
  warning(message: string, options?: ToastOptions): string | number {
    return show("warning", message, options);
  },
  error(message: string, options?: ToastOptions): string | number {
    return show("error", message, options);
  },
  dismiss(id?: string | number): string | number | undefined {
    return sonnerToast.dismiss(id);
  },
};
