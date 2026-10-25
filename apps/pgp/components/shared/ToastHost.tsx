import type * as React from "react";
import { useLayoutEffect, useState } from "react";
import { Toaster, useSonner } from "sonner";

/** Gap between a toast and the edge of the card it rises from. */
const GAP = 8;
/** The panel's side gutter, and the toasts' bottom edge with no anchor. */
const GUTTER = 16;

/**
 * Where a toast should sit: just above the first `[data-toast-anchor]`
 * on screen -- the workspace card's file list or its tool strip -- so a
 * toast about the message ("Text cleared", Undo) appears beside the
 * message rather than over the action button. No anchor in view (another
 * tab, a subpage), the usual bottom gutter.
 */
function anchoredBottom(): number {
  for (const el of document.querySelectorAll("[data-toast-anchor]")) {
    const rect = el.getBoundingClientRect();
    if (rect.height === 0) continue; // on a hidden tab
    return Math.max(GUTTER, window.innerHeight - rect.top + GAP);
  }
  return GUTTER;
}

/**
 * The panel's one `<Toaster />`, in the design language: a floating
 * surface with no outline, a filled chip for the action, and the tone in
 * the icon only (green go, amber warn, red stop). No corner close badge.
 *
 * The offset is measured while toasts are showing, and again whenever
 * the page reflows under them (files added or removed, the box growing),
 * so a toast stays clear of the controls it is about.
 */
export function ToastHost() {
  const { toasts } = useSonner();
  const active = toasts.length > 0;
  const [bottom, setBottom] = useState(GUTTER);

  useLayoutEffect(() => {
    if (!active) return;
    const measure = () => setBottom(anchoredBottom());
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(document.body);
    for (const el of document.querySelectorAll("[data-toast-anchor]")) {
      ro.observe(el);
    }
    window.addEventListener("resize", measure);
    document.addEventListener("scroll", measure, true);
    return () => {
      ro.disconnect();
      window.removeEventListener("resize", measure);
      document.removeEventListener("scroll", measure, true);
    };
  }, [active, toasts]);

  const offset = { bottom, left: GUTTER, right: GUTTER };
  return (
    <Toaster
      theme="dark"
      position="bottom-center"
      // No corner close badge: it hung off the surface's edge, outside
      // the flat-block look. Toasts here are short-lived and swipe away.
      offset={offset}
      mobileOffset={offset}
      gap={6}
      style={
        {
          "--normal-bg": "var(--popover)",
          "--normal-text": "var(--popover-foreground)",
          "--normal-border": "transparent",
        } as React.CSSProperties
      }
      toastOptions={{
        // Sonner's injected styles win the cascade, hence the `!`s.
        classNames: {
          toast:
            "surface-float !rounded-xl !border-0 !gap-2.5 !py-2.5 !pr-2.5 !pl-3.5 !text-[13px]",
          title: "!font-medium",
          description: "!text-muted-foreground !text-xs",
          icon: "!size-4 [&>svg]:!size-4",
          success: "[&_[data-icon]]:!text-good",
          warning: "[&_[data-icon]]:!text-warn",
          error: "[&_[data-icon]]:!text-bad",
          info: "[&_[data-icon]]:!text-muted-foreground",
          actionButton:
            "!bg-raised !text-foreground !h-7 !rounded-md !px-2.5 !text-xs !font-medium !shadow-[inset_0_1px_0_rgb(255_255_255/0.1),0_1px_2px_rgb(0_0_0/0.5)] hover:!bg-accent",
          cancelButton:
            "!bg-transparent !text-muted-foreground !h-7 !rounded-md !px-2 !text-xs",
        },
      }}
    />
  );
}
