import type * as React from "react";
import { useLayoutEffect, useState } from "react";
import { Toaster, useSonner } from "sonner";

const GAP = 8;
const GUTTER = 16;

/** Just above the first visible `[data-toast-anchor]`, so a toast about the
 *  message sits beside it, not over the action button. */
function anchoredBottom(): number {
  for (const el of document.querySelectorAll("[data-toast-anchor]")) {
    const rect = el.getBoundingClientRect();
    if (rect.height === 0) continue; // on a hidden tab
    return Math.max(GUTTER, window.innerHeight - rect.top + GAP);
  }
  return GUTTER;
}

/** Re-measured whenever the page reflows, so toasts stay clear of the
 *  controls they are about. */
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
