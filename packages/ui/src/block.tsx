import type * as React from "react";

import { cn } from "./cn";

/** A stack of flat blocks with 2px gaps; it clips, so end blocks take the
 *  outer corners. */
export function BlockStack({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="block-stack"
      className={cn(
        // End blocks take the corners themselves so focus rings follow them.
        "flex flex-col gap-0.5 overflow-hidden rounded-xl [&>:first-child]:rounded-t-xl [&>:last-child]:rounded-b-xl",
        className,
      )}
      {...props}
    />
  );
}

export function Block({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="block"
      className={cn("bg-card text-card-foreground rounded-[3px]", className)}
      {...props}
    />
  );
}

/** Use `as="h2"`/`"h3"` for section heads: screen readers and e2e helpers
 *  navigate by them. */
export function BlockLabel({
  as: Comp = "div",
  className,
  ...props
}: React.HTMLAttributes<HTMLElement> & {
  as?: "div" | "p" | "h2" | "h3";
}) {
  return (
    <Comp
      data-slot="block-label"
      className={cn(
        "text-muted-foreground px-1 text-xs font-medium",
        className,
      )}
      {...props}
    />
  );
}
