import type * as React from "react";

import { cn } from "@amibeingpwned/ui";

/**
 * A card built the design-language way: a stack of flat blocks with 2px
 * of page showing between them, instead of one outlined box with
 * dividers. The stack clips its children, so the first and last block
 * pick up the outer 12px corners and every inner corner stays tight.
 */
export function BlockStack({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="block-stack"
      className={cn(
        "flex flex-col gap-0.5 overflow-hidden rounded-xl",
        className,
      )}
      {...props}
    />
  );
}

/** One flat block in a {@link BlockStack}, or on its own. */
export function Block({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="block"
      className={cn("bg-card text-card-foreground rounded-[3px]", className)}
      {...props}
    />
  );
}

/** The small label that sits above a stack ("Your keys", "Key security"). */
export function BlockLabel({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="block-label"
      className={cn(
        "text-muted-foreground px-1 text-xs font-medium",
        className,
      )}
      {...props}
    />
  );
}
