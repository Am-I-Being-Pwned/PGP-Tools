import type * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Slot as SlotPrimitive } from "radix-ui";

import { cn } from "./cn";
import { ariaKeyShortcuts, isMacPlatform, Kbd, type ShortcutSpec } from "./kbd";

export const buttonVariants = cva(
  "focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive inline-flex shrink-0 cursor-pointer items-center justify-center gap-2 rounded-lg text-sm font-medium whitespace-nowrap transition-all outline-none focus-visible:ring-[3px] disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        default:
          "bg-primary text-primary-foreground hover:bg-primary/90 shadow-[inset_0_1px_0_rgb(255_255_255/0.25)]",
        // Solid: a destructive action is a stop.
        destructive:
          "bg-destructive hover:bg-destructive/90 focus-visible:ring-destructive/20 dark:focus-visible:ring-destructive/40 text-white shadow-[inset_0_1px_0_rgb(255_255_255/0.15)]",
        // Name kept for callers; it is a filled chip, no border.
        outline:
          "bg-secondary text-secondary-foreground hover:bg-accent shadow-[inset_0_1px_0_rgb(255_255_255/0.07)]",
        secondary:
          "bg-secondary text-secondary-foreground hover:bg-accent shadow-[inset_0_1px_0_rgb(255_255_255/0.07)]",
        ghost: "hover:bg-accent hover:text-accent-foreground",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        default: "h-9 px-4 py-2 has-[>svg]:px-3",
        sm: "h-8 gap-1.5 rounded-md px-3 has-[>svg]:px-2.5",
        lg: "h-10 rounded-lg px-6 has-[>svg]:px-4",
        icon: "size-9",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

export function Button({
  className,
  variant,
  size,
  asChild = false,
  shortcut,
  children,
  ...props
}: React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean;
    /** Display-only keycaps + `aria-keyshortcuts`; binding is the caller's.
     *  Ignored with `asChild`. */
    shortcut?: ShortcutSpec;
  }) {
  const Comp = asChild ? SlotPrimitive.Slot : "button";
  const showShortcut = shortcut !== undefined && !asChild;

  return (
    <Comp
      data-slot="button"
      className={cn(buttonVariants({ variant, size, className }))}
      aria-keyshortcuts={
        shortcut ? ariaKeyShortcuts(shortcut, isMacPlatform()) : undefined
      }
      {...props}
    >
      {showShortcut ? (
        <>
          {children}
          <Kbd shortcut={shortcut} />
        </>
      ) : (
        children
      )}
    </Comp>
  );
}
