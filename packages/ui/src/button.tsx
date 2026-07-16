import type { VariantProps } from "class-variance-authority";
import type * as React from "react";
import { cva } from "class-variance-authority";
import { Slot as SlotPrimitive } from "radix-ui";

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd";
import { cn } from "@amibeingpwned/ui";
import { ariaKeyShortcuts, isMacPlatform, Kbd } from "@amibeingpwned/ui/kbd";

export const buttonVariants = cva(
  "focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive inline-flex shrink-0 cursor-pointer items-center justify-center gap-2 rounded-md text-sm font-medium whitespace-nowrap transition-all outline-none focus-visible:ring-[3px] disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0 [&_svg:not([class*='size-'])]:size-4",
  {
    variants: {
      variant: {
        default:
          "bg-primary text-primary-foreground hover:bg-primary/90 shadow-xs",
        destructive:
          "bg-destructive hover:bg-destructive/90 focus-visible:ring-destructive/20 dark:focus-visible:ring-destructive/40 dark:bg-destructive/60 text-white shadow-xs",
        outline:
          "bg-background hover:bg-accent hover:text-accent-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50 border shadow-xs",
        secondary:
          "bg-secondary text-secondary-foreground hover:bg-secondary/80 shadow-xs",
        ghost:
          "hover:bg-accent hover:text-accent-foreground dark:hover:bg-accent/50",
        link: "text-primary underline-offset-4 hover:underline",
      },
      size: {
        default: "h-9 px-4 py-2 has-[>svg]:px-3",
        sm: "h-8 gap-1.5 rounded-md px-3 has-[>svg]:px-2.5",
        lg: "h-10 rounded-md px-6 has-[>svg]:px-4",
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
    /** Keyboard shortcut hint: renders trailing keycap chips inside the
     *  button and sets `aria-keyshortcuts`. The chips are display only —
     *  binding the keys is the caller's job (e.g. useShortcut). Ignored
     *  with `asChild`, where the button has a single pass-through child. */
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
