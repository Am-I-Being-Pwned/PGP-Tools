import type { VariantProps } from "class-variance-authority";
import type * as React from "react";
import { cva } from "class-variance-authority";

import { cn } from "@amibeingpwned/ui";

export const inputVariants = cva(
  "placeholder:text-muted-foreground w-full text-sm",
  {
    variants: {
      variant: {
        // A recessed well, not a drawn border.
        field:
          "surface-field focus:ring-ring rounded-lg px-3 py-2 focus:ring-2 focus:outline-none",
        // Bare text inside a field block; the block carries the focus ring.
        bare: "h-7 bg-transparent outline-none",
      },
    },
    defaultVariants: { variant: "field" },
  },
);

export function Input({
  className,
  variant,
  ...props
}: React.ComponentProps<"input"> & VariantProps<typeof inputVariants>) {
  return (
    <input
      data-slot="input"
      className={cn(inputVariants({ variant }), className)}
      {...props}
    />
  );
}
