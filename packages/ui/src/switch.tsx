"use client";

import type * as React from "react";
import { Switch as SwitchPrimitive } from "radix-ui";

import { cn } from "@amibeingpwned/ui";

function Switch({
  className,
  size = "default",
  ...props
}: React.ComponentProps<typeof SwitchPrimitive.Root> & {
  size?: "sm" | "default";
}) {
  return (
    <SwitchPrimitive.Root
      data-slot="switch"
      data-size={size}
      className={cn(
        "peer group/switch inline-flex shrink-0 items-center rounded-full border border-transparent transition-all outline-none",
        // On: green track. Off: a flat grey track; no drawn border.
        "data-[state=checked]:bg-primary",
        "data-[state=unchecked]:bg-[#3a3a3a]",
        "focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px]",
        "disabled:cursor-not-allowed disabled:opacity-50",
        "data-[size=default]:h-5 data-[size=default]:w-9 data-[size=sm]:h-4 data-[size=sm]:w-7",
        className,
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb
        data-slot="switch-thumb"
        className={cn(
          "pointer-events-none block rounded-full shadow-sm ring-0 transition-transform",
          // White knob in both states (white-on-green when checked), light or dark theme.
          "bg-white shadow-[0_1px_2px_rgb(0_0_0/0.35)]",
          "group-data-[size=default]/switch:size-4 group-data-[size=sm]/switch:size-3",
          "data-[state=checked]:translate-x-[calc(100%+2px)] data-[state=unchecked]:translate-x-0",
        )}
      />
    </SwitchPrimitive.Root>
  );
}

export { Switch };
