import type * as React from "react";

import { cn } from "./cn";

/** Independent on/off switches drawn as one bar (any combination on). */
export function OptionBar({
  className,
  ...props
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="option-bar"
      role="group"
      className={cn(
        "grid auto-cols-fr grid-flow-col gap-0.5 overflow-hidden rounded-lg",
        className,
      )}
      {...props}
    />
  );
}

export function OptionBarItem({
  pressed,
  onPressedChange,
  disabledReason,
  className,
  children,
  ...props
}: Omit<React.ComponentProps<"button">, "onClick" | "disabled"> & {
  pressed: boolean;
  onPressedChange: (pressed: boolean) => void;
  /** Dimmed with a reason (as the tooltip), never hidden. */
  disabledReason?: string;
}) {
  const disabled = disabledReason !== undefined;
  return (
    <button
      type="button"
      role="switch"
      aria-checked={pressed}
      disabled={disabled}
      aria-disabled={disabled || undefined}
      title={disabledReason}
      data-slot="option-bar-item"
      data-state={pressed ? "on" : "off"}
      onClick={() => {
        if (disabled) return;
        onPressedChange(!pressed);
      }}
      className={cn(
        "focus-visible:ring-ring/50 h-9 min-w-0 truncate px-2 text-[13px] font-medium transition-colors duration-150 outline-none focus-visible:ring-[3px] focus-visible:ring-inset",
        pressed
          ? "bg-on text-on-foreground shadow-[inset_0_1px_0_rgb(255_255_255/0.06)]"
          : "bg-card text-muted-foreground hover:text-foreground",
        disabled && "cursor-not-allowed opacity-50",
        className,
      )}
      {...props}
    >
      {children}
    </button>
  );
}
