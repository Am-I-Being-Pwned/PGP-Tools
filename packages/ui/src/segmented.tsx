import type * as React from "react";
import { useRef } from "react";

import { cn } from "@amibeingpwned/ui";

export interface SegmentedOption<T extends string> {
  value: T;
  label: React.ReactNode;
  /** Accessible name when `label` is not plain text (an icon). */
  ariaLabel?: string;
  disabled?: boolean;
}

/**
 * Pick exactly one of a few options: a recessed track with the chosen
 * segment raised. A radio group underneath -- one tab stop, arrow keys
 * move and select -- so it reads to assistive tech as the single choice
 * it is.
 */
export function Segmented<T extends string>({
  value,
  onValueChange,
  options,
  ariaLabel,
  fill = false,
  size = "default",
  className,
}: {
  value: T;
  onValueChange: (value: T) => void;
  options: readonly SegmentedOption<T>[];
  ariaLabel: string;
  /** Stretch segments to equal widths across the container. */
  fill?: boolean;
  size?: "default" | "sm";
  className?: string;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const enabled = options
    .map((o, i) => (o.disabled ? -1 : i))
    .filter((i) => i >= 0);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (enabled.length === 0) return;
    const at = enabled.indexOf(options.findIndex((o) => o.value === value));
    let next: number | undefined;
    switch (e.key) {
      case "ArrowRight":
      case "ArrowDown":
        next = enabled[(at + 1) % enabled.length];
        break;
      case "ArrowLeft":
      case "ArrowUp":
        next = enabled[(at - 1 + enabled.length) % enabled.length];
        break;
      case "Home":
        next = enabled[0];
        break;
      case "End":
        next = enabled[enabled.length - 1];
        break;
      default:
        return;
    }
    const target = next === undefined ? undefined : options[next];
    if (next === undefined || !target) return;
    e.preventDefault();
    onValueChange(target.value);
    refs.current[next]?.focus();
  };

  return (
    <div
      role="radiogroup"
      aria-label={ariaLabel}
      onKeyDown={onKeyDown}
      data-slot="segmented"
      className={cn(
        "bg-track flex gap-0.5 rounded-lg p-[3px]",
        fill && "grid auto-cols-fr grid-flow-col",
        className,
      )}
    >
      {options.map((o, i) => {
        const on = o.value === value;
        return (
          <button
            key={o.value}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="radio"
            aria-checked={on}
            aria-label={o.ariaLabel}
            disabled={o.disabled}
            tabIndex={on ? 0 : -1}
            onClick={() => onValueChange(o.value)}
            data-state={on ? "on" : "off"}
            className={cn(
              "focus-visible:ring-ring/50 inline-flex min-w-0 items-center justify-center gap-1.5 truncate rounded-md px-3 font-medium transition-colors duration-150 outline-none focus-visible:ring-[3px] disabled:cursor-not-allowed disabled:opacity-50",
              size === "sm" ? "h-6 text-xs" : "h-7 text-[13px]",
              on
                ? "bg-raised text-foreground shadow-[inset_0_1px_0_rgb(255_255_255/0.1),0_1px_2px_rgb(0_0_0/0.5)]"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}
