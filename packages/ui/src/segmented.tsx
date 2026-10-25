import type * as React from "react";
import { useRef } from "react";

import { cn } from "@amibeingpwned/ui";

export interface SegmentedOption<T extends string> {
  value: T;
  label: React.ReactNode;
  /** Accessible name when `label` is not plain text (an icon). */
  ariaLabel?: string;
  /** `aria-keyshortcuts` for this option (the binding is the caller's). */
  ariaKeyShortcuts?: string;
  /** A small hint shown above the segment on hover / keyboard focus
   *  (e.g. its shortcut keycaps). Plain CSS, not a popover layer: a
   *  layer would claim Escape and stray keystrokes while the pointer
   *  merely rests on the control. Decorative -- put anything a screen
   *  reader needs in `ariaLabel` / `ariaKeyShortcuts`. */
  hint?: React.ReactNode;
  disabled?: boolean;
}

/**
 * Pick exactly one of a few options: a recessed track with the chosen
 * segment raised. A radio group underneath -- one tab stop, arrow keys
 * move between options -- so it reads to assistive tech as the single
 * choice it is.
 *
 * `activation="manual"` makes the arrows move focus only, with Space /
 * Enter / click choosing. Use it when choosing has consequences (the
 * workspace mode switch resets a finished result): arrowing from
 * Encrypt to Sign must not pass through, and act on, Decrypt.
 */
export function Segmented<T extends string>({
  value,
  onValueChange,
  options,
  ariaLabel,
  fill = false,
  size = "default",
  activation = "automatic",
  hintSide = "bottom",
  className,
}: {
  value: T;
  onValueChange: (value: T) => void;
  options: readonly SegmentedOption<T>[];
  ariaLabel: string;
  /** Stretch segments to equal widths across the container. */
  fill?: boolean;
  size?: "default" | "sm";
  activation?: "automatic" | "manual";
  /** Where option hints appear. Below by default: above, they collide
   *  with whatever header the control sits under. */
  hintSide?: "top" | "bottom";
  className?: string;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const enabled = options
    .map((o, i) => (o.disabled ? -1 : i))
    .filter((i) => i >= 0);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (enabled.length === 0) return;
    // Manual activation steps from the focused segment, automatic from
    // the chosen one (they are the same segment there).
    const focused = refs.current.findIndex((el) => el === e.target);
    const from =
      activation === "manual" && focused >= 0
        ? focused
        : options.findIndex((o) => o.value === value);
    const at = enabled.indexOf(from);
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
    if (activation === "automatic") onValueChange(target.value);
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
        const button = (
          <button
            key={o.value}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="radio"
            aria-checked={on}
            aria-label={o.ariaLabel}
            aria-keyshortcuts={o.ariaKeyShortcuts}
            disabled={o.disabled}
            tabIndex={on ? 0 : -1}
            onClick={() => onValueChange(o.value)}
            data-state={on ? "on" : "off"}
            className={cn(
              "focus-visible:ring-ring/50 inline-flex min-w-0 items-center justify-center gap-1.5 truncate rounded-md px-3 font-medium transition-colors duration-150 outline-none focus-visible:ring-[3px] disabled:cursor-not-allowed disabled:opacity-50",
              o.hint !== undefined && "w-full",
              size === "sm" ? "h-6 text-xs" : "h-7 text-[13px]",
              on
                ? "bg-raised text-foreground shadow-[inset_0_1px_0_rgb(255_255_255/0.1),0_1px_2px_rgb(0_0_0/0.5)]"
                : "text-muted-foreground hover:text-foreground",
            )}
          >
            {o.label}
          </button>
        );
        if (o.hint === undefined) return button;
        return (
          <span key={o.value} className="group/seg relative flex min-w-0">
            {button}
            <span
              aria-hidden="true"
              className={cn(
                "surface-float text-muted-foreground pointer-events-none absolute left-1/2 z-50 -translate-x-1/2 rounded-md px-1.5 py-1 whitespace-nowrap opacity-0 transition-opacity delay-0 duration-150 group-hover/seg:opacity-100 group-hover/seg:delay-[800ms] group-has-[:focus-visible]/seg:opacity-100",
                hintSide === "top" ? "bottom-full mb-2" : "top-full mt-2",
              )}
            >
              {o.hint}
            </span>
          </span>
        );
      })}
    </div>
  );
}
