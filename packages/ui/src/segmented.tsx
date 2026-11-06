import type * as React from "react";
import { useRef } from "react";

import { cn } from "./cn";

interface SegmentedOption<T extends string> {
  value: T;
  label: React.ReactNode;
  /** When `label` is not plain text. */
  ariaLabel?: string;
  ariaKeyShortcuts?: string;
  /** Plain CSS, not a popover layer: a layer would claim Escape and stray
   *  keystrokes while the pointer merely rests. Decorative. */
  hint?: React.ReactNode;
  /** "start"/"end" for an end segment narrower than its hint. */
  hintAlign?: "center" | "start" | "end";
  disabled?: boolean;
}

/**
 * A radio group: one tab stop, arrows move. Use `activation="manual"` when
 * choosing has consequences, so arrowing past an option never acts on it.
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
  skipTab = false,
  className,
}: {
  value: T;
  onValueChange: (value: T) => void;
  options: readonly SegmentedOption<T>[];
  ariaLabel: string;
  fill?: boolean;
  size?: "default" | "sm";
  activation?: "automatic" | "manual";
  /** Below by default: above collides with the header. */
  hintSide?: "top" | "bottom";
  /** For a control with its own shortcuts that Tab would stop on first. */
  skipTab?: boolean;
  className?: string;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const enabled = options
    .map((o, i) => (o.disabled ? -1 : i))
    .filter((i) => i >= 0);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (enabled.length === 0) return;
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
            tabIndex={on && !skipTab ? 0 : -1}
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
                "surface-float text-muted-foreground pointer-events-none absolute z-50 rounded-md px-1.5 py-1 whitespace-nowrap opacity-0 transition-opacity delay-0 duration-150 group-hover/seg:opacity-100 group-hover/seg:delay-[800ms] group-has-[:focus-visible]/seg:opacity-100",
                hintSide === "top" ? "bottom-full mb-2" : "top-full mt-2",
                o.hintAlign === "start"
                  ? "left-0"
                  : o.hintAlign === "end"
                    ? "right-0"
                    : "left-1/2 -translate-x-1/2",
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
