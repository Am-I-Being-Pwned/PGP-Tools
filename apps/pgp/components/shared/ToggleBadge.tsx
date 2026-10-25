import { OptionBarItem } from "@amibeingpwned/ui/option-bar";

/**
 * A boolean toggle: one segment of an `OptionBar`. OFF is a flat block
 * with muted text, ON is tinted green (green means on). The segment
 * keeps its size in both states, so toggling never shifts layout.
 *
 * Kept as its own name rather than calling `OptionBarItem` directly so
 * the workspace's toggles keep one place that says what a toggle is in
 * this app; the bar itself (`OptionBar`) is the caller's to lay out.
 */
export function ToggleBadge({
  pressed,
  onPressedChange,
  disabledReason,
  className,
  children,
}: {
  pressed: boolean;
  onPressedChange: (pressed: boolean) => void;
  /** Present ⇒ the toggle cannot be flipped right now, and this says
   *  why. Dimmed-with-a-reason rather than hidden: a toggle that
   *  vanishes when it stops applying looks like a feature that isn't
   *  there (the same rule lib/actions states for disabled actions). */
  disabledReason?: string;
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <OptionBarItem
      pressed={pressed}
      onPressedChange={onPressedChange}
      disabledReason={disabledReason}
      className={className}
    >
      {children}
    </OptionBarItem>
  );
}
