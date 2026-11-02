import { OptionBarItem } from "@amibeingpwned/ui/option-bar";

/** One `OptionBar` segment; same size in both states, so no layout shift. */
export function ToggleBadge({
  pressed,
  onPressedChange,
  disabledReason,
  className,
  children,
}: {
  pressed: boolean;
  onPressedChange: (pressed: boolean) => void;
  /** Dimmed with a reason rather than hidden (see lib/actions). */
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
