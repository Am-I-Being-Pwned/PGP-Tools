import { CheckIcon } from "lucide-react";

/**
 * A pill-style boolean toggle: on = green-tinted with a check, off = muted
 * outline. Replaces checkbox+label rows where the option reads as a mode
 * rather than a form field. The check icon keeps its footprint when off so
 * toggling never changes the pill's width.
 */
export function ToggleBadge({
  pressed,
  onPressedChange,
  children,
}: {
  pressed: boolean;
  onPressedChange: (pressed: boolean) => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={pressed}
      onClick={() => onPressedChange(!pressed)}
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs transition-colors ${
        pressed
          ? "text-foreground border-green-500/40 bg-green-500/15"
          : "border-input text-muted-foreground hover:bg-accent/50 hover:text-foreground"
      }`}
    >
      <CheckIcon
        aria-hidden
        className={`h-3 w-3 text-green-400 ${pressed ? "" : "invisible"}`}
      />
      {children}
    </button>
  );
}
