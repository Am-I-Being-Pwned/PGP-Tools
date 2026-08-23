/**
 * A boolean toggle chip. OFF is a borderless chip with muted text, ON is a
 * filled chip with a constant neutral border and brighter text. No
 * checkmarks and no colored chrome - fill + text weight carry the state.
 * The border is transparent (not absent) when off, so toggling never
 * shifts layout.
 */
export function ToggleBadge({
  pressed,
  onPressedChange,
  disabledReason,
  children,
}: {
  pressed: boolean;
  onPressedChange: (pressed: boolean) => void;
  /** Present ⇒ the toggle cannot be flipped right now, and this says
   *  why. Dimmed-with-a-reason rather than hidden: a toggle that
   *  vanishes when it stops applying looks like a feature that isn't
   *  there (the same rule lib/actions states for disabled actions). */
  disabledReason?: string;
  children: React.ReactNode;
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
      onClick={() => {
        if (disabled) return;
        onPressedChange(!pressed);
      }}
      className={`inline-flex h-6 items-center rounded-[5px] border px-2 text-xs font-medium transition-colors duration-150 ${
        disabled ? "cursor-not-allowed opacity-50" : ""
      } ${
        pressed
          ? "bg-secondary text-foreground hover:bg-secondary/70 border-green-500/40"
          : "text-muted-foreground hover:bg-accent/50 hover:text-foreground border-transparent bg-transparent"
      }`}
    >
      {children}
    </button>
  );
}
