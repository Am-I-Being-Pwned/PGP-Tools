/**
 * A Linear-style boolean toggle chip. State is signaled the way Linear's
 * property chips do it: OFF is a borderless chip with muted text, ON is a
 * filled chip with a constant neutral border and brighter text. No
 * checkmarks and no colored chrome - fill + text weight carry the state.
 * The border is transparent (not absent) when off, so toggling never
 * shifts layout.
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
      className={`inline-flex h-6 items-center rounded-[5px] border px-2 text-xs font-medium transition-colors duration-150 ${
        pressed
          ? "bg-secondary text-foreground hover:bg-secondary/70 border-green-500/40"
          : "text-muted-foreground hover:bg-accent/50 hover:text-foreground border-transparent bg-transparent"
      }`}
    >
      {children}
    </button>
  );
}
