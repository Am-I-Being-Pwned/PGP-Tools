import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";
import { cn } from "@amibeingpwned/ui";
import { formatShortcut, isMacPlatform } from "@amibeingpwned/ui/kbd-helpers";

export type { ShortcutSpec };
export {
  ariaKeyShortcuts,
  formatShortcut,
  formatShortcutTitle,
  isMacPlatform,
} from "@amibeingpwned/ui/kbd-helpers";

/**
 * Keycap chips for a shortcut, Linear-style: one small rounded chip per
 * key, platform-aware (⌘ on macOS, Ctrl elsewhere). Styled with
 * currentColor so the chips adapt to whatever button/surface they sit
 * in, and dim with it when disabled. Decorative only (aria-hidden) —
 * the shortcut belongs in `aria-keyshortcuts` on the interactive
 * element itself.
 */
export function Kbd({
  shortcut,
  className,
}: {
  shortcut: ShortcutSpec;
  className?: string;
}) {
  const keys = formatShortcut(shortcut, isMacPlatform());
  return (
    <span
      aria-hidden="true"
      className={cn("inline-flex items-center gap-0.5", className)}
    >
      {keys.map((key, i) => (
        <kbd
          key={i}
          className="min-w-4 rounded border border-current/25 bg-current/10 px-1 text-center font-sans text-[10px] leading-4 font-medium opacity-80"
        >
          {key}
        </kbd>
      ))}
    </span>
  );
}
