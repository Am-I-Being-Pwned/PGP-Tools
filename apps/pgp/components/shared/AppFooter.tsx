import { Kbd } from "@amibeingpwned/ui/kbd";
import { ariaKeyShortcuts, isMacPlatform } from "@amibeingpwned/ui/kbd-helpers";

import { PALETTE_SHORTCUT } from "../../lib/actions/definitions";

/**
 * Sticky footer used on every top-level shell (onboarding, master
 * unlock, main tabbed view). The byline is here, with a top border as
 * a separator. When `onOpenPalette` is provided (the unlocked main
 * view), a muted mod+K hint advertises the command palette; clicking
 * it opens the palette directly.
 */
export function AppFooter({ onOpenPalette }: { onOpenPalette?: () => void }) {
  return (
    <footer className="border-border flex shrink-0 items-center justify-center gap-3 border-t px-4 py-3.5">
      <p className="text-muted-foreground text-xs">
        A privacy tool by{" "}
        <a
          href="https://amibeingpwned.com"
          target="_blank"
          rel="noopener noreferrer"
          className="text-primary underline underline-offset-2 hover:opacity-80"
        >
          Am I Being Pwned
        </a>
      </p>
      {onOpenPalette && (
        <button
          type="button"
          onClick={onOpenPalette}
          aria-keyshortcuts={ariaKeyShortcuts(PALETTE_SHORTCUT, isMacPlatform())}
          className="text-muted-foreground hover:text-foreground flex items-center gap-1.5 text-xs transition-colors"
        >
          <Kbd shortcut={PALETTE_SHORTCUT} />
          Commands
        </button>
      )}
    </footer>
  );
}
