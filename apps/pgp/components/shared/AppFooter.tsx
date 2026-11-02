import { ariaKeyShortcuts, isMacPlatform, Kbd } from "@amibeingpwned/ui";

import { PALETTE_SHORTCUT } from "~/lib/actions/definitions";
import { t } from "~/lib/i18n";

export function AppFooter({ onOpenPalette }: { onOpenPalette?: () => void }) {
  return (
    <footer className="bg-chrome flex shrink-0 items-center justify-center gap-3 border-t border-white/[0.06] px-4 py-2.5">
      <p className="text-muted-foreground text-xs">
        {t("shared_byline_before")}{" "}
        <a
          href="https://amibeingpwned.com"
          target="_blank"
          rel="noopener noreferrer"
          className="text-foreground/80 hover:text-foreground underline decoration-white/20 underline-offset-2 transition-colors"
        >
          {/* i18n-ignore */}
          Am I Being Pwned
        </a>
      </p>
      {onOpenPalette && (
        <button
          type="button"
          onClick={onOpenPalette}
          aria-keyshortcuts={ariaKeyShortcuts(
            PALETTE_SHORTCUT,
            isMacPlatform(),
          )}
          className="text-muted-foreground hover:text-foreground flex items-center gap-1.5 text-xs transition-colors"
        >
          <Kbd shortcut={PALETTE_SHORTCUT} />
          {t("shared_commands")}
        </button>
      )}
    </footer>
  );
}
