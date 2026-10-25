import { Block, BlockStack } from "@amibeingpwned/ui/block";
import { Button } from "@amibeingpwned/ui/button";
import { Kbd } from "@amibeingpwned/ui/kbd";

import type { ShortcutRefEntry } from "../../lib/shortcuts-reference";
import { t } from "../../lib/i18n";
import {
  CHROME_SHORTCUTS_URL,
  shortcutReference,
} from "../../lib/shortcuts-reference";
import { SubPage } from "../shared/SubPage";

/** Right-hand side of a reference row: platform-aware keycaps, literal
 *  chips, or a muted "Unbound" for entries with neither. */
function EntryKeys({ entry }: { entry: ShortcutRefEntry }) {
  if (entry.shortcut) return <Kbd shortcut={entry.shortcut} />;
  if (entry.chips) {
    return (
      <span aria-hidden="true" className="inline-flex items-center gap-0.5">
        {entry.chips.map((chip) => (
          <kbd
            key={chip}
            className="min-w-4 rounded border border-current/25 bg-current/10 px-1 text-center font-sans text-[10px] leading-4 font-medium opacity-80"
          >
            {chip}
          </kbd>
        ))}
      </span>
    );
  }
  return (
    <span className="text-muted-foreground text-xs">
      {t("settings_shortcuts_unbound")}
    </span>
  );
}

/**
 * Settings subpage listing every keyboard shortcut, grouped: palette,
 * workspace, modes (derived from MODE_SHORTCUTS), and the browser-wide
 * chrome.commands bindings. The data lives in lib/shortcuts-reference.
 */
export function KeyboardShortcutsPage({ onClose }: { onClose: () => void }) {
  return (
    <SubPage title={t("settings_shortcuts_title")} onClose={onClose}>
      <div className="space-y-4">
        {shortcutReference().map((section) => (
          <div key={section.id} className="space-y-1.5">
            <h2 className="text-muted-foreground px-1 text-xs font-medium">
              {section.title}
            </h2>
            <BlockStack>
              {section.entries.map((entry) => (
                <Block
                  key={entry.label}
                  className="flex items-center justify-between gap-4 px-3.5 py-2.5"
                >
                  <div className="min-w-0">
                    <span className="text-sm">{entry.label}</span>
                    {entry.note && (
                      <p className="text-muted-foreground text-xs">
                        {entry.note}
                      </p>
                    )}
                  </div>
                  <span className="text-muted-foreground shrink-0">
                    <EntryKeys entry={entry} />
                  </span>
                </Block>
              ))}
            </BlockStack>
            {/* chrome:// URLs render as plain text: pages can't link to
                them, but an extension MAY open one via chrome.tabs. */}
            {section.note && (
              <p className="text-muted-foreground px-1 text-xs">
                {section.note}
              </p>
            )}
            {section.id === "global" && (
              <Button
                variant="outline"
                size="sm"
                className="w-full"
                onClick={() =>
                  void chrome.tabs.create({ url: CHROME_SHORTCUTS_URL })
                }
              >
                {t("settings_shortcuts_manage")}
              </Button>
            )}
          </div>
        ))}
      </div>
    </SubPage>
  );
}
