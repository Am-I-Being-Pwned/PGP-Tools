import { Block, BlockLabel, BlockStack, Button, Kbd } from "@amibeingpwned/ui";

import { SubPage } from "~/components/shared/SubPage";
import { t } from "~/lib/i18n";
import {
  CHROME_SHORTCUTS_URL,
  shortcutReference,
  type ShortcutRefEntry,
} from "~/lib/shortcuts-reference";

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

export function KeyboardShortcutsPage({ onClose }: { onClose: () => void }) {
  return (
    <SubPage title={t("settings_shortcuts_title")} onClose={onClose}>
      <div className="space-y-4">
        {shortcutReference().map((section) => (
          <div key={section.id} className="space-y-1.5">
            <BlockLabel as="h2">{section.title}</BlockLabel>
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
            {/* Pages can't link chrome:// URLs, so they render as text. */}
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
