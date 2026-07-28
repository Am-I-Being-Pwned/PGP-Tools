import { Button } from "@amibeingpwned/ui/button";
import { Kbd } from "@amibeingpwned/ui/kbd";

import type { ShortcutRefEntry } from "../../lib/shortcuts-reference";
import {
  CHROME_SHORTCUTS_URL,
  SHORTCUT_REFERENCE,
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
  return <span className="text-muted-foreground text-xs">Unbound</span>;
}

/**
 * Settings subpage listing every keyboard shortcut, grouped: palette,
 * workspace, modes (derived from MODE_SHORTCUTS), and the browser-wide
 * browser.commands bindings. The data lives in lib/shortcuts-reference.
 */
export function KeyboardShortcutsPage({ onClose }: { onClose: () => void }) {
  return (
    <SubPage title="Keyboard shortcuts" onClose={onClose}>
      <div className="space-y-5">
        {SHORTCUT_REFERENCE.map((section) => (
          <div key={section.title}>
            <h2 className="mb-2 text-sm font-semibold">{section.title}</h2>
            <div className="border-border divide-border divide-y rounded-md border">
              {section.entries.map((entry) => (
                <div
                  key={entry.label}
                  className="flex items-center justify-between gap-4 px-4 py-2.5"
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
                </div>
              ))}
            </div>
            {/* chrome:// URLs render as plain text: pages can't link to
                them, but an extension MAY open one via browser.tabs. */}
            {section.note && (
              <p className="text-muted-foreground mt-1 text-xs">
                {section.note}
              </p>
            )}
            {section.title === "Global browser shortcuts" && (
              <Button
                variant="outline"
                size="sm"
                className="mt-2 w-full"
                onClick={() =>
                  void browser.tabs.create({ url: CHROME_SHORTCUTS_URL })
                }
              >
                Manage browser shortcuts
              </Button>
            )}
          </div>
        ))}
      </div>
    </SubPage>
  );
}
