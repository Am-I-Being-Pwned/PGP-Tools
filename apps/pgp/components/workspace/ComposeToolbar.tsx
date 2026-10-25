import { useRef, useState } from "react";
import {
  BoldIcon,
  CheckIcon,
  CodeIcon,
  ItalicIcon,
  LanguagesIcon,
  LoaderCircleIcon,
  SearchIcon,
  StrikethroughIcon,
} from "lucide-react";

import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@amibeingpwned/ui/command";
import { ariaKeyShortcuts, isMacPlatform } from "@amibeingpwned/ui/kbd-helpers";
import {
  Popover,
  PopoverAnchor,
  PopoverContent,
} from "@amibeingpwned/ui/popover";

import type { TranslationStatus } from "../../lib/ai/run-translation";
import type { InlineStyle } from "../../lib/compose/text-format";
import { languageLabel, translationLanguages } from "../../lib/ai/languages";
import {
  FIND_SHORTCUT,
  STYLE_LABELS,
  STYLE_SHORTCUTS,
} from "../../lib/compose/shortcuts";
import { t } from "../../lib/i18n";
import { HoverLabel } from "./TranslationPanel";

export interface ComposeTranslateProps {
  status: TranslationStatus;
  /** Last picked language, or null before the first pick. */
  targetLanguage: string | null;
  onTranslate: (language: string) => void;
  onUndo: () => void;
  canUndo: boolean;
}

interface ComposeToolbarProps {
  onStyle: (style: InlineStyle) => void;
  onFind: () => void;
  /** Absent when translation is off in Settings or the device has no
   *  model: the button is simply not there. */
  translate?: ComposeTranslateProps;
}

const STYLE_ICONS: Record<
  InlineStyle,
  React.ComponentType<{ className?: string }>
> = {
  bold: BoldIcon,
  italic: ItalicIcon,
  strike: StrikethroughIcon,
  code: CodeIcon,
};

const STYLE_ORDER: InlineStyle[] = ["bold", "italic", "strike", "code"];

/** One button in the strip: borderless, a soft fill on hover. */
const CHIP =
  "text-muted-foreground hover:text-foreground hover:bg-accent flex h-7 w-7 shrink-0 items-center justify-center rounded transition-colors disabled:opacity-60";

/**
 * Editing controls docked in the message card's bottom strip: inline
 * formatting, find, and translate-before-sending. Icon-only with hover
 * labels, mirroring the translate toggle on the result box. Always
 * there -- it sits under the text rather than over it, so there is
 * nothing to fade out of the writer's way.
 */
export function ComposeToolbar({
  onStyle,
  onFind,
  translate,
}: ComposeToolbarProps) {
  const mac = isMacPlatform();
  const [menuOpen, setMenuOpen] = useState(false);
  return (
    <div
      role="toolbar"
      aria-label={t("workspace_message_tools")}
      className="flex items-center gap-0.5"
    >
      {STYLE_ORDER.map((style) => {
        const Icon = STYLE_ICONS[style];
        return (
          <HoverLabel
            key={style}
            label={STYLE_LABELS[style]}
            shortcut={STYLE_SHORTCUTS[style]}
          >
            <button
              type="button"
              aria-label={STYLE_LABELS[style]}
              aria-keyshortcuts={ariaKeyShortcuts(STYLE_SHORTCUTS[style], mac)}
              // Keep focus (and the selection) in the textarea: the
              // style applies to what is selected there.
              onMouseDown={(e) => e.preventDefault()}
              onClick={() => onStyle(style)}
              // Out of the Tab order: Tab from the message goes to
              // Recipients, as it always has; the shortcuts cover these.
              tabIndex={-1}
              className={CHIP}
            >
              <Icon className="h-3.5 w-3.5" />
            </button>
          </HoverLabel>
        );
      })}

      <span aria-hidden className="bg-border mx-1 h-4 w-px" />

      <HoverLabel label={t("workspace_find_replace")} shortcut={FIND_SHORTCUT}>
        <button
          type="button"
          aria-label={t("workspace_find_replace")}
          aria-keyshortcuts={ariaKeyShortcuts(FIND_SHORTCUT, mac)}
          onClick={onFind}
          tabIndex={-1}
          className={CHIP}
        >
          <SearchIcon className="h-3.5 w-3.5" />
        </button>
      </HoverLabel>

      {translate && (
        <TranslateMenu
          {...translate}
          open={menuOpen}
          onOpenChange={setMenuOpen}
        />
      )}
    </div>
  );
}

function TranslateMenu({
  status,
  targetLanguage,
  onTranslate,
  onUndo,
  canUndo,
  open,
  onOpenChange: setOpen,
}: ComposeTranslateProps & {
  /** Owned by the strip. */
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const buttonRef = useRef<HTMLButtonElement>(null);
  const busy = status.kind === "working" || status.kind === "downloading";
  if (status.kind === "unavailable") return null;
  // "Translate" until a language has been picked: a guessed default
  // would put a language the user never asked for on the button.
  const label = busy
    ? t("workspace_translating")
    : targetLanguage
      ? t("workspace_translate_to", { language: languageLabel(targetLanguage) })
      : t("workspace_translate");

  return (
    <>
      <HoverLabel label={label}>
        <button
          ref={buttonRef}
          type="button"
          aria-label={label}
          aria-haspopup="listbox"
          aria-expanded={open}
          disabled={busy}
          tabIndex={-1}
          onClick={() => setOpen(!open)}
          className={CHIP}
        >
          {busy ? (
            <LoaderCircleIcon className="h-3.5 w-3.5 animate-spin motion-reduce:animate-none" />
          ) : (
            <LanguagesIcon className="h-3.5 w-3.5" />
          )}
        </button>
      </HoverLabel>
      {/* Anchored to the chip by ref rather than wrapping it in a
          trigger: the chip already sits inside the hover label's own
          popover, and a nested trigger binds to that one. */}
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverAnchor virtualRef={buttonRef} />
        <PopoverContent align="end" side="top" className="w-56 p-0">
          {/* cmdk does the filtering: the search box IS the language
            picker, so a long list costs nothing to use. */}
          <Command label={t("workspace_translate_menu_heading")}>
            <CommandInput
              placeholder={t("workspace_search_languages")}
              autoFocus
            />
            <CommandList className="max-h-60">
              <CommandEmpty>{t("workspace_no_such_language")}</CommandEmpty>
              <CommandGroup heading={t("workspace_translate_menu_heading")}>
                {translationLanguages().map((l) => (
                  <CommandItem
                    key={l.code}
                    value={`${l.label} ${l.code}`}
                    onSelect={() => {
                      setOpen(false);
                      onTranslate(l.code);
                    }}
                  >
                    <span className="flex-1">{l.label}</span>
                    {l.code === targetLanguage && (
                      <CheckIcon className="text-muted-foreground h-3.5 w-3.5" />
                    )}
                  </CommandItem>
                ))}
              </CommandGroup>
              {canUndo && (
                <CommandGroup>
                  <CommandItem
                    value="restore the original"
                    onSelect={() => {
                      setOpen(false);
                      onUndo();
                    }}
                  >
                    {t("workspace_restore_original")}
                  </CommandItem>
                </CommandGroup>
              )}
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
    </>
  );
}
