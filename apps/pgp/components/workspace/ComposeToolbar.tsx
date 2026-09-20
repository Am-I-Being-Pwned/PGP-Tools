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
import { languageLabel, TRANSLATION_LANGUAGES } from "../../lib/ai/languages";
import {
  FIND_SHORTCUT,
  STYLE_LABELS,
  STYLE_SHORTCUTS,
} from "../../lib/compose/shortcuts";
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

/** The same chip the result box's translate toggle uses, so the two
 *  boxes' floating controls read as one family. */
const CHIP =
  "border-border bg-background/90 hover:border-muted-foreground/40 hover:text-foreground text-muted-foreground pointer-events-auto shrink-0 rounded-md border p-2 shadow-sm backdrop-blur transition-colors disabled:opacity-60";

/**
 * Editing controls floating in the bottom-right corner of the message
 * box: inline formatting, find, and translate-before-sending. Icon-only
 * with hover labels, mirroring the translate toggle on the result box;
 * `pointer-events-none` on the strip (set by the parent) keeps it from
 * eating selection drags, and each chip re-enables them for itself.
 */
export function ComposeToolbar({
  onStyle,
  onFind,
  translate,
}: ComposeToolbarProps) {
  const mac = isMacPlatform();
  return (
    <div
      role="toolbar"
      aria-label="Message tools"
      className="pointer-events-none flex items-center gap-1.5"
    >
      {STYLE_ORDER.map((style) => {
        const Icon = STYLE_ICONS[style];
        return (
          <HoverLabel key={style} label={STYLE_LABELS[style]}>
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
              <Icon className="h-4 w-4" />
            </button>
          </HoverLabel>
        );
      })}

      <HoverLabel label="Find and replace">
        <button
          type="button"
          aria-label="Find and replace"
          aria-keyshortcuts={ariaKeyShortcuts(FIND_SHORTCUT, mac)}
          onClick={onFind}
          tabIndex={-1}
          className={CHIP}
        >
          <SearchIcon className="h-4 w-4" />
        </button>
      </HoverLabel>

      {translate && <TranslateMenu {...translate} />}
    </div>
  );
}

function TranslateMenu({
  status,
  targetLanguage,
  onTranslate,
  onUndo,
  canUndo,
}: ComposeTranslateProps) {
  const [open, setOpen] = useState(false);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const busy = status.kind === "working" || status.kind === "downloading";
  if (status.kind === "unavailable") return null;
  // "Translate" until a language has been picked: a guessed default
  // would put a language the user never asked for on the button.
  const label = busy
    ? "Translating..."
    : targetLanguage
      ? `Translate to ${languageLabel(targetLanguage)}`
      : "Translate";

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
          onClick={() => setOpen((v) => !v)}
          className={CHIP}
        >
          {busy ? (
            <LoaderCircleIcon className="h-4 w-4 animate-spin motion-reduce:animate-none" />
          ) : (
            <LanguagesIcon className="h-4 w-4" />
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
          <Command label="Translate the message to">
            <CommandInput placeholder="Search languages" autoFocus />
            <CommandList className="max-h-60">
              <CommandEmpty>No such language.</CommandEmpty>
              <CommandGroup heading="Translate the message to">
                {TRANSLATION_LANGUAGES.map((l) => (
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
                    Restore the original
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
