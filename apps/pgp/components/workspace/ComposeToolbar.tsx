import { useEffect, useRef, useState } from "react";
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

/** How close (px, from the strip's edge) the pointer has to come before
 *  the strip fades back in. Far enough that it is showing by the time
 *  the pointer lands on a chip, near enough that writing in the rest of
 *  the box leaves it hidden. */
const REVEAL_DISTANCE = 72;

/**
 * Whether the pointer is within `REVEAL_DISTANCE` of `ref`'s box.
 * Tracked on the document rather than the message box so approaching
 * from below or beside the box counts too; one rect read per frame at
 * most, and a state change only when the answer flips.
 */
function usePointerNear(ref: React.RefObject<HTMLElement | null>): boolean {
  const [near, setNear] = useState(false);
  useEffect(() => {
    let frame = 0;
    let x = 0;
    let y = 0;
    const check = () => {
      frame = 0;
      const el = ref.current;
      if (!el) return;
      const r = el.getBoundingClientRect();
      const dx = Math.max(r.left - x, 0, x - r.right);
      const dy = Math.max(r.top - y, 0, y - r.bottom);
      setNear(Math.hypot(dx, dy) <= REVEAL_DISTANCE);
    };
    const onMove = (e: PointerEvent) => {
      x = e.clientX;
      y = e.clientY;
      if (!frame) frame = requestAnimationFrame(check);
    };
    // Leaving the panel altogether hides it, rather than freezing it at
    // whatever the last in-panel position said.
    const onLeave = () => setNear(false);
    document.addEventListener("pointermove", onMove, { passive: true });
    document.documentElement.addEventListener("pointerleave", onLeave);
    return () => {
      document.removeEventListener("pointermove", onMove);
      document.documentElement.removeEventListener("pointerleave", onLeave);
      if (frame) cancelAnimationFrame(frame);
    };
  }, [ref]);
  return near;
}

/** One button in the strip: borderless, a soft fill on hover, the
 *  strip itself carries the border and the translucent background. */
const CHIP =
  "text-muted-foreground hover:text-foreground hover:bg-border/70 pointer-events-auto flex h-7 w-7 shrink-0 items-center justify-center rounded transition-colors disabled:opacity-60";

/**
 * Editing controls floating in the bottom-right corner of the message
 * box: inline formatting, find, and translate-before-sending. Icon-only
 * with hover labels, mirroring the translate toggle on the result box;
 * `pointer-events-none` on the strip (set by the parent) keeps it from
 * eating selection drags, and each chip re-enables them for itself.
 *
 * Faded out while it is not in use, so it doesn't sit over the words
 * being written; it comes back as the pointer nears the corner, and
 * stays while its language menu is open or a translation is running.
 * Only opacity changes: the chips stay clickable and in the
 * accessibility tree (and the shortcuts cover them anyway), and on a
 * device with no hover it never fades at all.
 */
export function ComposeToolbar({
  onStyle,
  onFind,
  translate,
}: ComposeToolbarProps) {
  const mac = isMacPlatform();
  const stripRef = useRef<HTMLDivElement>(null);
  const near = usePointerNear(stripRef);
  const [menuOpen, setMenuOpen] = useState(false);
  const translating =
    translate?.status.kind === "working" ||
    translate?.status.kind === "downloading";
  const shown = near || menuOpen || translating;
  return (
    <div
      ref={stripRef}
      role="toolbar"
      aria-label={t("workspace_message_tools")}
      data-shown={shown}
      // In quickly; out slowly and after a beat, so skimming past the
      // corner doesn't make it flicker.
      className={`border-border bg-background/90 pointer-events-auto flex items-center gap-0.5 rounded-md border p-0.5 shadow-sm backdrop-blur transition-opacity ease-out focus-within:opacity-100 hover:opacity-100 motion-reduce:transition-none [@media(hover:none)]:opacity-100 ${
        shown ? "opacity-100 duration-150" : "opacity-0 delay-300 duration-300"
      }`}
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

      <span aria-hidden className="bg-border mx-0.5 h-4 w-px" />

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
  /** Owned by the strip, which stays visible while the menu is open. */
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
