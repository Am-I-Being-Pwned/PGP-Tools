import { useState } from "react";
import { LanguagesIcon, LoaderCircleIcon } from "lucide-react";

import {
  Popover,
  PopoverAnchor,
  PopoverContent,
} from "@amibeingpwned/ui/popover";

import type { TranslationStatus } from "../../hooks/useTranslation";
import { languageLabel } from "../../lib/ai/languages";

/**
 * The two halves of the result box's footer bar: a status line and the
 * translate toggle.
 *
 * They live in the box's own chrome rather than under it for two
 * reasons. The control is mostly noise -- a decrypted message is usually
 * already in a language the reader speaks, and we cannot know that in
 * advance without a model reading it first (T-AI-PLAINTEXT-DISCLOSURE:
 * detection is deliberately not eager), so a full-width button would
 * shout about something rarely wanted. And the status text has to be
 * able to appear and clear without resizing the message above it, which
 * a bar that is always present gives for free.
 *
 * Once a translation exists the same button toggles between it and the
 * original, so the message can always be checked against the model's
 * version.
 */

interface TranslateToggleProps {
  status: TranslationStatus;
  /** True while the box is showing the translation. */
  showing: boolean;
  hasTranslation: boolean;
  onTranslate: () => void;
  onToggle: () => void;
  targetLanguage: string;
}

/** Hover/focus label, matching `ShortcutHint`'s pattern in WorkspaceView
 *  (the UI kit has no tooltip, so a Popover anchored to the trigger is
 *  the house idiom). */
function HoverLabel({
  label,
  children,
}: {
  label: string;
  children: React.ReactElement;
}) {
  const [open, setOpen] = useState(false);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverAnchor
        asChild
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
      >
        {children}
      </PopoverAnchor>
      <PopoverContent
        side="top"
        align="end"
        className="pointer-events-none w-auto px-2 py-1.5 text-xs"
        onOpenAutoFocus={(e) => e.preventDefault()}
      >
        {label}
      </PopoverContent>
    </Popover>
  );
}

export function TranslateToggle({
  status,
  showing,
  hasTranslation,
  onTranslate,
  onToggle,
  targetLanguage,
}: TranslateToggleProps) {
  const busy = status.kind === "working" || status.kind === "downloading";

  // Nothing to offer on a device without the models, and nothing to
  // offer for a message we already know is in the target language --
  // once the press has told us that, re-offering it is just wrong.
  if (status.kind === "unavailable" || status.kind === "same-language") {
    return null;
  }

  const label = hasTranslation
    ? showing
      ? "Show original"
      : `Show ${languageLabel(targetLanguage)} translation`
    : `Translate to ${languageLabel(targetLanguage)}`;

  return (
    <HoverLabel label={busy ? "Working..." : label}>
      <button
        type="button"
        aria-label={label}
        disabled={busy}
        onClick={hasTranslation ? onToggle : onTranslate}
        className={`border-border bg-background/90 hover:border-muted-foreground/40 hover:text-foreground pointer-events-auto shrink-0 rounded-md border p-2 shadow-sm backdrop-blur transition-colors disabled:opacity-60 ${
          showing
            ? "text-foreground border-muted-foreground/40"
            : "text-muted-foreground"
        }`}
      >
        {busy ? (
          <LoaderCircleIcon className="h-4 w-4 animate-spin motion-reduce:animate-none" />
        ) : (
          <LanguagesIcon className="h-4 w-4" />
        )}
      </button>
    </HoverLabel>
  );
}

/**
 * The status chip that floats beside the button. Renders nothing at all
 * for the states the button already communicates, so the idle box shows
 * a single icon and no chrome. It carries its own background because it
 * sits over the message text rather than in a bar of its own.
 */
export function TranslationNote({
  status,
  showing,
}: {
  status: TranslationStatus;
  showing: boolean;
}) {
  let text: string | null = null;

  switch (status.kind) {
    case "same-language":
      text = `This message is already in ${languageLabel(status.language)}.`;
      break;
    case "uncertain":
      text = "Not sure what language this message is in.";
      break;
    case "downloading":
      // Named and progress-bearing on purpose: this is the one moment
      // the feature touches the network, so it says what it is fetching
      // rather than hiding behind a spinner. Kept terse because the bar
      // is one line high and truncates.
      text =
        status.progress > 0
          ? `Downloading ${status.what}, ${Math.round(status.progress * 100)}%`
          : `Downloading ${status.what}...`;
      break;
    case "error":
      text = status.message;
      break;
    case "done":
      // Provenance, and only while the translation is the thing being
      // read. Flipping back to the original must not keep claiming the
      // text on screen was translated.
      text = showing
        ? `Translated on this device from ${languageLabel(status.from)}.`
        : null;
      break;
    default:
      text = null;
  }

  if (!text) return null;
  // `truncate` keeps this one line high whatever it holds. Every string
  // above is written to fit; this only catches an error message from
  // Chrome, whose length we do not control.
  return (
    <p
      className="text-muted-foreground border-border bg-background/90 min-w-0 truncate rounded-md border px-2 py-1 text-xs shadow-sm backdrop-blur"
      title={text}
    >
      {text}
    </p>
  );
}
