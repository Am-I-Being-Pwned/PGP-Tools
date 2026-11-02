import { LanguagesIcon, LoaderCircleIcon } from "lucide-react";

import { HoverHint } from "~/components/shared/HoverHint";
import type { TranslationStatus } from "~/hooks/useTranslation";
import { languageLabel } from "~/lib/ai/languages";
import { t } from "~/lib/i18n";

/**
 * Status line + translate toggle in the result box's footer. Kept small:
 * language detection is deliberately not eager (T-AI-PLAINTEXT-DISCLOSURE),
 * so we can't know in advance whether translation is even wanted.
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

export function TranslateToggle({
  status,
  showing,
  hasTranslation,
  onTranslate,
  onToggle,
  targetLanguage,
}: TranslateToggleProps) {
  const busy = status.kind === "working" || status.kind === "downloading";

  if (status.kind === "unavailable" || status.kind === "same-language") {
    return null;
  }

  const label = hasTranslation
    ? showing
      ? t("workspace_show_original")
      : t("workspace_show_translation", {
          language: languageLabel(targetLanguage),
        })
    : t("workspace_translate_to", { language: languageLabel(targetLanguage) });

  return (
    <HoverHint align="end" label={busy ? t("workspace_working") : label}>
      <button
        type="button"
        aria-label={label}
        disabled={busy}
        onClick={hasTranslation ? onToggle : onTranslate}
        className={`surface-float hover:text-foreground pointer-events-auto shrink-0 rounded-lg p-2 transition-colors disabled:opacity-60 ${
          showing ? "text-on-foreground bg-on" : "text-muted-foreground"
        }`}
      >
        {busy ? (
          <LoaderCircleIcon className="h-4 w-4 animate-spin motion-reduce:animate-none" />
        ) : (
          <LanguagesIcon className="h-4 w-4" />
        )}
      </button>
    </HoverHint>
  );
}

/** Status chip beside the button; renders nothing for states the button already shows. */
export function TranslationNote({
  status,
  showing,
}: {
  status: TranslationStatus;
  showing: boolean;
}) {
  let text: string | null;

  switch (status.kind) {
    case "same-language":
      text = t("workspace_note_same_language", {
        language: languageLabel(status.language),
      });
      break;
    case "uncertain":
      text = t("workspace_note_uncertain");
      break;
    case "downloading":
      // The one network touch: say what is being fetched, not just a spinner.
      text =
        status.progress > 0
          ? t("workspace_note_downloading_progress", {
              what: status.what,
              percent: Math.round(status.progress * 100),
            })
          : t("workspace_note_downloading", { what: status.what });
      break;
    case "error":
      text = status.message;
      break;
    case "done":
      // Only while the translation is on screen; the original must not claim it.
      text = showing
        ? t("workspace_note_translated_from", {
            language: languageLabel(status.from),
          })
        : null;
      break;
    default:
      text = null;
  }

  if (!text) return null;
  // `truncate` catches Chrome error messages of unknown length.
  return (
    <p
      className="surface-float text-muted-foreground min-w-0 truncate rounded-lg px-2 py-1 text-xs"
      title={text}
    >
      {text}
    </p>
  );
}
