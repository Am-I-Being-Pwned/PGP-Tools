import { useCallback } from "react";
import { LanguagesIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import type { TranslationStatus } from "../../hooks/useTranslation";
import { languageLabel } from "../../lib/ai/languages";

/**
 * The translate control under a decrypted message, and the translation
 * itself when there is one.
 *
 * Like `OutputArea`, the translated text is written to the node
 * imperatively and never rendered as a React child: it is a second copy
 * of the decrypted plaintext, so it lives under the same rule (see the
 * translation block in `useWorkspaceState`).
 */

interface TranslationPanelProps {
  status: TranslationStatus;
  onTranslate: () => void;
  onDismiss: () => void;
  /** Routes to Settings, where a language pack may be downloaded. */
  onOpenSettings?: () => void;
  translationElRef: React.MutableRefObject<HTMLPreElement | null>;
  getTranslation: () => string;
  hasTranslation: boolean;
  targetLanguage: string;
}

/** The one-line explanation under the button for every non-happy path.
 *  Returns null where the UI speaks for itself (idle, working, done). */
function statusNote(status: TranslationStatus): string | null {
  switch (status.kind) {
    case "same-language":
      return `This message is already in ${languageLabel(status.language)}.`;
    case "uncertain":
      return "Could not identify the language of this message with enough confidence to translate it.";
    case "downloading":
      // Named and progress-bearing on purpose. This is the one moment
      // the feature touches the network, so it says what it is fetching
      // rather than hiding behind a generic spinner.
      return status.progress > 0
        ? `Downloading the ${status.what} model, ${Math.round(status.progress * 100)}%. One time only.`
        : `Downloading the ${status.what} model. One time only.`;
    case "unavailable":
      return "On-device translation is not available on this device.";
    case "error":
      return status.message;
    default:
      return null;
  }
}

export function TranslationPanel({
  status,
  onTranslate,
  onDismiss,
  onOpenSettings,
  translationElRef,
  getTranslation,
  hasTranslation,
  targetLanguage,
}: TranslationPanelProps) {
  // Callback ref, same contract as `OutputArea.attachOutput`: publish the
  // node and re-seed it from the ref, because an imperatively-written
  // node comes back empty after any unmount.
  const attachTranslation = useCallback(
    (el: HTMLPreElement | null) => {
      translationElRef.current = el;
      if (el) el.textContent = getTranslation();
    },
    [translationElRef, getTranslation],
  );

  const note = statusNote(status);
  // A download is part of the same press, so the button stays busy
  // through it rather than appearing idle while bytes are moving.
  const working = status.kind === "working" || status.kind === "downloading";

  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3">
        {hasTranslation ? (
          <button
            type="button"
            className="text-muted-foreground text-xs underline underline-offset-2"
            onClick={onDismiss}
          >
            Hide translation
          </button>
        ) : (
          <Button
            variant="outline"
            size="sm"
            disabled={working}
            onClick={onTranslate}
          >
            <LanguagesIcon className="h-3.5 w-3.5" />
            {status.kind === "downloading"
              ? "Preparing..."
              : working
                ? "Translating..."
                : `Translate to ${languageLabel(targetLanguage)}`}
          </Button>
        )}

        {status.kind === "error" && onOpenSettings && (
          <button
            type="button"
            className="text-xs font-medium underline underline-offset-2"
            onClick={onOpenSettings}
          >
            Manage language packs
          </button>
        )}
      </div>

      {note && <p className="text-muted-foreground text-xs">{note}</p>}

      {hasTranslation && (
        <div className="space-y-1">
          <p className="text-muted-foreground text-xs">
            {status.kind === "done"
              ? `Translated on this device from ${languageLabel(status.from)}.`
              : "Translated on this device."}
          </p>
          {/* No React children on purpose -- see attachTranslation. */}
          <pre
            ref={attachTranslation}
            tabIndex={0}
            className="bg-muted/50 border-border max-h-64 overflow-auto rounded-md border p-3 font-mono text-xs break-all whitespace-pre-wrap focus:outline-none"
          />
        </div>
      )}
    </div>
  );
}
