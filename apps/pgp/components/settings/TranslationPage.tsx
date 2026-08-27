import { useCallback, useEffect, useState } from "react";
import { CheckIcon, DownloadIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@amibeingpwned/ui/select";
import { Switch } from "@amibeingpwned/ui/switch";

import {
  LANGUAGE_PACK_SIZE_HINT,
  translationAvailability,
  translationSupportedHere,
} from "../../lib/ai/availability";
import { TRANSLATION_LANGUAGES } from "../../lib/ai/languages";
import { downloadLanguagePack } from "../../lib/ai/translate";
import { SubPage } from "../shared/SubPage";

/**
 * Where language packs can be downloaded AHEAD of needing them.
 *
 * No longer the only place that fetches one -- a missing pack now
 * installs itself on the first Translate press, because the alternative
 * was a button that never worked on a fresh profile (see the header of
 * lib/ai/translate.ts). What this page is still for is the property that
 * on-demand install gives up: a pack download is observable off-device,
 * so fetching one at the moment a message is decrypted ties "a pack for
 * Russian was fetched" to "this user just decrypted a Russian message".
 * Pre-downloading here, unprompted by any particular message, breaks that
 * correlation. Users who care keep the original guarantee by coming here
 * first, which is why the copy below says so plainly rather than selling
 * this as a convenience. See T-AI-TRANSLATE-METADATA.
 */

interface TranslationPageProps {
  onClose: () => void;
  enabled: boolean;
  onEnabledChange: (v: boolean) => void;
  targetLanguage: string;
  onTargetLanguageChange: (code: string) => void;
}

/** Per-row download state. Absent means "not checked yet". */
type PackState =
  | { kind: "ready" }
  | { kind: "downloadable" }
  | { kind: "downloading"; progress: number }
  | { kind: "unsupported" }
  | { kind: "error"; message: string };

export function TranslationPage({
  onClose,
  enabled,
  onEnabledChange,
  targetLanguage,
  onTargetLanguageChange,
}: TranslationPageProps) {
  const [supported, setSupported] = useState<boolean | null>(null);
  // Explicitly `| undefined` per key: rows render before the first
  // availability sweep resolves, so a lookup genuinely can miss. The
  // repo runs with `noUncheckedIndexedAccess: false`, which would
  // otherwise type these as always-present and make the `state?.` guards
  // below look redundant to the linter while still being needed at
  // runtime.
  const [packs, setPacks] = useState<Record<string, PackState | undefined>>({});

  useEffect(() => {
    void translationSupportedHere().then(setSupported);
  }, []);

  // Every language except the target is a potential source. Re-read on
  // target change, since readiness is per DIRECTION rather than per
  // language.
  const refresh = useCallback(async () => {
    if (!(await translationSupportedHere())) return;
    const next: Record<string, PackState> = {};
    for (const lang of TRANSLATION_LANGUAGES) {
      if (lang.code === targetLanguage) continue;
      const state = await translationAvailability({
        sourceLanguage: lang.code,
        targetLanguage,
      });
      next[lang.code] =
        state === "available"
          ? { kind: "ready" }
          : state === "unavailable"
            ? { kind: "unsupported" }
            : { kind: "downloadable" };
    }
    setPacks(next);
  }, [targetLanguage]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const download = useCallback(
    async (code: string) => {
      setPacks((p) => ({ ...p, [code]: { kind: "downloading", progress: 0 } }));
      try {
        await downloadLanguagePack(
          { sourceLanguage: code, targetLanguage },
          (loaded) =>
            setPacks((p) => ({
              ...p,
              [code]: { kind: "downloading", progress: loaded },
            })),
        );
        setPacks((p) => ({ ...p, [code]: { kind: "ready" } }));
      } catch (e) {
        setPacks((p) => ({
          ...p,
          [code]: {
            kind: "error",
            message: e instanceof Error ? e.message : "Download failed.",
          },
        }));
      }
    },
    [targetLanguage],
  );

  return (
    <SubPage title="Translation" onClose={onClose}>
      <div className="space-y-5">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            <p className="text-sm font-medium">Translate decrypted messages</p>
            <p className="text-muted-foreground text-xs">
              Adds a Translate button under a decrypted message. Translation
              runs on this device using Chrome's built-in model, and nothing is
              translated until you press the button.
            </p>
          </div>
          <Switch
            aria-label="Translate decrypted messages"
            checked={enabled}
            onCheckedChange={onEnabledChange}
            disabled={supported === false}
          />
        </div>

        {supported === false && (
          <p className="text-muted-foreground text-xs">
            Chrome's on-device translation is not available here. It needs a
            desktop Chrome on Windows 10+, macOS 13+, Linux or a Chromebook
            Plus, with enough free disk space and memory for the models.
          </p>
        )}

        {supported && (
          <>
            <div className="space-y-2">
              <p className="text-sm font-medium">Translate into</p>
              <Select
                value={targetLanguage}
                onValueChange={onTargetLanguageChange}
              >
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {TRANSLATION_LANGUAGES.map((l) => (
                    <SelectItem key={l.code} value={l.code}>
                      {l.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <p className="text-sm font-medium">Language packs</p>
              <p className="text-muted-foreground text-xs">
                Optional. A missing pack downloads by itself the first time you
                translate from that language, so you only need this to get ahead
                of it. Downloading here does buy you one thing: the download no
                longer happens at the moment you decrypt a message, so its
                timing reveals nothing about what you just read. Each pack is{" "}
                {LANGUAGE_PACK_SIZE_HINT} and is stored by Chrome, not by this
                extension.
              </p>

              <ul className="divide-border divide-y">
                {TRANSLATION_LANGUAGES.filter(
                  (l) => l.code !== targetLanguage,
                ).map((l) => {
                  const state = packs[l.code];
                  return (
                    <li
                      key={l.code}
                      className="flex items-center justify-between gap-3 py-2"
                    >
                      <span className="text-sm">{l.label}</span>
                      {state?.kind === "ready" && (
                        <span className="flex items-center gap-1 text-xs text-green-400">
                          <CheckIcon className="h-3.5 w-3.5" />
                          Ready
                        </span>
                      )}
                      {state?.kind === "downloading" && (
                        <span className="text-muted-foreground text-xs">
                          {Math.round(state.progress * 100)}%
                        </span>
                      )}
                      {state?.kind === "downloadable" && (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => void download(l.code)}
                        >
                          <DownloadIcon className="h-3.5 w-3.5" />
                          Download
                        </Button>
                      )}
                      {state?.kind === "unsupported" && (
                        <span className="text-muted-foreground text-xs">
                          Not offered
                        </span>
                      )}
                      {state?.kind === "error" && (
                        <span className="text-destructive text-xs">
                          {state.message}
                        </span>
                      )}
                    </li>
                  );
                })}
              </ul>
            </div>
          </>
        )}
      </div>
    </SubPage>
  );
}
