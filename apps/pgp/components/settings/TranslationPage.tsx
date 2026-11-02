import { useCallback, useEffect, useState } from "react";
import { CheckIcon, DownloadIcon } from "lucide-react";

import { BlockLabel } from "@amibeingpwned/ui/block";
import { Button } from "@amibeingpwned/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@amibeingpwned/ui/select";
import { SwitchRow } from "@amibeingpwned/ui/switch-row";

import {
  LANGUAGE_PACK_SIZE_HINT,
  translationAvailability,
  translationSupportedHere,
} from "../../lib/ai/availability";
import {
  TRANSLATION_LANGUAGES,
  translationLanguages,
} from "../../lib/ai/languages";
import { downloadLanguagePack } from "../../lib/ai/translate";
import { t } from "../../lib/i18n";
import { SubPage } from "../shared/SubPage";

/**
 * Pre-download language packs. On-demand install is observable off-device
 * and ties the pack to the message just decrypted; fetching here,
 * unprompted, breaks that correlation. See T-AI-TRANSLATE-METADATA.
 */

interface TranslationPageProps {
  onClose: () => void;
  enabled: boolean;
  onEnabledChange: (v: boolean) => void;
  targetLanguage: string;
  onTargetLanguageChange: (code: string) => void;
}

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
  // `| undefined`: rows render before the availability sweep resolves.
  const [packs, setPacks] = useState<Record<string, PackState | undefined>>({});

  useEffect(() => {
    void translationSupportedHere().then(setSupported);
  }, []);

  // Re-read on target change: readiness is per direction.
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
            message:
              e instanceof Error
                ? e.message
                : t("settings_translation_download_failed"),
          },
        }));
      }
    },
    [targetLanguage],
  );

  return (
    <SubPage title={t("settings_translation_title")} onClose={onClose}>
      <div className="space-y-4">
        <SwitchRow
          className="rounded-xl"
          title={t("settings_translation_enable")}
          description={t("settings_translation_enable_desc")}
          checked={enabled}
          onCheckedChange={onEnabledChange}
          disabled={supported === false}
        />

        {supported === false && (
          <p className="text-muted-foreground px-1 text-xs">
            {t("settings_translation_unsupported")}
          </p>
        )}

        {supported && (
          <>
            <div className="space-y-1.5">
              <BlockLabel as="p">{t("settings_translation_target")}</BlockLabel>
              <Select
                value={targetLanguage}
                onValueChange={onTargetLanguageChange}
              >
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {translationLanguages().map((l) => (
                    <SelectItem key={l.code} value={l.code}>
                      {l.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <BlockLabel as="p">{t("settings_translation_packs")}</BlockLabel>
              <p className="text-muted-foreground px-1 text-xs">
                {t("settings_translation_packs_desc", {
                  size: LANGUAGE_PACK_SIZE_HINT,
                })}
              </p>

              <ul className="flex flex-col gap-0.5 overflow-hidden rounded-xl">
                {translationLanguages()
                  .filter((l) => l.code !== targetLanguage)
                  .map((l) => {
                    const state = packs[l.code];
                    return (
                      <li
                        key={l.code}
                        className="bg-card flex min-h-11 items-center justify-between gap-3 rounded-[3px] px-3.5 py-2"
                      >
                        <span className="text-sm">{l.label}</span>
                        {state?.kind === "ready" && (
                          <span className="text-good flex items-center gap-1 text-xs">
                            <CheckIcon className="h-3.5 w-3.5" />
                            {t("settings_translation_pack_ready")}
                          </span>
                        )}
                        {state?.kind === "downloading" && (
                          <span className="text-muted-foreground text-xs">
                            {t("settings_translation_pack_progress", {
                              percent: Math.round(state.progress * 100),
                            })}
                          </span>
                        )}
                        {state?.kind === "downloadable" && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => void download(l.code)}
                          >
                            <DownloadIcon className="h-3.5 w-3.5" />
                            {t("common_download")}
                          </Button>
                        )}
                        {state?.kind === "unsupported" && (
                          <span className="text-muted-foreground text-xs">
                            {t("settings_translation_pack_not_offered")}
                          </span>
                        )}
                        {state?.kind === "error" && (
                          <span className="text-bad text-xs">
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
