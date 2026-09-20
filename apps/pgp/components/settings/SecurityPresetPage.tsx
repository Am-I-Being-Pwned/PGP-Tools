import { useEffect, useState } from "react";

import type { PresetId } from "../../lib/presets";
import { t } from "../../lib/i18n";
import { PRESETS } from "../../lib/presets";
import { historyByteSize } from "../../lib/storage/history";
import { formatFileSize } from "../../lib/utils/formatting";
import { PresetPicker } from "../shared/PresetPicker";
import { SubPage } from "../shared/SubPage";

/** A translated sentence with one substituted term rendered in bold.
 *  The term is found by string search so the message carries no markup
 *  and the translator can place it anywhere. */
function Bolded({ text, term }: { text: string; term: string }) {
  const at = term === "" ? -1 : text.indexOf(term);
  if (at === -1) return <>{text}</>;
  return (
    <>
      {text.slice(0, at)}
      <b>{term}</b>
      {text.slice(at + term.length)}
    </>
  );
}

interface SecurityPresetPageProps {
  /** Preset the saved preferences currently match, "custom" when none
   *  does, or null while preferences are still loading. */
  currentPreset: PresetId | "custom" | null;
  /** Persists the preset bundle (and runs any storage migration).
   *  Rejections surface in the SubPage footer; the page closes on
   *  success. */
  onApply: (id: PresetId) => Promise<void>;
  /** Called after the slide-out finishes; the parent unmounts the page. */
  onClose: () => void;
}

/**
 * Settings subpage for choosing a security preset: the three full
 * PresetPicker cards (with their describeBundle transparency lines),
 * the currently applied preset badged, and an Apply footer action.
 * Overwriting a custom setup swaps the footer into an explicit confirm
 * step first, as does applying a never-cache preset while stored
 * history exists (applying it deletes that history).
 */
export function SecurityPresetPage({
  currentPreset,
  onApply,
  onClose,
}: SecurityPresetPageProps) {
  const activeId =
    currentPreset !== null && currentPreset !== "custom" ? currentPreset : null;
  const [selected, setSelected] = useState<PresetId | null>(activeId);
  // Applying over a custom setup needs an explicit confirm; the footer
  // swaps into confirm mode instead of applying straight away.
  const [confirming, setConfirming] = useState(false);
  // Stored-history size, so a preset that enters never-cache (which
  // wipes history) can spell that cost out before applying.
  const [historyBytes, setHistoryBytes] = useState(0);
  useEffect(() => {
    void historyByteSize().then(setHistoryBytes);
  }, []);

  const isCustom = currentPreset === "custom";
  // Re-applying the preset you are already on is a no-op; keep the
  // button disabled until the choice would change something.
  const applyDisabled = selected === null || selected === activeId;
  // Applying this preset would delete stored history: it turns
  // never-cache on and history exists. That's destructive, so it goes
  // through the confirm step even from a non-custom state.
  const deletesHistory =
    selected !== null &&
    PRESETS[selected].bundle.neverCacheKeys === true &&
    historyBytes > 0;
  const needsConfirm = isCustom || deletesHistory;

  return (
    <SubPage
      title={t("settings_preset_title")}
      onClose={onClose}
      actions={
        confirming && selected !== null
          ? [
              {
                text: isCustom
                  ? t("settings_preset_replace_custom")
                  : t("settings_preset_apply_delete_history"),
                busyText: t("settings_preset_applying"),
                onClick: () => onApply(selected),
                closeOnSuccess: true,
              },
              {
                type: "outline",
                text: isCustom
                  ? t("settings_preset_keep_custom")
                  : t("common_cancel"),
                onClick: () => setConfirming(false),
              },
            ]
          : [
              {
                text: t("settings_preset_apply"),
                busyText: t("settings_preset_applying"),
                disabled: applyDisabled,
                onClick: () => {
                  if (selected === null) return;
                  if (needsConfirm) {
                    setConfirming(true);
                    return;
                  }
                  return onApply(selected);
                },
                closeOnSuccess: !needsConfirm,
              },
            ]
      }
    >
      <div className="space-y-3">
        <p className="text-muted-foreground text-xs">
          {t("settings_preset_intro")}
        </p>
        {isCustom && (
          <p className="text-muted-foreground text-xs">
            <Bolded
              text={t("settings_preset_custom_notice", {
                custom: t("settings_preset_custom_name"),
              })}
              term={t("settings_preset_custom_name")}
            />
          </p>
        )}
        <PresetPicker
          selected={selected}
          activeId={activeId}
          onSelect={(id) => {
            setSelected(id);
            setConfirming(false);
          }}
        />
        {confirming && selected !== null && (
          <div className="border-border bg-muted/40 rounded-md border p-3">
            {isCustom && (
              <p className="text-xs">
                <Bolded
                  text={t("settings_preset_confirm_replace", {
                    preset: PRESETS[selected].title,
                  })}
                  term={PRESETS[selected].title}
                />
              </p>
            )}
            {deletesHistory && (
              <p className={isCustom ? "mt-2 text-xs" : "text-xs"}>
                {t("settings_preset_confirm_history", {
                  size: formatFileSize(historyBytes),
                })}
              </p>
            )}
          </div>
        )}
      </div>
    </SubPage>
  );
}
