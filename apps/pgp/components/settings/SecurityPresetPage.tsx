import { useEffect, useState } from "react";

import type { PresetId } from "../../lib/presets";
import { t } from "../../lib/i18n";
import { PRESETS } from "../../lib/presets";
import { historyByteSize } from "../../lib/storage/history";
import { formatFileSize } from "../../lib/utils/formatting";
import { PresetPicker } from "../shared/PresetPicker";
import { SubPage } from "../shared/SubPage";

/** The term is found by string search so the message carries no markup. */
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
  /** null while preferences are loading. */
  currentPreset: PresetId | "custom" | null;
  onApply: (id: PresetId) => Promise<void>;
  onClose: () => void;
}

/** Overwriting a custom setup, or a never-cache preset deleting stored
 *  history, goes through an explicit confirm step first. */
export function SecurityPresetPage({
  currentPreset,
  onApply,
  onClose,
}: SecurityPresetPageProps) {
  const activeId =
    currentPreset !== null && currentPreset !== "custom" ? currentPreset : null;
  const [selected, setSelected] = useState<PresetId | null>(activeId);
  const [confirming, setConfirming] = useState(false);
  const [historyBytes, setHistoryBytes] = useState(0);
  useEffect(() => {
    void historyByteSize().then(setHistoryBytes);
  }, []);

  const isCustom = currentPreset === "custom";
  const applyDisabled = selected === null || selected === activeId;
  // Deleting history is destructive: confirm even from a non-custom state.
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
          <div className="rounded-xl bg-[#252012] p-3">
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
