import { useEffect, useState } from "react";

import type { PresetId } from "../../lib/presets";
import { PRESETS } from "../../lib/presets";
import { historyByteSize } from "../../lib/storage/history";
import { formatFileSize } from "../../lib/utils/formatting";
import { PresetPicker } from "../shared/PresetPicker";
import { SubPage } from "../shared/SubPage";

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
      title="Security preset"
      onClose={onClose}
      actions={
        confirming && selected !== null
          ? [
              {
                text: isCustom
                  ? "Replace custom settings"
                  : "Apply and delete history",
                busyText: "Applying...",
                onClick: () => onApply(selected),
                closeOnSuccess: true,
              },
              {
                type: "outline",
                text: isCustom ? "Keep custom settings" : "Cancel",
                onClick: () => setConfirming(false),
              },
            ]
          : [
              {
                text: "Apply preset",
                busyText: "Applying...",
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
          Each preset bundles the security settings for one threat model, and
          its card lists exactly what it sets. Applying one only changes those
          settings, and you can adjust any of them again afterwards.
        </p>
        {isCustom && (
          <p className="text-muted-foreground text-xs">
            You are on <b>Custom</b>: a bundled setting was changed, so no
            preset matches exactly.
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
                Replace your custom settings with the{" "}
                <b>{PRESETS[selected].title}</b> preset? Only the settings
                listed on its card change, and you can adjust any of them again
                afterwards.
              </p>
            )}
            {deletesHistory && (
              <p className={isCustom ? "mt-2 text-xs" : "text-xs"}>
                This preset turns on never-cache, which also deletes your saved
                history ({formatFileSize(historyBytes)}). It can't be recovered.
              </p>
            )}
          </div>
        )}
      </div>
    </SubPage>
  );
}
