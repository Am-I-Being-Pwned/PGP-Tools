import { useState } from "react";

import type { PresetId } from "../../lib/presets";
import { PRESETS } from "../../lib/presets";
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
 * step first.
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

  const isCustom = currentPreset === "custom";
  // Re-applying the preset you are already on is a no-op; keep the
  // button disabled until the choice would change something.
  const applyDisabled = selected === null || selected === activeId;

  return (
    <SubPage
      title="Security preset"
      onClose={onClose}
      actions={
        confirming && selected !== null
          ? [
              {
                text: "Replace custom settings",
                busyText: "Applying...",
                onClick: () => onApply(selected),
                closeOnSuccess: true,
              },
              {
                type: "outline",
                text: "Keep custom settings",
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
                  if (isCustom) {
                    setConfirming(true);
                    return;
                  }
                  return onApply(selected);
                },
                closeOnSuccess: !isCustom,
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
            <p className="text-xs">
              Replace your custom settings with the{" "}
              <b>{PRESETS[selected].title}</b> preset? Only the settings listed
              on its card change, and you can adjust any of them again
              afterwards.
            </p>
          </div>
        )}
      </div>
    </SubPage>
  );
}
