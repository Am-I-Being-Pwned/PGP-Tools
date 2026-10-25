import { CheckIcon } from "lucide-react";

import { BlockStack } from "@amibeingpwned/ui/block";

import type { PresetId } from "../../lib/presets";
import { t } from "../../lib/i18n";
import { describeBundle, PRESET_IDS, PRESETS } from "../../lib/presets";

interface PresetPickerProps {
  /** Currently selected preset, or null when none is. */
  selected: PresetId | null;
  /** Preset the user's settings currently match, marked with a
   *  "Current" badge so pickers can distinguish "you are ON this" from
   *  the tentative selection. Omit where there is no applied preset yet
   *  (onboarding). */
  activeId?: PresetId | null;
  onSelect: (id: PresetId) => void;
}

/**
 * Radio-style cards for the three security presets, each listing
 * exactly what its bundle sets (via describeBundle). Used by both the
 * onboarding preset step and the settings security-preset subpage.
 *
 * Drawn as one block stack, a block per preset; the chosen one takes
 * the "on" tint. Too much per option (tagline plus the bundle lines)
 * for a one-line option bar, so it stays a stack of radio cards.
 */
export function PresetPicker({
  selected,
  activeId,
  onSelect,
}: PresetPickerProps) {
  return (
    <BlockStack role="radiogroup" aria-label={t("shared_security_preset")}>
      {PRESET_IDS.map((id) => {
        const preset = PRESETS[id];
        const isSelected = selected === id;
        return (
          <button
            key={id}
            type="button"
            role="radio"
            aria-checked={isSelected}
            onClick={() => onSelect(id)}
            className={`focus-visible:ring-ring/50 w-full rounded-[3px] px-3.5 py-3 text-left transition-colors focus-visible:ring-2 focus-visible:outline-none focus-visible:ring-inset ${
              isSelected ? "bg-on" : "bg-card hover:bg-accent"
            }`}
          >
            <div className="flex items-center gap-2">
              <span
                className={`text-sm font-medium ${isSelected ? "text-on-foreground" : ""}`}
              >
                {preset.title}
              </span>
              {activeId === id && (
                <span className="bg-secondary text-muted-foreground rounded px-1.5 py-px text-[10.5px] font-medium">
                  {t("shared_preset_current")}
                </span>
              )}
              {preset.recommended && (
                <span className="bg-good/12 text-good rounded px-1.5 py-px text-[10.5px] font-medium">
                  {t("shared_preset_recommended")}
                </span>
              )}
            </div>
            <p className="text-muted-foreground mt-0.5 text-xs">
              {preset.tagline}
            </p>
            <ul className="text-muted-foreground mt-2 space-y-1 text-xs">
              {describeBundle(preset.bundle).map((line) => (
                <li key={line} className="flex items-start gap-1.5">
                  <CheckIcon className="mt-0.5 h-3 w-3 shrink-0" />
                  <span>{line}</span>
                </li>
              ))}
              {/* Extra transparency line on the strictest preset's card:
                  even it keeps encrypt-to-self on, and where to turn that
                  off. */}
              {id === "paranoid" && (
                <li className="flex items-start gap-1.5">
                  <CheckIcon className="mt-0.5 h-3 w-3 shrink-0" />
                  <span>{t("shared_preset_paranoid_note")}</span>
                </li>
              )}
            </ul>
          </button>
        );
      })}
    </BlockStack>
  );
}
