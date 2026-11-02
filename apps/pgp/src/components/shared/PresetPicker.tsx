import { CheckIcon } from "lucide-react";

import { BlockStack } from "@amibeingpwned/ui";

import { t } from "~/lib/i18n";
import {
  describeBundle,
  PRESET_IDS,
  PRESETS,
  type PresetId,
} from "~/lib/presets";

interface PresetPickerProps {
  selected: PresetId | null;
  /** Gets a "Current" badge, distinct from the tentative selection. */
  activeId?: PresetId | null;
  onSelect: (id: PresetId) => void;
}

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
