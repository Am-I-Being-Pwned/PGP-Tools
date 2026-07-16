import { CheckIcon } from "lucide-react";

import type { PresetId } from "../../lib/presets";
import { describeBundle, PRESET_IDS, PRESETS } from "../../lib/presets";

/** Extra transparency line on the strictest preset's card: even it
 *  keeps encrypt-to-self on, and where to turn that off. */
const PARANOID_ENCRYPT_TO_SELF_NOTE =
  "Your messages stay readable by you - turn off 'Also encrypt to me' later if even that is a risk.";

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
 */
export function PresetPicker({
  selected,
  activeId,
  onSelect,
}: PresetPickerProps) {
  return (
    <div className="space-y-2" role="radiogroup" aria-label="Security preset">
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
            className={`w-full rounded-md border p-3 text-left transition-colors ${
              isSelected
                ? "border-primary bg-primary/5"
                : "border-border hover:border-muted-foreground/40"
            }`}
          >
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium">{preset.title}</span>
              {activeId === id && (
                <span className="bg-muted text-muted-foreground rounded px-1.5 py-0.5 text-[10px] font-medium">
                  Current
                </span>
              )}
              {preset.recommended && (
                <span className="bg-primary/10 text-primary rounded px-1.5 py-0.5 text-[10px] font-medium">
                  Recommended
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
              {id === "paranoid" && (
                <li className="flex items-start gap-1.5">
                  <CheckIcon className="mt-0.5 h-3 w-3 shrink-0" />
                  <span>{PARANOID_ENCRYPT_TO_SELF_NOTE}</span>
                </li>
              )}
            </ul>
          </button>
        );
      })}
    </div>
  );
}
