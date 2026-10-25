import { BlockStack } from "@amibeingpwned/ui/block";

import type { MessageKey } from "../../lib/i18n";
import type { StorageLocation } from "../../lib/storage/preferences";
import { t } from "../../lib/i18n";

interface StorageLocationPickerProps {
  value: StorageLocation;
  onChange: (location: StorageLocation) => void;
  /** Blocks interaction while a migration is in flight. Intentionally has
   *  no visual treatment -- the move is near-instant and a flash of
   *  dimming/spinner reads as jank. */
  disabled?: boolean;
}

const OPTIONS: {
  id: StorageLocation;
  label: MessageKey;
  description: MessageKey;
}[] = [
  {
    id: "local",
    label: "shared_storage_local_label",
    description: "shared_storage_local_desc",
  },
  {
    id: "sync",
    label: "shared_storage_sync_label",
    description: "shared_storage_sync_desc",
  },
];

/** Two radio rows in one block stack; the chosen one takes the "on" tint. */
export function StorageLocationPicker({
  value,
  onChange,
  disabled,
}: StorageLocationPickerProps) {
  return (
    <BlockStack>
      {OPTIONS.map((opt) => (
        <label
          key={opt.id}
          className={`flex cursor-pointer items-center justify-between gap-4 rounded-[3px] px-3.5 py-3 transition-colors ${
            value === opt.id ? "bg-on" : "bg-card hover:bg-accent"
          } ${disabled ? "pointer-events-none" : ""}`}
        >
          <div>
            <p
              className={`text-sm font-medium ${value === opt.id ? "text-on-foreground" : ""}`}
            >
              {t(opt.label)}
            </p>
            <p className="text-muted-foreground text-xs">
              {t(opt.description)}
            </p>
          </div>
          <input
            type="radio"
            name="storage-location"
            checked={value === opt.id}
            onChange={() => onChange(opt.id)}
            disabled={disabled}
            className="accent-primary shrink-0"
          />
        </label>
      ))}
    </BlockStack>
  );
}
