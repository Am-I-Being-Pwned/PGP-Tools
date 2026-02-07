import type { StorageLocation } from "../../lib/storage/preferences";

interface StorageLocationPickerProps {
  value: StorageLocation;
  onChange: (location: StorageLocation) => void;
  disabled?: boolean;
}

const OPTIONS: {
  id: StorageLocation;
  label: string;
  description: string;
}[] = [
  {
    id: "local",
    label: "This device only",
    description:
      "Your data stays on this computer. If you switch devices or reinstall, you'll need to set up again.",
  },
  {
    id: "sync",
    label: "Sync across devices",
    description:
      "Your data is synced via your Chrome account. Available anywhere you're signed in.",
  },
];

export function StorageLocationPicker({
  value,
  onChange,
  disabled,
}: StorageLocationPickerProps) {
  return (
    <div className="space-y-2">
      {OPTIONS.map((opt) => (
        <label
          key={opt.id}
          className={`flex cursor-pointer items-start gap-3 rounded-md border p-3 transition-colors ${
            value === opt.id
              ? "border-primary bg-primary/5"
              : "border-border hover:border-muted-foreground/50"
          } ${disabled ? "pointer-events-none opacity-60" : ""}`}
        >
          <input
            type="radio"
            name="storage-location"
            checked={value === opt.id}
            onChange={() => onChange(opt.id)}
            disabled={disabled}
            className="accent-primary mt-0.5"
          />
          <div>
            <p className="text-sm font-medium">{opt.label}</p>
            <p className="text-muted-foreground text-xs">{opt.description}</p>
          </div>
        </label>
      ))}
    </div>
  );
}
