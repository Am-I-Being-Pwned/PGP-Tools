import { useState } from "react";

import { Button } from "@amibeingpwned/ui/button";

import { INPUT_CLASS } from "../../lib/utils/styles";
import { SlideOverHeader, SlideOverPanel, useSlideOver } from "./SlideOver";

interface RenamePageProps {
  title: string;
  /** Field label above the input, e.g. "Display name". */
  fieldLabel: string;
  /** Current alias/label, empty string if unset. */
  initialValue: string;
  /** Shown muted under the field, e.g. the real key identity. */
  hint?: string;
  placeholder?: string;
  /** Persist the new name (already trimmed; "" means clear). Caller
   *  closes/unmounts after the slide-out. */
  onSave: (value: string) => void | Promise<void>;
  onCancel: () => void;
}

/**
 * Full-panel rename, using the shared slide-over pattern. Sets a local
 * display alias; submitting an empty value clears it (reverts to the
 * key's real identity).
 */
export function RenamePage({
  title,
  fieldLabel,
  initialValue,
  hint,
  placeholder,
  onSave,
  onCancel,
}: RenamePageProps) {
  const { entered, close } = useSlideOver(onCancel);
  const [value, setValue] = useState(initialValue);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const dirty = value.trim() !== initialValue.trim();

  const handleSave = async () => {
    setBusy(true);
    setError(null);
    try {
      await onSave(value.trim());
      close();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn't save the name.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <SlideOverPanel entered={entered} ariaLabel={title}>
      <SlideOverHeader title={title} onBack={close} />
      <div className="flex flex-1 flex-col overflow-y-auto p-4">
        <div className="space-y-3">
          <div>
            <label className="text-muted-foreground mb-1 block text-xs">
              {fieldLabel}
            </label>
            <input
              type="text"
              value={value}
              autoFocus
              placeholder={placeholder}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && dirty) void handleSave();
              }}
              className={INPUT_CLASS}
            />
            {hint && (
              <p className="text-muted-foreground mt-1 text-[11px]">{hint}</p>
            )}
          </div>
          {error && <p className="text-destructive text-xs">{error}</p>}
          {initialValue && (
            <button
              type="button"
              onClick={() => setValue("")}
              className="text-muted-foreground hover:text-foreground text-xs transition-colors"
            >
              Clear name
            </button>
          )}
        </div>
        <div className="mt-auto space-y-2 pt-4">
          <Button
            className="w-full"
            disabled={busy || !dirty}
            onClick={() => void handleSave()}
          >
            {busy ? "Saving..." : "Save"}
          </Button>
          <Button
            variant="outline"
            className="w-full"
            disabled={busy}
            onClick={close}
          >
            Cancel
          </Button>
        </div>
      </div>
    </SlideOverPanel>
  );
}
