import { useState } from "react";

import { INPUT_CLASS } from "../../lib/utils/styles";
import { SubPage } from "./SubPage";

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
 * Full-panel rename subpage. Sets a local display alias; submitting an
 * empty value clears it (reverts to the key's real identity).
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
  const [value, setValue] = useState(initialValue);

  const dirty = value.trim() !== initialValue.trim();

  return (
    <SubPage
      title={title}
      onClose={onCancel}
      actions={[
        {
          text: "Save",
          busyText: "Saving...",
          disabled: !dirty,
          onClick: () => onSave(value.trim()),
          closeOnSuccess: true,
        },
        { type: "outline", text: "Cancel" },
      ]}
    >
      {(api) => (
        <div className="space-y-3">
          <div>
            <label className="text-muted-foreground mb-1 block text-xs">
              {fieldLabel}
            </label>
            <input
              type="text"
              value={value}
              autoFocus
              maxLength={200}
              placeholder={placeholder}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => {
                // runAction no-ops while busy, so a second Enter during
                // the slide-out can't re-fire onSave.
                if (e.key === "Enter") api.runAction(0);
              }}
              className={INPUT_CLASS}
            />
            {hint && (
              <p className="text-muted-foreground mt-1 text-[11px]">{hint}</p>
            )}
          </div>
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
      )}
    </SubPage>
  );
}
