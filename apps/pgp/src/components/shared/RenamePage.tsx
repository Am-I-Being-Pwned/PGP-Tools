import { useState } from "react";

import { Input } from "@amibeingpwned/ui";

import { t } from "~/lib/i18n";
import { SubPage } from "./SubPage";

interface RenamePageProps {
  title: string;
  fieldLabel: string;
  initialValue: string;
  hint?: string;
  placeholder?: string;
  /** Already trimmed; "" clears the alias. */
  onSave: (value: string) => void | Promise<void>;
  onCancel: () => void;
}

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
          text: t("common_save"),
          busyText: t("shared_saving"),
          disabled: !dirty,
          onClick: () => onSave(value.trim()),
          closeOnSuccess: true,
        },
        { type: "outline", text: t("common_cancel") },
      ]}
    >
      {(api) => (
        <div className="space-y-3">
          <div>
            <label className="text-muted-foreground mb-1 block text-xs">
              {fieldLabel}
            </label>
            <Input
              type="text"
              value={value}
              autoFocus
              maxLength={200}
              placeholder={placeholder}
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => {
                // runAction no-ops while busy: no double onSave.
                if (e.key === "Enter") api.runAction(0);
              }}
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
              {t("shared_clear_name")}
            </button>
          )}
        </div>
      )}
    </SubPage>
  );
}
