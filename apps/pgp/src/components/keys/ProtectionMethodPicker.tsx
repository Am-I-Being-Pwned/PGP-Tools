import { BlockStack, Button, cn, Input, Kbd } from "@amibeingpwned/ui";

import { t } from "~/lib/i18n";
import { checkPrfSupport } from "~/lib/protection/webauthn-prf";
import type { ProtectionMethod } from "./protection-choice";

interface ProtectionMethodPickerProps {
  method: ProtectionMethod;
  onMethodChange: (method: ProtectionMethod) => void;
  password: string;
  onPasswordChange: (password: string) => void;
  confirmPassword: string;
  onConfirmPasswordChange: (password: string) => void;
  error: string | null;
  onSubmit: () => void;
  onBack: () => void;
  submitting: boolean;
  submitLabel?: string;
  reusePasskeyCredentialId?: string;
  reusePasskey?: boolean;
  onReusePasskeyChange?: (reuse: boolean) => void;
}

const OPTION =
  "flex cursor-pointer items-start gap-3 rounded-[3px] p-3 transition-colors";
const OPTION_ON = "bg-on";
const OPTION_OFF = "bg-card hover:bg-accent/50";

export function ProtectionMethodPicker({
  method,
  onMethodChange,
  password,
  onPasswordChange,
  confirmPassword,
  onConfirmPasswordChange,
  error,
  onSubmit,
  onBack,
  submitting,
  submitLabel,
  reusePasskeyCredentialId,
  reusePasskey,
  onReusePasskeyChange,
}: ProtectionMethodPickerProps) {
  const prfAvailable = checkPrfSupport();

  return (
    <div className="space-y-3">
      <p className="text-muted-foreground text-xs">
        {t("keygen_protection_intro")}
      </p>

      {/* Native radios stay underneath: they carry keyboard and group semantics. */}
      <BlockStack>
        <label
          className={cn(
            OPTION,
            method === "passkey" ? OPTION_ON : OPTION_OFF,
            !prfAvailable && "pointer-events-none opacity-50",
          )}
        >
          <input
            type="radio"
            name="protection"
            checked={method === "passkey"}
            onChange={() => onMethodChange("passkey")}
            disabled={!prfAvailable}
            className="accent-primary mt-0.5"
          />
          <div>
            <p className="flex items-center justify-between text-sm font-medium">
              {t("keygen_protection_passkey")}
              <span className="text-good text-xs font-normal">
                {t("keygen_protection_recommended")}
              </span>
            </p>
            <p className="text-muted-foreground text-xs">
              {t("keygen_protection_passkey_desc")}
            </p>
            {!prfAvailable && (
              <p className="text-destructive mt-1 text-xs">
                {t("keygen_protection_passkey_unavailable")}
              </p>
            )}
            {method === "passkey" &&
              reusePasskeyCredentialId &&
              onReusePasskeyChange && (
                <label className="mt-2 flex cursor-pointer items-center gap-2">
                  <input
                    type="checkbox"
                    checked={reusePasskey ?? true}
                    onChange={(e) => onReusePasskeyChange(e.target.checked)}
                    className="accent-primary"
                  />
                  <span className="text-muted-foreground text-xs">
                    {t("keygen_protection_reuse_passkey")}
                  </span>
                </label>
              )}
          </div>
        </label>

        <label
          className={cn(OPTION, method === "password" ? OPTION_ON : OPTION_OFF)}
        >
          <input
            type="radio"
            name="protection"
            checked={method === "password"}
            onChange={() => onMethodChange("password")}
            className="accent-primary mt-0.5"
          />
          <div>
            <p className="text-sm font-medium">
              {t("keygen_protection_password")}
            </p>
            <p className="text-muted-foreground text-xs">
              {t("keygen_protection_password_desc")}
            </p>
          </div>
        </label>
      </BlockStack>

      {method === "password" && (
        <>
          <Input
            type="password"
            autoComplete="new-password"
            placeholder={t("keygen_password_placeholder")}
            value={password}
            onChange={(e) => onPasswordChange(e.target.value)}
            aria-label={t("keygen_protection_password")}
          />
          <Input
            type="password"
            autoComplete="new-password"
            placeholder={t("keygen_confirm_password")}
            value={confirmPassword}
            onChange={(e) => onConfirmPasswordChange(e.target.value)}
            onKeyDown={(e) => {
              // No <form> here: without this, Return does nothing.
              if (e.key === "Enter" && !submitting) {
                e.preventDefault();
                onSubmit();
              }
            }}
            aria-label={t("keygen_confirm_password")}
          />
        </>
      )}

      {error && (
        <p className="text-destructive text-xs" role="alert">
          {error}
        </p>
      )}

      <div className="flex gap-2">
        <Button
          variant="outline"
          size="sm"
          className="flex-1"
          onClick={onBack}
          disabled={submitting}
        >
          {t("common_back")}
        </Button>
        <Button
          size="sm"
          className="flex-1"
          onClick={onSubmit}
          disabled={submitting}
          aria-keyshortcuts="Enter"
        >
          <span className="flex w-full items-center justify-center gap-2">
            {submitting
              ? "..."
              : (submitLabel ??
                (method === "passkey"
                  ? t("keygen_submit_create_passkey")
                  : t("common_continue")))}
            {!submitting && method === "password" && (
              <Kbd shortcut={{ key: "Enter" }} className="opacity-70" />
            )}
          </span>
        </Button>
      </div>
    </div>
  );
}
