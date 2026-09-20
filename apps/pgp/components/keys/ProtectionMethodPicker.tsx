import { Button } from "@amibeingpwned/ui/button";
import { Kbd } from "@amibeingpwned/ui/kbd";

import { t } from "../../lib/i18n";
import { checkPrfSupport } from "../../lib/protection/webauthn-prf";
import { INPUT_CLASS } from "../../lib/utils/styles";

export type ProtectionMethod = "passkey" | "password";

export function getDefaultProtectionMethod(): ProtectionMethod {
  return checkPrfSupport() ? "passkey" : "password";
}

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
  /** When set, offer to reuse the existing passkey instead of registering a new one. */
  reusePasskeyCredentialId?: string;
  reusePasskey?: boolean;
  onReusePasskeyChange?: (reuse: boolean) => void;
}

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

      <label
        className={`flex cursor-pointer items-start gap-3 rounded-md border p-3 transition-colors ${
          method === "passkey"
            ? "border-primary bg-primary/5"
            : "border-border hover:border-muted-foreground/50"
        } ${!prfAvailable ? "pointer-events-none opacity-50" : ""}`}
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
            <span className="text-primary text-xs font-normal">
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
        className={`flex cursor-pointer items-start gap-3 rounded-md border p-3 transition-colors ${
          method === "password"
            ? "border-primary bg-primary/5"
            : "border-border hover:border-muted-foreground/50"
        }`}
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

      {method === "password" && (
        <>
          <input
            type="password"
            autoComplete="new-password"
            placeholder={t("keygen_password_placeholder")}
            value={password}
            onChange={(e) => onPasswordChange(e.target.value)}
            className={INPUT_CLASS}
            aria-label={t("keygen_protection_password")}
          />
          <input
            type="password"
            autoComplete="new-password"
            placeholder={t("keygen_confirm_password")}
            value={confirmPassword}
            onChange={(e) => onConfirmPasswordChange(e.target.value)}
            onKeyDown={(e) => {
              // Return submits from the last field, which is where a
              // keyboard user ends up anyway. Nothing here is a <form>,
              // so without this the key does nothing at all -- and the
              // chip on the button below would be advertising a
              // behaviour that did not exist.
              if (e.key === "Enter" && !submitting) {
                e.preventDefault();
                onSubmit();
              }
            }}
            className={INPUT_CLASS}
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
              // Password only: the passkey path submits by starting a
              // WebAuthn ceremony from a click, and there is no field to
              // press Return in.
              <Kbd shortcut={{ key: "Enter" }} className="opacity-70" />
            )}
          </span>
        </Button>
      </div>
    </div>
  );
}

export function validatePassword(
  password: string,
  confirmPassword: string,
): string | null {
  if (password.length < 8) return t("keygen_error_password_short");
  if (password !== confirmPassword) return t("keygen_error_password_mismatch");
  return null;
}
