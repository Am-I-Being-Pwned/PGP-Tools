import { Button } from "@amibeingpwned/ui/button";

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
        Choose how to protect your private key:
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
            Passkey
            <span className="text-primary text-xs font-normal">
              Recommended
            </span>
          </p>
          <p className="text-muted-foreground text-xs">
            Use your fingerprint, face, or security key. No password to
            remember.
          </p>
          {!prfAvailable && (
            <p className="text-destructive mt-1 text-xs">
              Not available in this browser.
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
                  Use the same passkey I already set up
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
          <p className="text-sm font-medium">Password</p>
          <p className="text-muted-foreground text-xs">
            Protect with a password. You'll enter it each time you unlock.
          </p>
        </div>
      </label>

      {method === "password" && (
        <>
          <input
            type="password"
            placeholder="Password (min 8 characters)"
            value={password}
            onChange={(e) => onPasswordChange(e.target.value)}
            className={INPUT_CLASS}
            aria-label="Password"
          />
          <input
            type="password"
            placeholder="Confirm password"
            value={confirmPassword}
            onChange={(e) => onConfirmPasswordChange(e.target.value)}
            className={INPUT_CLASS}
            aria-label="Confirm password"
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
          Back
        </Button>
        <Button
          size="sm"
          className="flex-1"
          onClick={onSubmit}
          disabled={submitting}
        >
          {submitting
            ? "..."
            : (submitLabel ??
              (method === "passkey" ? "Create passkey" : "Continue"))}
        </Button>
      </div>
    </div>
  );
}

/** Validate password fields. Returns error message or null. */
export function validatePassword(
  password: string,
  confirmPassword: string,
): string | null {
  if (password.length < 8) return "Password must be at least 8 characters.";
  if (password !== confirmPassword) return "Passwords don't match.";
  return null;
}
