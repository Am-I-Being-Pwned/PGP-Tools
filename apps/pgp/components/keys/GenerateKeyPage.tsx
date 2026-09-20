import { useState } from "react";
import { ChevronRightIcon, LoaderIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";
import { Calendar } from "@amibeingpwned/ui/calendar";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@amibeingpwned/ui/select";

import type { CrxProtectionInput } from "../../lib/crx/operations";
import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { generateCrxKey } from "../../lib/crx/operations";
import { t } from "../../lib/i18n";
import { formatDate } from "../../lib/i18n/format";
import { generateAndProtect } from "../../lib/protection/protect-flow";
import { INPUT_CLASS } from "../../lib/utils/styles";
import {
  SlideOverHeader,
  SlideOverPanel,
  useSlideOver,
} from "../shared/SlideOver";
import {
  getDefaultProtectionMethod,
  ProtectionMethodPicker,
  validatePassword,
} from "./ProtectionMethodPicker";

type Step = "identity" | "expiry" | "protection" | "generating";
type KeyAlgorithm = "ecc" | "rsa";
type KeyType = "pgp" | "crx";
type ExpiryOption = "never" | "1y" | "2y" | "3y" | "custom";

const DAY_MS = 86_400_000;

const EXPIRY_SECONDS: Record<Exclude<ExpiryOption, "custom">, number> = {
  never: 0,
  "1y": 365 * 24 * 60 * 60,
  "2y": 2 * 365 * 24 * 60 * 60,
  "3y": 3 * 365 * 24 * 60 * 60,
};

function expiryToSeconds(
  option: ExpiryOption,
  customDate: Date | undefined,
): number {
  if (option === "custom" && customDate) {
    const diff = Math.floor((customDate.getTime() - Date.now()) / 1000);
    return diff > 0 ? diff : 0;
  }
  return EXPIRY_SECONDS[option as Exclude<ExpiryOption, "custom">];
}

interface GenerateKeyPageProps {
  /** Called after the slide-out finishes (cancel or success). */
  onClose: () => void;
  onKeyGenerated: (keyId: string, keyHandle?: number) => void;
  addKey: (blob: ProtectedKeyBlob) => Promise<void>;
  /** Pass the primary key's passkey credential ID to allow reuse. */
  reusePasskeyCredentialId?: string;
  /** With reuse, seal under the master's PRF salt so the vault ceremony
   *  opens the key ("unlock keys when the vault unlocks"). */
  masterSealSalt?: ArrayBuffer;
  /** If true, cache the decrypted key in WASM and return the handle via onKeyGenerated. */
  cacheKey?: boolean;
  /** When true, offer generating a CRX (Chrome extension) signing key. */
  crxSigningEnabled?: boolean;
  /** Persist a newly generated CRX signing key. Required for the CRX path. */
  addCrxKey?: (blob: CrxSigningKeyBlob) => Promise<void>;
}

/**
 * Full-page key generation, using the same slide-over pattern as key
 * details and the onboarding page style (big step heading + subtitle,
 * full-width primary action; back lives in the header).
 */
export function GenerateKeyPage({
  onClose,
  onKeyGenerated,
  addKey,
  reusePasskeyCredentialId,
  masterSealSalt,
  cacheKey,
  crxSigningEnabled,
  addCrxKey,
}: GenerateKeyPageProps) {
  const { entered, close } = useSlideOver(onClose);
  const [step, setStep] = useState<Step>("identity");
  const [keyType, setKeyType] = useState<KeyType>("pgp");
  const [label, setLabel] = useState("");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [comment, setComment] = useState("");
  const [method, setMethod] = useState(getDefaultProtectionMethod);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [reusePasskey, setReusePasskey] = useState(true);

  const [showAdvanced, setShowAdvanced] = useState(false);
  const [keyAlgorithm, setKeyAlgorithm] = useState<KeyAlgorithm>("ecc");
  const [expiryOption, setExpiryOption] = useState<ExpiryOption>("2y");
  const [customExpiry, setCustomExpiry] = useState<Date | undefined>();

  // Calendar bounds, captured when the expiry step opens. Reading the
  // clock during render would break render purity (react-hooks/purity).
  const [expiryBounds, setExpiryBounds] = useState<{
    tomorrow: Date;
    max: Date;
  } | null>(null);

  const openExpiryStep = () => {
    const now = Date.now();
    setExpiryBounds({
      tomorrow: new Date(now + DAY_MS),
      max: new Date(now + 10 * 365 * DAY_MS),
    });
    setStep("expiry");
  };

  const canSkipProtection = !!reusePasskeyCredentialId && method === "passkey";

  // Header back mirrors the step order; from the first step it closes.
  const handleBack = () => {
    if (generating) return;
    setError(null);
    if (step === "expiry") {
      setStep("identity");
    } else if (step === "protection") {
      setStep(expiryOption === "custom" ? "expiry" : "identity");
    } else {
      close();
    }
  };

  const handleNext = () => {
    setError(null);
    if (keyType === "crx") {
      if (canSkipProtection) {
        void handleGenerate();
      } else {
        setStep("protection");
      }
      return;
    }
    if (!name.trim()) {
      setError(t("keygen_error_name_required"));
      return;
    }
    if (expiryOption === "custom") {
      openExpiryStep();
    } else if (canSkipProtection) {
      void handleGenerate();
    } else {
      setStep("protection");
    }
  };

  const handleExpiryNext = () => {
    setError(null);
    if (!customExpiry) {
      setError(t("keygen_error_expiry_required"));
      return;
    }
    // The calendar already disables anything before tomorrow; this is a
    // belt-and-braces check against the bounds captured at step open.
    if (expiryBounds && customExpiry < expiryBounds.tomorrow) {
      setError(t("keygen_error_expiry_past"));
      return;
    }
    if (canSkipProtection) {
      void handleGenerate();
    } else {
      setStep("protection");
    }
  };

  const handleGenerate = async () => {
    setError(null);

    if (method === "password") {
      const pwError = validatePassword(password, confirmPassword);
      if (pwError) {
        setError(pwError);
        return;
      }
    }

    setGenerating(true);
    setStep("generating");

    try {
      if (keyType === "crx") {
        const protection: CrxProtectionInput =
          method === "password"
            ? { method: "password", password }
            : {
                method: "passkey",
                reusePasskeyCredentialId: reusePasskey
                  ? reusePasskeyCredentialId
                  : undefined,
              };
        const blob = await generateCrxKey(
          protection,
          label.trim() || undefined,
        );
        await addCrxKey?.(blob);
        close();
        return;
      }

      const expiresIn = expiryToSeconds(expiryOption, customExpiry);
      const { blob, handle } = await generateAndProtect(
        {
          name: name.trim(),
          email: email.trim() || undefined,
          comment: comment.trim() || undefined,
          type: keyAlgorithm,
          expiresIn: expiresIn || undefined,
        },
        method === "password"
          ? { method: "password", password, cache: cacheKey }
          : {
              method: "passkey",
              reusePasskeyCredentialId: reusePasskey
                ? reusePasskeyCredentialId
                : undefined,
              prfSalt: reusePasskey ? masterSealSalt : undefined,
              cache: cacheKey,
            },
      );

      await addKey(blob);
      onKeyGenerated(blob.keyId, handle);
      close();
    } catch (e) {
      setError(
        e instanceof Error ? e.message : t("keygen_error_generation_failed"),
      );
      setStep("protection");
    } finally {
      setGenerating(false);
    }
  };

  return (
    <SlideOverPanel
      entered={entered}
      ariaLabel={t("keygen_title")}
      onDismiss={close}
    >
      <SlideOverHeader title={t("keygen_title")} onBack={handleBack} />

      <div className="flex flex-1 flex-col overflow-hidden">
        {step === "identity" && (
          <div className="flex flex-1 flex-col overflow-hidden">
            <div className="flex-1 space-y-4 overflow-y-auto p-4">
              <div>
                <h2 className="text-lg font-semibold">
                  {t("keygen_create_heading")}
                </h2>
                <p className="text-muted-foreground mt-1 text-sm">
                  {keyType === "crx"
                    ? t("keygen_create_subtitle_crx")
                    : t("keygen_create_subtitle_pgp")}
                </p>
              </div>

              {crxSigningEnabled && (
                <div className="flex gap-2">
                  <Button
                    variant={keyType === "pgp" ? "default" : "outline"}
                    size="sm"
                    className="flex-1"
                    onClick={() => setKeyType("pgp")}
                  >
                    {t("keygen_type_pgp")}
                  </Button>
                  <Button
                    variant={keyType === "crx" ? "default" : "outline"}
                    size="sm"
                    className="flex-1"
                    onClick={() => setKeyType("crx")}
                  >
                    {t("keygen_type_crx")}
                  </Button>
                </div>
              )}

              {keyType === "crx" ? (
                <div>
                  <label className="text-muted-foreground mb-1 block text-xs">
                    {t("keygen_label_label")}{" "}
                    <span className="text-muted-foreground/60">
                      {t("keygen_optional")}
                    </span>
                  </label>
                  <input
                    type="text"
                    placeholder={t("keygen_label_placeholder")}
                    value={label}
                    onChange={(e) => setLabel(e.target.value)}
                    className={INPUT_CLASS}
                  />
                </div>
              ) : (
                <>
                  <div className="space-y-2">
                    <div>
                      <label className="text-muted-foreground mb-1 block text-xs">
                        {t("keygen_name_label")}
                      </label>
                      <input
                        type="text"
                        placeholder={t("keygen_name_placeholder")}
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        className={INPUT_CLASS}
                      />
                    </div>
                    <div>
                      <label className="text-muted-foreground mb-1 block text-xs">
                        {t("keygen_email_label")}{" "}
                        <span className="text-muted-foreground/60">
                          {t("keygen_optional")}
                        </span>
                      </label>
                      <input
                        type="email"
                        placeholder={t("keygen_email_placeholder")}
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        className={INPUT_CLASS}
                      />
                    </div>
                    <div>
                      <label className="text-muted-foreground mb-1 block text-xs">
                        {t("keygen_comment_label")}{" "}
                        <span className="text-muted-foreground/60">
                          {t("keygen_optional")}
                        </span>
                      </label>
                      <input
                        type="text"
                        placeholder={t("keygen_comment_placeholder")}
                        value={comment}
                        onChange={(e) => setComment(e.target.value)}
                        className={INPUT_CLASS}
                      />
                    </div>
                  </div>

                  <button
                    type="button"
                    onClick={() => setShowAdvanced(!showAdvanced)}
                    className="text-muted-foreground hover:text-foreground flex w-full items-center gap-1.5 text-xs transition-colors"
                  >
                    <ChevronRightIcon
                      className={`h-3 w-3 transition-transform ${showAdvanced ? "rotate-90" : ""}`}
                    />
                    {t("keygen_advanced_options")}
                  </button>

                  {showAdvanced && (
                    <div className="border-border space-y-3 rounded-md border p-3">
                      <div>
                        <label className="text-muted-foreground mb-1.5 block text-xs">
                          {t("keygen_algorithm_label")}
                        </label>
                        <Select
                          value={keyAlgorithm}
                          onValueChange={(v) =>
                            setKeyAlgorithm(v as KeyAlgorithm)
                          }
                        >
                          <SelectTrigger className="h-8 text-xs">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            {/* i18n-ignore */}
                            <SelectItem value="ecc">ECC (Ed25519)</SelectItem>
                            {/* i18n-ignore */}
                            <SelectItem value="rsa">RSA</SelectItem>
                          </SelectContent>
                        </Select>
                        <p className="text-muted-foreground/60 mt-1 text-[10px]">
                          {keyAlgorithm === "ecc"
                            ? t("keygen_algorithm_hint_ecc")
                            : t("keygen_algorithm_hint_rsa")}
                        </p>
                      </div>

                      {keyAlgorithm === "rsa" && (
                        <div>
                          <label className="text-muted-foreground mb-1.5 block text-xs">
                            {t("keygen_key_size_label")}
                          </label>
                          {/* RSA-4096 is the only size the WASM engine generates. */}
                          <Select value="4096">
                            <SelectTrigger className="h-8 text-xs">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="4096">
                                {t("keygen_key_size_4096")}
                              </SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      )}

                      <div>
                        <label className="text-muted-foreground mb-1.5 block text-xs">
                          {t("keygen_expiry_label")}
                        </label>
                        <Select
                          value={expiryOption}
                          onValueChange={(v) =>
                            setExpiryOption(v as ExpiryOption)
                          }
                        >
                          <SelectTrigger className="h-8 text-xs">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="never">
                              {t("keygen_expiry_never")}
                            </SelectItem>
                            <SelectItem value="1y">
                              {t("keygen_expiry_1y")}
                            </SelectItem>
                            <SelectItem value="2y">
                              {t("keygen_expiry_2y")}
                            </SelectItem>
                            <SelectItem value="3y">
                              {t("keygen_expiry_3y")}
                            </SelectItem>
                            <SelectItem value="custom">
                              {t("keygen_expiry_custom")}
                            </SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>

            <div className="border-border space-y-2 border-t p-4">
              {error && (
                <p className="text-destructive text-xs" role="alert">
                  {error}
                </p>
              )}
              <Button className="w-full" onClick={handleNext}>
                {t("keygen_next")}
              </Button>
            </div>
          </div>
        )}

        {step === "expiry" && expiryBounds && (
          <div className="flex flex-1 flex-col overflow-hidden">
            <div className="flex-1 space-y-4 overflow-y-auto p-4">
              <div>
                <h2 className="text-lg font-semibold">
                  {t("keygen_expiry_heading")}
                </h2>
                <p className="text-muted-foreground mt-1 text-sm">
                  {t("keygen_expiry_subtitle")}
                </p>
              </div>
              <Calendar
                mode="single"
                captionLayout="dropdown"
                selected={customExpiry}
                onSelect={setCustomExpiry}
                disabled={{ before: expiryBounds.tomorrow }}
                defaultMonth={customExpiry ?? expiryBounds.tomorrow}
                startMonth={expiryBounds.tomorrow}
                endMonth={expiryBounds.max}
                className="mx-auto"
              />
              {customExpiry && (
                <p className="text-center text-xs">
                  {t("keygen_expires_on", { date: formatDate(customExpiry) })}
                </p>
              )}
            </div>

            <div className="border-border space-y-2 border-t p-4">
              {error && (
                <p className="text-destructive text-xs" role="alert">
                  {error}
                </p>
              )}
              <Button className="w-full" onClick={handleExpiryNext}>
                {t("keygen_next")}
              </Button>
            </div>
          </div>
        )}

        {step === "protection" && (
          <div className="flex-1 space-y-4 overflow-y-auto p-4">
            <div>
              <h2 className="text-lg font-semibold">
                {t("keygen_protect_heading")}
              </h2>
              <p className="text-muted-foreground mt-1 text-sm">
                {t("keygen_protect_subtitle")}
              </p>
            </div>
            <ProtectionMethodPicker
              method={method}
              onMethodChange={setMethod}
              password={password}
              onPasswordChange={setPassword}
              confirmPassword={confirmPassword}
              onConfirmPasswordChange={setConfirmPassword}
              error={error}
              onSubmit={handleGenerate}
              onBack={handleBack}
              submitting={generating}
              submitLabel={
                method === "passkey"
                  ? reusePasskeyCredentialId && reusePasskey
                    ? t("keygen_submit_use_passkey")
                    : t("keygen_submit_create_passkey")
                  : t("keygen_submit_generate")
              }
              reusePasskeyCredentialId={reusePasskeyCredentialId}
              reusePasskey={reusePasskey}
              onReusePasskeyChange={setReusePasskey}
            />
          </div>
        )}

        {step === "generating" && (
          <div className="m-auto text-center">
            <div className="bg-primary/10 mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-full">
              <LoaderIcon className="text-primary h-5 w-5 animate-spin" />
            </div>
            <p className="text-muted-foreground text-sm">
              {method === "passkey"
                ? t("keygen_generating_passkey")
                : t("keygen_generating_key")}
            </p>
            {(keyAlgorithm === "rsa" || keyType === "crx") && (
              <p className="text-muted-foreground/60 mt-1 text-xs">
                {t("keygen_generating_rsa_hint")}
              </p>
            )}
          </div>
        )}
      </div>
    </SlideOverPanel>
  );
}
