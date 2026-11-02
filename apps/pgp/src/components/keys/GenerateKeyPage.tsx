import { useState } from "react";
import { LoaderIcon } from "lucide-react";

import { BlockStack, Button, Calendar, cn } from "@amibeingpwned/ui";

import {
  SlideOverHeader,
  SlideOverPanel,
  useSlideOver,
} from "~/components/shared/SlideOver";
import { useAsyncAction } from "~/hooks";
import { generateCrxKey } from "~/lib/crx/operations";
import type { CrxSigningKeyBlob } from "~/lib/crx/types";
import { t } from "~/lib/i18n";
import { formatDate } from "~/lib/i18n/format";
import {
  DEFAULT_EXPIRY,
  expiryToSeconds,
  type ExpiryOption,
} from "~/lib/keys/expiry";
import { generateAndProtect } from "~/lib/protection/protect-flow";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import { afterNextPaint } from "~/lib/utils/paint";
import {
  EMPTY_IDENTITY,
  FieldBlock,
  identityUserId,
  KeyIdentityFields,
  type KeyAlgorithm,
} from "./KeyIdentityFields";
import { ProtectionMethodPicker } from "./ProtectionMethodPicker";
import { useProtectionChoice } from "./useProtectionChoice";

type Step = "identity" | "expiry" | "protection" | "generating";
type KeyType = "pgp" | "crx";

const DAY_MS = 86_400_000;

interface GenerateKeyPageProps {
  onClose: () => void;
  onKeyGenerated: (keyId: string, keyHandle?: number) => void;
  addKey: (blob: ProtectedKeyBlob) => Promise<void>;
  reusePasskeyCredentialId?: string;
  /** With reuse, seal under the master's PRF salt so the vault unlock
   *  opens the key. */
  masterSealSalt?: ArrayBuffer;
  cacheKey?: boolean;
  crxSigningEnabled?: boolean;
  addCrxKey?: (blob: CrxSigningKeyBlob) => Promise<void>;
}

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
  const [identity, setIdentity] = useState(EMPTY_IDENTITY);
  const choice = useProtectionChoice({
    reusePasskeyCredentialId,
    masterSealSalt,
  });
  // Engine text never reaches the message (it lands in `detail`).
  const generation = useAsyncAction(t("keygen_error_generation_failed"));
  const error = generation.error?.message ?? null;
  const setError = generation.setError;

  const [keyAlgorithm, setKeyAlgorithm] = useState<KeyAlgorithm>("ecc");
  const [expiryOption, setExpiryOption] =
    useState<ExpiryOption>(DEFAULT_EXPIRY);
  const [customExpiry, setCustomExpiry] = useState<Date | undefined>();

  // Reading the clock in render breaks render purity.
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

  const canSkipProtection =
    !!reusePasskeyCredentialId && choice.method === "passkey";

  const handleBack = () => {
    if (step === "generating") return;
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
    if (!identity.name.trim()) {
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
    const invalid = choice.validate();
    if (invalid) {
      setError(invalid);
      return;
    }
    const failed = await generation.run(async () => {
      setStep("generating");
      // Let "Generating…" paint before the wasm call holds the thread.
      await afterNextPaint();

      if (keyType === "crx") {
        const blob = await generateCrxKey(
          choice.toCrxInput(),
          label.trim() || undefined,
        );
        await addCrxKey?.(blob);
        close();
        return;
      }

      const expiresIn = expiryToSeconds(expiryOption, customExpiry);
      const { blob, handle } = await generateAndProtect(
        {
          ...identityUserId(identity),
          type: keyAlgorithm,
          expiresIn: expiresIn || undefined,
        },
        choice.toInput({ cache: cacheKey }),
      );
      await addKey(blob);
      onKeyGenerated(blob.keyId, handle);
      close();
    });
    if (failed) setStep("protection");
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
                // Plain pressed-state buttons: e2e finds them by name.
                <div className="bg-track grid grid-cols-2 gap-0.5 rounded-lg p-[3px]">
                  {(
                    [
                      ["pgp", t("keygen_type_pgp")],
                      ["crx", t("keygen_type_crx")],
                    ] as const
                  ).map(([type, text]) => (
                    <button
                      key={type}
                      type="button"
                      aria-pressed={keyType === type}
                      onClick={() => setKeyType(type)}
                      className={cn(
                        "focus-visible:ring-ring/50 h-7 truncate rounded-md px-3 text-[13px] font-medium transition-colors outline-none focus-visible:ring-[3px]",
                        keyType === type
                          ? "bg-raised text-foreground shadow-[inset_0_1px_0_rgb(255_255_255/0.1),0_1px_2px_rgb(0_0_0/0.5)]"
                          : "text-muted-foreground hover:text-foreground",
                      )}
                    >
                      {text}
                    </button>
                  ))}
                </div>
              )}

              {keyType === "crx" ? (
                <BlockStack>
                  <FieldBlock
                    label={t("keygen_label_label")}
                    optional
                    type="text"
                    placeholder={t("keygen_label_placeholder")}
                    value={label}
                    onChange={(e) => setLabel(e.target.value)}
                  />
                </BlockStack>
              ) : (
                <KeyIdentityFields
                  identity={identity}
                  onIdentityChange={setIdentity}
                  algorithm={keyAlgorithm}
                  onAlgorithmChange={setKeyAlgorithm}
                  expiry={expiryOption}
                  onExpiryChange={setExpiryOption}
                  allowCustomExpiry
                />
              )}
            </div>

            <div className="space-y-2 p-4">
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

            <div className="space-y-2 p-4">
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
              {...choice.pickerProps}
              error={error}
              onSubmit={() => void handleGenerate()}
              onBack={handleBack}
              submitting={generation.busy}
              submitLabel={
                choice.method === "passkey"
                  ? choice.reusing
                    ? t("keygen_submit_use_passkey")
                    : t("keygen_submit_create_passkey")
                  : t("keygen_submit_generate")
              }
            />
          </div>
        )}

        {step === "generating" && (
          <div className="m-auto text-center">
            <div className="bg-primary/10 mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-full">
              <LoaderIcon className="text-primary h-5 w-5 animate-spin" />
            </div>
            <p className="text-muted-foreground text-sm">
              {choice.method === "passkey"
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
