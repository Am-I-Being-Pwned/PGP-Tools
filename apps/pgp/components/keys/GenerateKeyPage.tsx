import { useState } from "react";
import { format } from "date-fns";
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
      setError("Name is required.");
      return;
    }
    if (!email.trim()) {
      setError("Email is required.");
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
      setError("Select an expiry date.");
      return;
    }
    // The calendar already disables anything before tomorrow; this is a
    // belt-and-braces check against the bounds captured at step open.
    if (expiryBounds && customExpiry < expiryBounds.tomorrow) {
      setError("Expiry date must be in the future.");
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
          email: email.trim(),
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
              cache: cacheKey,
            },
      );

      await addKey(blob);
      onKeyGenerated(blob.keyId, handle);
      close();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Key generation failed");
      setStep("protection");
    } finally {
      setGenerating(false);
    }
  };

  return (
    <SlideOverPanel entered={entered} ariaLabel="Generate key">
      <SlideOverHeader title="Generate key" onBack={handleBack} />

      <div className="flex flex-1 flex-col overflow-hidden">
        {step === "identity" && (
          <div className="flex flex-1 flex-col overflow-hidden">
            <div className="flex-1 space-y-4 overflow-y-auto p-4">
              <div>
                <h2 className="text-lg font-semibold">Create a new key</h2>
                <p className="text-muted-foreground mt-1 text-sm">
                  {keyType === "crx"
                    ? "A new RSA-2048 signing key for packaging a Chrome extension (.crx)."
                    : "A new OpenPGP keypair for encrypting, decrypting, and signing messages."}
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
                    Messaging key (PGP)
                  </Button>
                  <Button
                    variant={keyType === "crx" ? "default" : "outline"}
                    size="sm"
                    className="flex-1"
                    onClick={() => setKeyType("crx")}
                  >
                    Chrome extension (CRX)
                  </Button>
                </div>
              )}

              {keyType === "crx" ? (
                <div>
                  <label className="text-muted-foreground mb-1 block text-xs">
                    Label{" "}
                    <span className="text-muted-foreground/60">optional</span>
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. My Extension"
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
                        Name *
                      </label>
                      <input
                        type="text"
                        placeholder="Your full name"
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        className={INPUT_CLASS}
                      />
                    </div>
                    <div>
                      <label className="text-muted-foreground mb-1 block text-xs">
                        Email *
                      </label>
                      <input
                        type="email"
                        placeholder="you@example.com"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        className={INPUT_CLASS}
                      />
                    </div>
                    <div>
                      <label className="text-muted-foreground mb-1 block text-xs">
                        Comment{" "}
                        <span className="text-muted-foreground/60">
                          optional
                        </span>
                      </label>
                      <input
                        type="text"
                        placeholder="e.g. work, personal"
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
                    Advanced options
                  </button>

                  {showAdvanced && (
                    <div className="border-border space-y-3 rounded-md border p-3">
                      <div>
                        <label className="text-muted-foreground mb-1.5 block text-xs">
                          Algorithm
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
                            <SelectItem value="ecc">ECC (Ed25519)</SelectItem>
                            <SelectItem value="rsa">RSA</SelectItem>
                          </SelectContent>
                        </Select>
                        <p className="text-muted-foreground/60 mt-1 text-[10px]">
                          {keyAlgorithm === "ecc"
                            ? "Modern, fast, small keys. Recommended for most uses."
                            : "Widely compatible. Slower key generation."}
                        </p>
                      </div>

                      {keyAlgorithm === "rsa" && (
                        <div>
                          <label className="text-muted-foreground mb-1.5 block text-xs">
                            Key size
                          </label>
                          {/* RSA-4096 is the only size the WASM engine generates. */}
                          <Select value="4096">
                            <SelectTrigger className="h-8 text-xs">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="4096">4096 bit</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      )}

                      <div>
                        <label className="text-muted-foreground mb-1.5 block text-xs">
                          Key expiry
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
                            <SelectItem value="never">Never</SelectItem>
                            <SelectItem value="1y">1 year</SelectItem>
                            <SelectItem value="2y">2 years</SelectItem>
                            <SelectItem value="3y">3 years</SelectItem>
                            <SelectItem value="custom">Custom date</SelectItem>
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
                Next
              </Button>
            </div>
          </div>
        )}

        {step === "expiry" && expiryBounds && (
          <div className="flex flex-1 flex-col overflow-hidden">
            <div className="flex-1 space-y-4 overflow-y-auto p-4">
              <div>
                <h2 className="text-lg font-semibold">Choose an expiry date</h2>
                <p className="text-muted-foreground mt-1 text-sm">
                  After this date the key can no longer be used; you can always
                  generate a new one.
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
                  Expires {format(customExpiry, "PPP")}
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
                Next
              </Button>
            </div>
          </div>
        )}

        {step === "protection" && (
          <div className="flex-1 space-y-4 overflow-y-auto p-4">
            <div>
              <h2 className="text-lg font-semibold">Protect your key</h2>
              <p className="text-muted-foreground mt-1 text-sm">
                Choose how to unlock this key when you use it.
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
                    ? "Use passkey"
                    : "Create passkey"
                  : "Generate"
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
                ? "Follow your browser's passkey prompt..."
                : "Generating key..."}
            </p>
            {(keyAlgorithm === "rsa" || keyType === "crx") && (
              <p className="text-muted-foreground/60 mt-1 text-xs">
                RSA keys take a moment to generate
              </p>
            )}
          </div>
        )}
      </div>
    </SlideOverPanel>
  );
}
