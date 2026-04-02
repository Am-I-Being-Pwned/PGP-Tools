import { useState } from "react";
import { format } from "date-fns";
import { ChevronRightIcon, KeyRoundIcon, LoaderIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";
import { Calendar } from "@amibeingpwned/ui/calendar";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@amibeingpwned/ui/select";

import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { generateKey } from "../../lib/pgp/key-management";
import { protectAndStoreKey } from "../../lib/protection/protect-key";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { Dialog } from "../shared/Dialog";
import {
  getDefaultProtectionMethod,
  ProtectionMethodPicker,
  validatePassword,
} from "./ProtectionMethodPicker";

type Step = "identity" | "expiry" | "protection" | "generating";
type KeyAlgorithm = "ecc" | "rsa";
type ExpiryOption = "never" | "1y" | "2y" | "3y" | "custom";

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

interface GenerateKeyDialogProps {
  open: boolean;
  onClose: () => void;
  onKeyGenerated: (keyId: string, keyHandle?: number) => void;
  addKey: (blob: ProtectedKeyBlob) => Promise<void>;
  /** Pass the primary key's passkey credential ID to allow reuse. */
  reusePasskeyCredentialId?: string;
  /** If true, cache the decrypted key in WASM and return the handle via onKeyGenerated. */
  cacheKey?: boolean;
}

export function GenerateKeyDialog({
  open,
  onClose,
  onKeyGenerated,
  addKey,
  reusePasskeyCredentialId,
  cacheKey,
}: GenerateKeyDialogProps) {
  const [step, setStep] = useState<Step>("identity");
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
  const [rsaBits, setRsaBits] = useState<4096>(4096);
  const [expiryOption, setExpiryOption] = useState<ExpiryOption>("2y");
  const [customExpiry, setCustomExpiry] = useState<Date | undefined>();

  if (!open) return null;

  const resetAndClose = () => {
    setStep("identity");
    setName("");
    setEmail("");
    setComment("");
    setPassword("");
    setConfirmPassword("");
    setError(null);
    setReusePasskey(true);
    setShowAdvanced(false);
    setKeyAlgorithm("ecc");
    setRsaBits(4096);
    setExpiryOption("never");
    setCustomExpiry(undefined);
    onClose();
  };

  const canSkipProtection = !!reusePasskeyCredentialId && method === "passkey";

  const handleNext = () => {
    setError(null);
    if (!name.trim()) {
      setError("Name is required.");
      return;
    }
    if (!email.trim()) {
      setError("Email is required.");
      return;
    }
    if (expiryOption === "custom") {
      setStep("expiry");
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
    if (customExpiry.getTime() <= Date.now()) {
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
      const expiresIn = expiryToSeconds(expiryOption, customExpiry);
      const {
        publicKeyArmored,
        privateKeyArmored,
        revocationCertificate,
        keyInfo,
      } = await generateKey({
        name: name.trim(),
        email: email.trim(),
        comment: comment.trim() || undefined,
        type: keyAlgorithm,
        expiresIn: expiresIn || undefined,
      });

      const { blob, keyHandle } = await protectAndStoreKey({
        privateKeyArmored,
        publicKeyArmored,
        keyInfo,
        method,
        password,
        revocationCertificate,
        reusePasskeyCredentialId:
          method === "passkey" && reusePasskey
            ? reusePasskeyCredentialId
            : undefined,
        cacheKey,
      });

      await addKey(blob);
      onKeyGenerated(blob.keyId, keyHandle);
      resetAndClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Key generation failed");
      setStep("protection");
    } finally {
      setGenerating(false);
    }
  };

  const tomorrow = new Date(Date.now() + 86400000);

  return (
    <Dialog open={open} onClose={resetAndClose} title="Generate New Key">
      {step === "identity" && (
        <div className="space-y-3">
          <div className="flex items-start gap-3 pb-1">
            <div className="bg-primary/10 flex h-10 w-10 shrink-0 items-center justify-center rounded-lg">
              <KeyRoundIcon className="text-primary h-5 w-5" />
            </div>
            <p className="text-muted-foreground text-xs leading-relaxed">
              Create a new OpenPGP keypair for encrypting, decrypting, and
              signing messages.
            </p>
          </div>

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
                <span className="text-muted-foreground/60">optional</span>
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
                  onValueChange={(v) => setKeyAlgorithm(v as KeyAlgorithm)}
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
                  <Select
                    value={String(rsaBits)}
                    onValueChange={(v) => setRsaBits(Number(v) as 4096)}
                  >
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
                  onValueChange={(v) => setExpiryOption(v as ExpiryOption)}
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
              onClick={resetAndClose}
            >
              Cancel
            </Button>
            <Button size="sm" className="flex-1" onClick={handleNext}>
              Next
            </Button>
          </div>
        </div>
      )}

      {step === "expiry" && (
        <div className="space-y-3">
          <p className="text-muted-foreground text-xs">
            When should this key expire?
          </p>
          <Calendar
            mode="single"
            captionLayout="dropdown"
            selected={customExpiry}
            onSelect={setCustomExpiry}
            disabled={{ before: tomorrow }}
            defaultMonth={customExpiry ?? tomorrow}
            startMonth={tomorrow}
            endMonth={new Date(Date.now() + 10 * 365 * 86400000)}
            className="mx-auto"
          />
          {customExpiry && (
            <p className="text-center text-xs">
              Expires {format(customExpiry, "PPP")}
            </p>
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
              onClick={() => {
                setStep("identity");
                setError(null);
              }}
            >
              Back
            </Button>
            <Button size="sm" className="flex-1" onClick={handleExpiryNext}>
              Next
            </Button>
          </div>
        </div>
      )}

      {step === "protection" && (
        <ProtectionMethodPicker
          method={method}
          onMethodChange={setMethod}
          password={password}
          onPasswordChange={setPassword}
          confirmPassword={confirmPassword}
          onConfirmPasswordChange={setConfirmPassword}
          error={error}
          onSubmit={handleGenerate}
          onBack={() => {
            setStep(expiryOption === "custom" ? "expiry" : "identity");
            setError(null);
          }}
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
      )}

      {step === "generating" && (
        <div className="py-6 text-center">
          <div className="bg-primary/10 mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-full">
            <LoaderIcon className="text-primary h-5 w-5 animate-spin" />
          </div>
          <p className="text-muted-foreground text-sm">
            {method === "passkey"
              ? "Follow your browser's passkey prompt..."
              : "Generating key..."}
          </p>
          {keyAlgorithm === "rsa" && (
            <p className="text-muted-foreground/60 mt-1 text-xs">
              RSA keys take a moment to generate
            </p>
          )}
        </div>
      )}
    </Dialog>
  );
}
