import { useEffect, useRef, useState } from "react";
import { ChevronRightIcon, LoaderIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@amibeingpwned/ui/select";

import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { MasterProtection } from "../../lib/storage/master-protection";
import type { StorageLocation } from "../../lib/storage/preferences";
import { toBase64, unpackIvCiphertext } from "../../lib/encoding";
import * as wasmApi from "../../lib/pgp/wasm";
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  generateSalt,
} from "../../lib/protection/password-kdf";
import { generateAndProtect } from "../../lib/protection/protect-flow";
import {
  authenticateAndGetPrf,
  generatePrfSalt,
  generateStoredSecret,
  registerPasskey,
} from "../../lib/protection/webauthn-prf";
import { saveMasterProtection } from "../../lib/storage/master-protection";
import { savePreferences } from "../../lib/storage/preferences";
import { INPUT_CLASS } from "../../lib/utils/styles";
import {
  getDefaultProtectionMethod,
  ProtectionMethodPicker,
  validatePassword,
} from "../keys/ProtectionMethodPicker";
import { StorageLocationPicker } from "./StorageLocationPicker";

type Step = "storage" | "protection" | "identity" | "generating";
type KeyAlgorithm = "ecc" | "rsa";
type ExpiryOption = "never" | "1y" | "2y" | "3y";

const EXPIRY_SECONDS: Record<ExpiryOption, number> = {
  never: 0,
  "1y": 365 * 24 * 60 * 60,
  "2y": 2 * 365 * 24 * 60 * 60,
  "3y": 3 * 365 * 24 * 60 * 60,
};

interface OnboardingFlowProps {
  onComplete: (storageLocation: StorageLocation) => void;
  addKey: (blob: ProtectedKeyBlob) => Promise<void>;
  /** Called when a newly generated key is cached in WASM. */
  onKeyCached?: (keyId: string, keyHandle: number) => void;
  /** Whether to cache decrypted keys in WASM after generation. */
  cacheKey?: boolean;
}

export function OnboardingFlow({ onComplete, addKey, onKeyCached, cacheKey }: OnboardingFlowProps) {
  const [step, setStep] = useState<Step>("storage");
  const [location, setLocation] = useState<StorageLocation>("local");

  const [method, setMethod] = useState(getDefaultProtectionMethod);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [masterCredentialId, setMasterCredentialId] = useState<
    string | undefined
  >();

  // Captured during master setup (passkey path) so we can hand it to
  // `generateAndProtect` and skip a second WebAuthn ceremony when the
  // user creates their first key. Lifetime: from master-setup success
  // until generate-key completes (success or fail). Always zeroed.
  const masterPrfRef = useRef<{
    prfOutput: Uint8Array;
    prfSalt: ArrayBuffer;
  } | null>(null);

  // Belt-and-braces: if the component unmounts mid-flow, zero the PRF.
  useEffect(() => {
    return () => {
      masterPrfRef.current?.prfOutput.fill(0);
      masterPrfRef.current = null;
    };
  }, []);

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [comment, setComment] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [keyAlgorithm, setKeyAlgorithm] = useState<KeyAlgorithm>("ecc");
  const [expiryOption, setExpiryOption] = useState<ExpiryOption>("2y");

  const handleProtectionSubmit = async () => {
    setError(null);

    if (method === "password") {
      const pwError = validatePassword(password, confirmPassword);
      if (pwError) {
        setError(pwError);
        return;
      }
    }

    setSubmitting(true);
    try {
      let mp: MasterProtection;

      if (method === "passkey") {
        const reg = await registerPasskey(
          "PGP Tools Master",
          "PGP Tools Master",
        );
        if (!reg.prfEnabled) {
          setError(
            "Your authenticator does not support PRF. Try a different passkey or use a password instead.",
          );
          setSubmitting(false);
          return;
        }

        const prfSalt = generatePrfSalt();
        const storedSecret = generateStoredSecret();
        const { prfOutput } = await authenticateAndGetPrf(
          reg.credentialId,
          prfSalt,
        );
        await wasmApi.initContactsSessionWithPrf(
          prfOutput,
          new Uint8Array(storedSecret),
        );

        // Keep the PRF output alive across the form-fill step so the
        // "create your first key" call below can reuse it without a
        // second WebAuthn dialog. Zeroed in handleGenerateKey's
        // finally + the unmount cleanup.
        masterPrfRef.current = { prfOutput, prfSalt };

        mp = {
          method: "passkey",
          credentialId: reg.credentialId,
          prfSalt: toBase64(prfSalt),
          storedSecret: toBase64(storedSecret),
        };

        setMasterCredentialId(reg.credentialId);
      } else {
        const salt = generateSalt();
        const passwordBytes = new TextEncoder().encode(password);
        try {
          const packed = await wasmApi.encryptCanaryAndInitSession(
            passwordBytes,
            new Uint8Array(salt),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
          );
          setConfirmPassword("");

          const { iv: canaryIv, ciphertext: canaryCtx } =
            unpackIvCiphertext(packed);

          mp = {
            method: "password",
            kdfSalt: toBase64(salt),
            encryptedCanary: toBase64(canaryCtx.buffer as ArrayBuffer),
            canaryIv: toBase64(canaryIv.buffer as ArrayBuffer),
          };
        } finally {
          passwordBytes.fill(0);
        }
      }

      await savePreferences({ storageLocation: location });
      await saveMasterProtection(mp);

      setStep("identity");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Setup failed");
    } finally {
      setSubmitting(false);
    }
  };

  const handleGenerateKey = async () => {
    setError(null);

    if (!name.trim()) {
      setError("Name is required.");
      return;
    }
    if (!email.trim()) {
      setError("Email is required.");
      return;
    }

    setStep("generating");

    try {
      const expiresIn = EXPIRY_SECONDS[expiryOption];
      const { blob, handle } = await generateAndProtect(
        {
          name: name.trim(),
          email: email.trim(),
          comment: comment.trim() || undefined,
          type: keyAlgorithm,
          expiresIn: expiresIn || undefined,
        },
        masterCredentialId
          ? {
              method: "passkey",
              reusePasskeyCredentialId: masterCredentialId,
              cache: cacheKey,
              prfReuse: masterPrfRef.current ?? undefined,
            }
          : { method: "password", password, cache: cacheKey },
      );

      await addKey(blob);
      if (handle !== undefined && onKeyCached) {
        onKeyCached(blob.keyId, handle);
      }
      setPassword("");
      await savePreferences({
        storageLocation: location,
        onboardingComplete: true,
      });
      onComplete(location);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Key generation failed");
      setStep("identity");
    } finally {
      masterPrfRef.current?.prfOutput.fill(0);
      masterPrfRef.current = null;
    }
  };

  const handleSkip = async () => {
    await savePreferences({
      storageLocation: location,
      onboardingComplete: true,
    });
    onComplete(location);
  };

  return (
    <div className="flex h-full flex-col justify-between p-4">
      {step === "storage" && (
        <>
          <div className="space-y-5">
            <div>
              <h1 className="text-lg font-semibold">PGP Tools</h1>
              <p className="text-muted-foreground mt-1 text-sm">
                Send private messages that only the right person can read, and
                verify messages really came from who they claim.
              </p>
            </div>

            <div>
              <h2 className="mb-2 text-sm font-semibold">
                Where should we store your data?
              </h2>
              <StorageLocationPicker value={location} onChange={setLocation} />
            </div>
          </div>

          <div className="space-y-2 pt-4">
            <Button className="w-full" onClick={() => setStep("protection")}>
              Next
            </Button>
            <p className="text-muted-foreground text-center text-xs">
              A privacy tool by{" "}
              <a
                href="https://amibeingpwned.com"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary underline"
              >
                Am I Being Pwned
              </a>
            </p>
          </div>
        </>
      )}

      {step === "protection" && (
        <div className="space-y-5">
          <div>
            <h2 className="text-lg font-semibold">Secure your data</h2>
            <p className="text-muted-foreground mt-1 text-sm">
              Choose how to protect your contacts and keys. You will use this
              each time you open PGP Tools.
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
            onSubmit={handleProtectionSubmit}
            onBack={() => {
              setStep("storage");
              setError(null);
            }}
            submitting={submitting}
            submitLabel={
              method === "passkey" ? "Create passkey" : "Set password"
            }
          />
        </div>
      )}

      {step === "identity" && (
        <>
          <div className="space-y-4">
            <div>
              <h2 className="text-lg font-semibold">Create your PGP key</h2>
              <p className="text-muted-foreground mt-1 text-sm">
                Create a keypair for encrypting, decrypting, and signing
                messages.
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
          </div>

          <div className="space-y-2 pt-4">
            <Button className="w-full" onClick={handleGenerateKey}>
              Create my PGP key
            </Button>
            <Button
              variant="outline"
              className="w-full"
              onClick={handleSkip}
            >
              I'll set up later
            </Button>
          </div>
        </>
      )}

      {step === "generating" && (
        <div className="flex flex-1 flex-col items-center justify-center py-6">
          <div className="bg-primary/10 mb-3 flex h-10 w-10 items-center justify-center rounded-full">
            <LoaderIcon className="text-primary h-5 w-5 animate-spin" />
          </div>
          <p className="text-muted-foreground text-sm">
            {masterCredentialId
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
    </div>
  );
}
