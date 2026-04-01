import { useState } from "react";

import { Button } from "@amibeingpwned/ui/button";

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
import {
  authenticateAndGetPrf,
  generatePrfSalt,
  generateStoredSecret,
  registerPasskey,
} from "../../lib/protection/webauthn-prf";
import { saveMasterProtection } from "../../lib/storage/master-protection";
import { savePreferences } from "../../lib/storage/preferences";
import {
  getDefaultProtectionMethod,
  ProtectionMethodPicker,
  validatePassword,
} from "../keys/ProtectionMethodPicker";
import { StorageLocationPicker } from "./StorageLocationPicker";

type Step = "storage" | "protection" | "identity";

interface OnboardingFlowProps {
  onComplete: (storageLocation: StorageLocation) => void;
  onGenerateKey: () => void;
}

export function OnboardingFlow({
  onComplete,
  onGenerateKey,
}: OnboardingFlowProps) {
  const [step, setStep] = useState<Step>("storage");
  const [location, setLocation] = useState<StorageLocation>("local");

  const [method, setMethod] = useState(getDefaultProtectionMethod);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

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
        let prfOutput: Uint8Array | undefined;
        try {
          ({ prfOutput } = await authenticateAndGetPrf(
            reg.credentialId,
            prfSalt,
          ));

          await wasmApi.initContactsSessionWithPrf(
            prfOutput,
            new Uint8Array(storedSecret),
          );
        } finally {
          prfOutput?.fill(0);
        }

        mp = {
          method: "passkey",
          credentialId: reg.credentialId,
          prfSalt: toBase64(prfSalt),
          storedSecret: toBase64(storedSecret),
        };
      } else {
        const salt = generateSalt();
        const passwordBytes = new TextEncoder().encode(password);
        try {
          // Single Argon2id pass: encrypts canary + inits contacts session.
          const packed = await wasmApi.encryptCanaryAndInitSession(
            passwordBytes,
            new Uint8Array(salt),
            ARGON2_MEMORY_KIB,
            ARGON2_ITERATIONS,
            ARGON2_PARALLELISM,
          );
          setPassword("");
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

      // Save storage location first (engine needs it for routing)
      await savePreferences({ storageLocation: location });
      await saveMasterProtection(mp);

      setStep("identity");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Setup failed");
    } finally {
      setSubmitting(false);
    }
  };

  const finish = async (generateKey: boolean) => {
    await savePreferences({
      storageLocation: location,
      onboardingComplete: true,
    });
    onComplete(location);
    if (generateKey) setTimeout(onGenerateKey, 100);
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
          <div className="space-y-5">
            <div>
              <h2 className="text-lg font-semibold">You are all set</h2>
              <p className="text-muted-foreground mt-1 text-sm">
                Your data is now protected. Create a PGP keypair to start
                encrypting and signing messages, or set up later.
              </p>
            </div>
          </div>

          <div className="space-y-2 pt-4">
            <Button className="w-full" onClick={() => finish(true)}>
              Create my PGP key
            </Button>
            <Button
              variant="outline"
              className="w-full"
              onClick={() => finish(false)}
            >
              I'll set up later
            </Button>
          </div>
        </>
      )}
    </div>
  );
}
