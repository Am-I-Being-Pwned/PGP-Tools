import { useEffect, useRef, useState } from "react";
import { LoaderIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui";

import {
  EMPTY_IDENTITY,
  identityUserId,
  KeyIdentityFields,
  type KeyAlgorithm,
} from "~/components/keys/KeyIdentityFields";
import { ProtectionMethodPicker } from "~/components/keys/ProtectionMethodPicker";
import { useProtectionChoice } from "~/components/keys/useProtectionChoice";
import { useAsyncAction } from "~/hooks";
import { toBase64, unpackIvCiphertext } from "~/lib/encoding";
import { presentError } from "~/lib/errors/present";
import { t } from "~/lib/i18n";
import {
  DEFAULT_EXPIRY,
  expiryToSeconds,
  type ExpiryOption,
} from "~/lib/keys/expiry";
import * as wasmApi from "~/lib/pgp/wasm";
import { PRESETS, type PresetId } from "~/lib/presets";
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  generateSalt,
} from "~/lib/protection/password-kdf";
import { generateAndProtect } from "~/lib/protection/protect-flow";
import {
  authenticateAndGetPrf,
  generatePrfSalt,
  generateStoredSecret,
  isWebAuthnCancel,
  registerPasskey,
} from "~/lib/protection/webauthn-prf";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import {
  masterProtectionIn,
  saveMasterProtection,
  VaultExistsError,
  type MasterProtection,
} from "~/lib/storage/master-protection";
import {
  savePreferences,
  type StorageLocation,
} from "~/lib/storage/preferences";
import { afterNextPaint } from "~/lib/utils/paint";
import { PresetPicker } from "./PresetPicker";
import { StorageLocationPicker } from "./StorageLocationPicker";

type Step = "storage" | "protection" | "identity" | "generating" | "preset";

interface OnboardingFlowProps {
  onComplete: (storageLocation: StorageLocation) => void;
  addKey: (blob: ProtectedKeyBlob) => Promise<void>;
  onKeyCached?: (keyId: string, keyHandle: number) => void;
  cacheKey?: boolean;
}

/** Paranoid pins never-cache, which rules out unlock-on-open. */
function presetPinsNeverCache(preset: PresetId | undefined): boolean {
  return preset !== undefined && PRESETS[preset].bundle.neverCacheKeys === true;
}

export function OnboardingFlow({
  onComplete,
  addKey,
  onKeyCached,
  cacheKey,
}: OnboardingFlowProps) {
  const [step, setStep] = useState<Step>("storage");
  const [location, setLocation] = useState<StorageLocation>("local");

  const choice = useProtectionChoice();
  const { method, password } = choice;
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  // Engine text never reaches the message (it lands in `detail`).
  const keygen = useAsyncAction(t("app_onboarding_generate_failed"));

  const [masterCredentialId, setMasterCredentialId] = useState<
    string | undefined
  >();

  // Master-setup PRF, reused for the first key to skip a second WebAuthn
  // ceremony. Always zeroed.
  const masterPrfRef = useRef<{
    prfOutput: Uint8Array;
    prfSalt: ArrayBuffer;
  } | null>(null);

  useEffect(() => {
    return () => {
      masterPrfRef.current?.prfOutput.fill(0);
      masterPrfRef.current = null;
    };
  }, []);

  // Abort the in-flight ceremony before a new one (InvalidStateError).
  const passkeyAbortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    passkeyAbortRef.current?.abort();
    passkeyAbortRef.current = null;
    setSubmitting(false);
    setError(null);
  }, [method]);

  useEffect(
    () => () => {
      passkeyAbortRef.current?.abort();
      passkeyAbortRef.current = null;
    },
    [],
  );

  const [identity, setIdentity] = useState(EMPTY_IDENTITY);
  const [keyAlgorithm, setKeyAlgorithm] = useState<KeyAlgorithm>("ecc");
  const [expiryOption, setExpiryOption] =
    useState<ExpiryOption>(DEFAULT_EXPIRY);
  const [presetChoice, setPresetChoice] = useState<PresetId>("careful");
  // Passkey path only: a password master has no PRF to reuse.
  const [unlockKeysOnOpen, setUnlockKeysOnOpen] = useState(false);

  const finishOnboarding = async (preset?: PresetId) => {
    if (preset) {
      // Never write storageLocation: the vault already lives where the
      // user picked, and flipping it without a migration strands it.
      const { storageLocation: _ignored, ...bundle } = PRESETS[preset].bundle;
      await savePreferences(bundle);
    }
    await savePreferences({
      storageLocation: location,
      onboardingComplete: true,
      // After the bundle so the tick wins; ignored for a preset that pins
      // never-cache.
      ...(unlockKeysOnOpen && !presetPinsNeverCache(preset)
        ? { unlockKeysOnOpen: true }
        : {}),
    });
    onComplete(location);
  };

  const handleProtectionSubmit = async () => {
    setError(null);

    const invalid = choice.validate();
    if (invalid) {
      setError(invalid);
      return;
    }

    // Never set up over an existing vault (another window may have made
    // one since): every key sealed under it would become unopenable.
    // Checked before anything is minted; `saveMasterProtection` backstops.
    if (
      (await masterProtectionIn("local")) ||
      (await masterProtectionIn("sync"))
    ) {
      setError(t("app_onboarding_vault_exists"));
      return;
    }

    setSubmitting(true);
    // Independent of the WebAuthn promise so an open dialog can't strand it.
    setTimeout(() => setSubmitting(false), 2000);

    passkeyAbortRef.current?.abort();
    const abort = new AbortController();
    passkeyAbortRef.current = abort;

    try {
      let mp: MasterProtection;

      if (method === "passkey") {
        const reg = await registerPasskey(
          "PGP Tools Master",
          "PGP Tools Master",
          abort.signal,
        );
        if (!reg.prfEnabled) {
          setError(t("app_onboarding_prf_unsupported"));
          setSubmitting(false);
          return;
        }

        const prfSalt = generatePrfSalt();
        const storedSecret = generateStoredSecret();
        const { prfOutput } = await authenticateAndGetPrf(
          reg.credentialId,
          prfSalt,
          abort.signal,
        );
        await wasmApi.initContactsSessionWithPrf(
          prfOutput,
          new Uint8Array(storedSecret),
        );

        // Kept for the first-key step; zeroed in handleGenerateKey + unmount.
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
          choice.clearConfirmation();

          const { iv: canaryIv, ciphertext: canaryCtx } =
            unpackIvCiphertext(packed);

          mp = {
            method: "password",
            kdfSalt: toBase64(salt),
            encryptedCanary: toBase64(canaryCtx),
            canaryIv: toBase64(canaryIv),
          };
        } finally {
          passwordBytes.fill(0);
        }
      }

      // Vault before location: a refusal (lost race) must leave the
      // location pointing at the vault that exists.
      await saveMasterProtection(mp, location);
      await savePreferences({ storageLocation: location });

      setStep("identity");
    } catch (e) {
      if (isWebAuthnCancel(e)) {
        setError(null);
      } else if (e instanceof VaultExistsError) {
        // Lost the race: drop the session minted for no stored vault.
        void wasmApi.dropContactsSession().catch(() => undefined);
        setError(t("app_onboarding_vault_exists"));
      } else {
        setError(presentError(e, t("app_onboarding_setup_failed")).message);
      }
    } finally {
      passkeyAbortRef.current = null;
      // setSubmitting(false) is owned by the 2s timeout above.
    }
  };

  const handleGenerateKey = async () => {
    if (!identity.name.trim()) {
      keygen.setError(t("app_onboarding_name_required"));
      return;
    }
    const failed = await keygen.run(async () => {
      setStep("generating");
      // Let "Generating…" paint before the wasm call holds the thread.
      await afterNextPaint();
      try {
        const expiresIn = expiryToSeconds(expiryOption, undefined);
        const { blob, handle } = await generateAndProtect(
          {
            ...identityUserId(identity),
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
        choice.clear();
        setStep("preset");
      } finally {
        masterPrfRef.current?.prfOutput.fill(0);
        masterPrfRef.current = null;
      }
    });
    if (failed) setStep("identity");
  };

  const handleSkip = () => {
    setStep("preset");
  };

  return (
    <div className="flex flex-col p-4">
      {step === "storage" && (
        <>
          <div className="space-y-5">
            <div>
              {/* i18n-ignore */}
              <h1 className="text-lg font-semibold">PGP Tools</h1>
              <p className="text-muted-foreground mt-1 text-sm">
                {t("app_onboarding_intro_body")}
              </p>
            </div>

            <div>
              <h2 className="mb-2 text-sm font-semibold">
                {t("app_onboarding_storage_question")}
              </h2>
              <StorageLocationPicker value={location} onChange={setLocation} />
            </div>
          </div>

          <div className="pt-4">
            <Button className="w-full" onClick={() => setStep("protection")}>
              {t("app_onboarding_next")}
            </Button>
          </div>
        </>
      )}

      {step === "protection" && (
        <div className="space-y-5">
          <div>
            <h2 className="text-lg font-semibold">
              {t("app_onboarding_protection_title")}
            </h2>
            <p className="text-muted-foreground mt-1 text-sm">
              {t("app_onboarding_protection_body")}
            </p>
          </div>

          <ProtectionMethodPicker
            {...choice.pickerProps}
            error={error}
            onSubmit={handleProtectionSubmit}
            onBack={() => {
              setStep("storage");
              setError(null);
            }}
            submitting={submitting}
            submitLabel={
              method === "passkey"
                ? t("app_onboarding_create_passkey")
                : t("app_onboarding_set_password")
            }
          />
        </div>
      )}

      {step === "identity" && (
        <>
          <div className="space-y-4">
            <div>
              <h2 className="text-lg font-semibold">
                {t("app_onboarding_identity_title")}
              </h2>
              <p className="text-muted-foreground mt-1 text-sm">
                {t("app_onboarding_identity_body")}
              </p>
            </div>

            <KeyIdentityFields
              identity={identity}
              onIdentityChange={setIdentity}
              algorithm={keyAlgorithm}
              onAlgorithmChange={setKeyAlgorithm}
              expiry={expiryOption}
              onExpiryChange={setExpiryOption}
            />

            {keygen.error && (
              <p className="text-bad text-xs" role="alert">
                {keygen.error.message}
              </p>
            )}
          </div>

          <div className="space-y-2 pt-4">
            <Button className="w-full" onClick={() => void handleGenerateKey()}>
              {t("app_onboarding_create_key")}
            </Button>
            <Button variant="outline" className="w-full" onClick={handleSkip}>
              {t("app_onboarding_skip")}
            </Button>
          </div>
        </>
      )}

      {step === "generating" && (
        <div className="flex flex-1 flex-col items-center justify-center py-6">
          <div className="bg-card text-good mb-3 flex size-12 items-center justify-center rounded-xl">
            <LoaderIcon className="size-5 animate-spin" />
          </div>
          <p className="text-muted-foreground text-sm">
            {masterCredentialId
              ? t("app_onboarding_passkey_prompt")
              : t("app_onboarding_generating")}
          </p>
          {keyAlgorithm === "rsa" && (
            <p className="text-muted-foreground/60 mt-1 text-xs">
              {t("app_onboarding_rsa_slow")}
            </p>
          )}
        </div>
      )}

      {step === "preset" && (
        <>
          <div className="space-y-4">
            <div>
              <h2 className="text-lg font-semibold">
                {t("app_onboarding_preset_title")}
              </h2>
              <p className="text-muted-foreground mt-1 text-sm">
                {t("app_onboarding_preset_body")}
              </p>
            </div>

            <PresetPicker selected={presetChoice} onSelect={setPresetChoice} />

            {masterCredentialId && !presetPinsNeverCache(presetChoice) && (
              <label className="bg-card flex cursor-pointer items-start gap-3 rounded-xl p-3 text-sm">
                <input
                  type="checkbox"
                  className="mt-0.5"
                  checked={unlockKeysOnOpen}
                  onChange={(e) => setUnlockKeysOnOpen(e.target.checked)}
                />
                <span>
                  {t("app_onboarding_unlock_with_vault")}
                  <span className="text-muted-foreground block text-xs">
                    {t("app_onboarding_unlock_with_vault_hint")}
                  </span>
                </span>
              </label>
            )}
          </div>

          <div className="space-y-2 pt-4">
            <Button
              className="w-full"
              onClick={() => void finishOnboarding(presetChoice)}
            >
              {t("app_onboarding_use_preset")}
            </Button>
            <Button
              variant="outline"
              className="w-full"
              onClick={() => void finishOnboarding()}
            >
              {t("app_onboarding_keep_defaults")}
            </Button>
          </div>
        </>
      )}
    </div>
  );
}
