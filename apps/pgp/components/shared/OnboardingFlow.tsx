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

import type { PresetId } from "../../lib/presets";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { MasterProtection } from "../../lib/storage/master-protection";
import type { StorageLocation } from "../../lib/storage/preferences";
import { toBase64, unpackIvCiphertext } from "../../lib/encoding";
import { t, tn } from "../../lib/i18n";
import * as wasmApi from "../../lib/pgp/wasm";
import { PRESETS } from "../../lib/presets";
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
  isWebAuthnCancel,
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
import { PresetPicker } from "./PresetPicker";
import { StorageLocationPicker } from "./StorageLocationPicker";

type Step = "storage" | "protection" | "identity" | "generating" | "preset";
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

/** Whether picking `preset` turns never-cache on (Paranoid does), which
 *  rules out unlock-on-open. `undefined` is "Keep the defaults". */
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

  // Zero the PRF if the component unmounts before generate-key
  // consumes it.
  useEffect(() => {
    return () => {
      masterPrfRef.current?.prfOutput.fill(0);
      masterPrfRef.current = null;
    };
  }, []);

  // Cancels an in-flight WebAuthn ceremony before issuing a new one
  // (or on method-switch / unmount), so re-clicks can't trip
  // `InvalidStateError: A request is already pending.`
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

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [comment, setComment] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [keyAlgorithm, setKeyAlgorithm] = useState<KeyAlgorithm>("ecc");
  const [expiryOption, setExpiryOption] = useState<ExpiryOption>("2y");
  const [presetChoice, setPresetChoice] = useState<PresetId>("careful");
  // "Unlock keys with the vault": off by default, offered only on the
  // passkey path (a password master has no PRF output to reuse). The
  // first key was sealed under the master salt by `prfReuse` above, so
  // opting in here needs no migration.
  const [unlockKeysOnOpen, setUnlockKeysOnOpen] = useState(false);

  /** Final onboarding step: optionally apply a preset bundle, then
   *  persist completion and hand off to the app. */
  const finishOnboarding = async (preset?: PresetId) => {
    if (preset) {
      // Never write the bundle's storageLocation here: the user picked
      // theirs in step 1 and the vault blobs already live there, so
      // flipping the pointer without a migration would strand them.
      // The preset simply reads as "Custom" if the locations differ.
      const { storageLocation: _ignored, ...bundle } = PRESETS[preset].bundle;
      await savePreferences(bundle);
    }
    await savePreferences({
      storageLocation: location,
      onboardingComplete: true,
      // After the bundle, so the tick wins over a preset that leaves the
      // field alone. The checkbox is hidden (and its state ignored) for
      // a preset that turns never-cache on -- the two are opposites.
      ...(unlockKeysOnOpen && !presetPinsNeverCache(preset)
        ? { unlockKeysOnOpen: true }
        : {}),
    });
    onComplete(location);
  };

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
    // The button re-enables after 2s independent of the WebAuthn
    // promise so a still-open system dialog can't strand it.
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
            encryptedCanary: toBase64(canaryCtx),
            canaryIv: toBase64(canaryIv),
          };
        } finally {
          passwordBytes.fill(0);
        }
      }

      await savePreferences({ storageLocation: location });
      await saveMasterProtection(mp);

      setStep("identity");
    } catch (e) {
      if (isWebAuthnCancel(e)) {
        setError(null);
      } else {
        setError(
          e instanceof Error ? e.message : t("app_onboarding_setup_failed"),
        );
      }
    } finally {
      passkeyAbortRef.current = null;
      // setSubmitting(false) is owned by the 2s timeout above.
    }
  };

  const handleGenerateKey = async () => {
    setError(null);

    if (!name.trim()) {
      setError(t("app_onboarding_name_required"));
      return;
    }

    setStep("generating");

    try {
      const expiresIn = EXPIRY_SECONDS[expiryOption];
      const { blob, handle } = await generateAndProtect(
        {
          name: name.trim(),
          email: email.trim() || undefined,
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
      setStep("preset");
    } catch (e) {
      setError(
        e instanceof Error ? e.message : t("app_onboarding_generate_failed"),
      );
      setStep("identity");
    } finally {
      masterPrfRef.current?.prfOutput.fill(0);
      masterPrfRef.current = null;
    }
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

            <div className="space-y-2">
              <div>
                <label className="text-muted-foreground mb-1 block text-xs">
                  {t("app_onboarding_name_label")}
                </label>
                <input
                  type="text"
                  placeholder={t("app_onboarding_name_placeholder")}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className={INPUT_CLASS}
                />
              </div>
              <div>
                <label className="text-muted-foreground mb-1 block text-xs">
                  {t("app_onboarding_email_label")}{" "}
                  <span className="text-muted-foreground/60">
                    {t("app_onboarding_optional")}
                  </span>
                </label>
                <input
                  type="email"
                  placeholder={t("app_onboarding_email_placeholder")}
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className={INPUT_CLASS}
                />
              </div>
              <div>
                <label className="text-muted-foreground mb-1 block text-xs">
                  {t("app_onboarding_comment_label")}{" "}
                  <span className="text-muted-foreground/60">
                    {t("app_onboarding_optional")}
                  </span>
                </label>
                <input
                  type="text"
                  placeholder={t("app_onboarding_comment_placeholder")}
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
              {t("app_onboarding_advanced_options")}
            </button>

            {showAdvanced && (
              <div className="border-border space-y-3 rounded-md border p-3">
                <div>
                  <label className="text-muted-foreground mb-1.5 block text-xs">
                    {t("app_onboarding_algorithm_label")}
                  </label>
                  <Select
                    value={keyAlgorithm}
                    onValueChange={(v) => setKeyAlgorithm(v as KeyAlgorithm)}
                  >
                    <SelectTrigger className="h-8 text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {/* i18n-ignore */}
                      <SelectItem value="ecc">ECC (Ed25519)</SelectItem>
                      <SelectItem value="rsa">RSA</SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-muted-foreground/60 mt-1 text-[10px]">
                    {keyAlgorithm === "ecc"
                      ? t("app_onboarding_algo_ecc_hint")
                      : t("app_onboarding_algo_rsa_hint")}
                  </p>
                </div>

                <div>
                  <label className="text-muted-foreground mb-1.5 block text-xs">
                    {t("app_onboarding_expiry_label")}
                  </label>
                  <Select
                    value={expiryOption}
                    onValueChange={(v) => setExpiryOption(v as ExpiryOption)}
                  >
                    <SelectTrigger className="h-8 text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="never">
                        {t("app_onboarding_expiry_never")}
                      </SelectItem>
                      <SelectItem value="1y">
                        {tn("app_onboarding_expiry_years", 1)}
                      </SelectItem>
                      <SelectItem value="2y">
                        {tn("app_onboarding_expiry_years", 2)}
                      </SelectItem>
                      <SelectItem value="3y">
                        {tn("app_onboarding_expiry_years", 3)}
                      </SelectItem>
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
          <div className="bg-primary/10 mb-3 flex h-10 w-10 items-center justify-center rounded-full">
            <LoaderIcon className="text-primary h-5 w-5 animate-spin" />
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
              <label className="flex cursor-pointer items-start gap-3 text-sm">
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
