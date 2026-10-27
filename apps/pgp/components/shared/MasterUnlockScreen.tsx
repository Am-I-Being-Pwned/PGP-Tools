import { useEffect, useRef, useState } from "react";
import { LockIcon } from "lucide-react";

import { Block, BlockStack } from "@amibeingpwned/ui/block";
import { Button } from "@amibeingpwned/ui/button";

import type { MasterProtection } from "../../lib/storage/master-protection";
import type { StorageLocation } from "../../lib/storage/preferences";
import { fromBase64 } from "../../lib/encoding";
import { t } from "../../lib/i18n";
import * as wasmApi from "../../lib/pgp/wasm";
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
} from "../../lib/protection/password-kdf";
import { authenticateAndGetPrf } from "../../lib/protection/webauthn-prf";
import { DevToolsPage } from "../settings/DevToolsPage";

/** The passkey ceremony's PRF output, on loan to `onUnlocked` for the
 *  duration of that call so "unlock keys when the vault unlocks" can open
 *  the keys sealed under the master salt off the same ceremony. */
export interface MasterPrfLoan {
  prfOutput: Uint8Array;
}

interface MasterUnlockScreenProps {
  masterProtection: MasterProtection;
  /** The vault session is live. On the passkey path `prf` carries the
   *  ceremony's PRF output; it is valid only until the returned promise
   *  settles (this screen zeroes it in a `finally`), so a consumer must
   *  await everything it does with it and keep no reference. Absent on
   *  the password path. */
  onUnlocked: (prf?: MasterPrfLoan) => void | Promise<void>;
  /** True when the lock was system-initiated (idle timer / visibility /
   *  OS idle). Suppresses the otherwise-automatic passkey prompt: a
   *  re-lock should not pop a passkey dialog without explicit user
   *  intent, both for UX (surprise dialogs) and security (an attacker
   *  with momentary screen access shouldn't get a passkey ceremony
   *  pre-launched for them). */
  autoLocked?: boolean;
  /** The OTHER storage area also holds a master protection. Offered once
   *  an unlock has failed: this device's record of where its vault lives
   *  may be what was tampered with (`lib/storage/vault-state.ts`). */
  alternate?: StorageLocation;
  onUseAlternate?: () => void | Promise<void>;
}

export function MasterUnlockScreen({
  masterProtection,
  onUnlocked,
  autoLocked,
  alternate,
  onUseAlternate,
}: MasterUnlockScreenProps) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [unlocking, setUnlocking] = useState(false);
  const [showDevTools, setShowDevTools] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  // Auto-prompt, but only once the panel HAS focus. Chrome gives a side
  // panel focus when it is shown (crbug 486495151), a moment after the
  // page loads; prompting before that anchors the WebAuthn dialog to
  // whatever was focused before -- the web page -- and Chrome hands focus
  // back THERE when the dialog closes, so the user unlocks and still has
  // to click into the panel. Browsers without that fix never focus the
  // panel on their own, so after a short wait it prompts regardless, as
  // it always did.
  useEffect(() => {
    if (autoLocked) return;
    if (masterProtection.method !== "passkey") return;
    let started = false;
    const start = () => {
      if (started) return;
      started = true;
      window.removeEventListener("focus", start);
      clearTimeout(fallback);
      void handlePasskeyUnlock();
    };
    const fallback = setTimeout(start, 1_000);
    if (document.hasFocus()) start();
    else window.addEventListener("focus", start);
    return () => {
      window.removeEventListener("focus", start);
      clearTimeout(fallback);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Function declaration (hoisted) so the auto-unlock effect above can
  // reference it without a use-before-declaration error.
  async function handlePasskeyUnlock() {
    if (masterProtection.method !== "passkey") return;

    // Abort any in-flight ceremony so we don't get InvalidStateError
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;

    setError(null);

    let prfOutput: Uint8Array | undefined;
    try {
      ({ prfOutput } = await authenticateAndGetPrf(
        masterProtection.credentialId,
        fromBase64(masterProtection.prfSalt),
        ac.signal,
      ));

      await wasmApi.initContactsSessionWithPrf(
        prfOutput,
        fromBase64(masterProtection.storedSecret),
      );
      // Loaned, not handed over: the `finally` below zeroes it once the
      // consumer's promise settles. A consumer that throws lands in the
      // catch below and shows a generic error, but the session is live
      // by then -- App's handler owns its own failure modes and does not
      // throw for a key that will not open.
      await onUnlocked({ prfOutput });
    } catch (e) {
      if (ac.signal.aborted) return;
      const name = e instanceof Error ? e.name : "";
      if (name === "NotAllowedError" || name === "AbortError") {
        // User dismissed the passkey dialog.
      } else {
        setError(t("shared_passkey_failed"));
      }
    } finally {
      prfOutput?.fill(0);
    }
  }

  const handlePasswordUnlock = async () => {
    if (masterProtection.method !== "password") return;

    setError(null);
    setUnlocking(true);

    const passwordBytes = new TextEncoder().encode(password);
    try {
      // Single Argon2id pass: verifies canary + inits contacts session.
      const ok = await wasmApi.verifyCanaryAndInitSession(
        fromBase64(masterProtection.encryptedCanary),
        fromBase64(masterProtection.canaryIv),
        passwordBytes,
        fromBase64(masterProtection.kdfSalt),
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
      );

      if (!ok) {
        setError(t("shared_wrong_password"));
        // Drop the JS reference to the wrong-password string. Retries
        // build a new immutable string anyway; minimising heap lifetime.
        setPassword("");
        return;
      }
      setPassword("");
      await onUnlocked();
    } catch {
      setError(t("shared_unlock_failed"));
      setPassword("");
    } finally {
      passwordBytes.fill(0);
      setUnlocking(false);
    }
  };

  return (
    <div
      className="flex h-full flex-col items-center justify-center px-4 py-6"
      role="main"
      aria-label={t("shared_unlock_aria")}
    >
      {/* One column, centred as a group: who this is, the one field, the
          one action -- the card language of the rest of the panel rather
          than a hero floating far above a strip of controls. */}
      <div className="w-full max-w-sm space-y-5">
        <div className="flex items-center gap-3">
          <div className="bg-card text-good flex size-11 shrink-0 items-center justify-center rounded-xl">
            <LockIcon className="size-5" aria-hidden="true" />
          </div>
          <div className="min-w-0">
            {/* i18n-ignore */}
            <h1 className="text-base font-semibold tracking-tight">
              PGP Tools
            </h1>
            <p className="text-muted-foreground text-xs">
              {t("shared_unlock_intro")}
            </p>
          </div>
        </div>

        {masterProtection.method === "passkey" && (
          <Button
            size="lg"
            className="w-full"
            onClick={handlePasskeyUnlock}
            autoFocus
          >
            {t("shared_unlock_with_passkey")}
          </Button>
        )}

        {masterProtection.method === "password" && (
          <form
            className="space-y-2"
            onSubmit={(e) => {
              e.preventDefault();
              void handlePasswordUnlock();
            }}
          >
            <BlockStack>
              <Block className="flex items-center gap-3 pl-3 focus-within:shadow-[inset_0_0_0_1px_rgb(79_193_133/0.35)]">
                <label
                  htmlFor="master-password"
                  className="text-muted-foreground shrink-0 text-xs font-medium"
                >
                  {t("shared_master_password")}
                </label>
                <input
                  id="master-password"
                  type="password"
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="h-11 min-w-0 flex-1 bg-transparent pr-3 text-sm outline-none"
                  autoFocus
                />
              </Block>
            </BlockStack>
            <Button
              type="submit"
              size="lg"
              className="w-full"
              disabled={unlocking || !password}
            >
              {unlocking ? t("shared_unlocking") : t("common_unlock")}
            </Button>
          </form>
        )}

        {error && (
          <p className="text-bad px-1 text-xs" role="alert">
            {error}
          </p>
        )}

        {error && alternate && onUseAlternate && (
          <p className="text-muted-foreground px-1 text-xs">
            {alternate === "sync"
              ? t("app_vault_alternate_sync")
              : t("app_vault_alternate_local")}{" "}
            <button
              type="button"
              onClick={() => void onUseAlternate()}
              className="hover:text-foreground underline transition-colors"
            >
              {t("app_vault_alternate_use")}
            </button>
          </p>
        )}

        <p className="text-muted-foreground px-1 text-xs">
          {t("shared_unlock_lost_password")}
        </p>

        {import.meta.env.DEV && (
          <button
            type="button"
            onClick={() => setShowDevTools(true)}
            className="text-muted-foreground hover:text-foreground px-1 text-[10px] underline transition-colors"
          >
            {t("shared_dev_tools")}
          </button>
        )}
      </div>

      {import.meta.env.DEV && showDevTools && (
        <DevToolsPage onClose={() => setShowDevTools(false)} />
      )}
    </div>
  );
}
