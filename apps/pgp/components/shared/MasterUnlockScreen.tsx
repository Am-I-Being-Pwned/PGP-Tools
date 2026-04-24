import { useEffect, useRef, useState } from "react";
import { LockIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import type { MasterProtection } from "../../lib/storage/master-protection";
import { fromBase64 } from "../../lib/encoding";
import * as wasmApi from "../../lib/pgp/wasm";
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
} from "../../lib/protection/password-kdf";
import { authenticateAndGetPrf } from "../../lib/protection/webauthn-prf";
import { INPUT_CLASS } from "../../lib/utils/styles";

interface MasterUnlockScreenProps {
  masterProtection: MasterProtection;
  onUnlocked: () => void;
  /** True when the lock was system-initiated (idle timer / visibility /
   *  OS idle). Suppresses the otherwise-automatic passkey prompt: a
   *  re-lock should not pop a passkey dialog without explicit user
   *  intent, both for UX (surprise dialogs) and security (an attacker
   *  with momentary screen access shouldn't get a passkey ceremony
   *  pre-launched for them). */
  autoLocked?: boolean;
}

export function MasterUnlockScreen({
  masterProtection,
  onUnlocked,
  autoLocked,
}: MasterUnlockScreenProps) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [unlocking, setUnlocking] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  useEffect(() => {
    if (autoLocked) return;
    if (masterProtection.method === "passkey") {
      void handlePasskeyUnlock();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handlePasskeyUnlock = async () => {
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
        new Uint8Array(fromBase64(masterProtection.storedSecret)),
      );
      onUnlocked();
    } catch (e) {
      if (ac.signal.aborted) return;
      const name = e instanceof Error ? e.name : "";
      if (name === "NotAllowedError" || name === "AbortError") {
        // User dismissed the passkey dialog.
      } else {
        setError("Passkey authentication failed. Try again.");
      }
    } finally {
      prfOutput?.fill(0);
    }
  };

  const handlePasswordUnlock = async () => {
    if (masterProtection.method !== "password") return;

    setError(null);
    setUnlocking(true);

    const passwordBytes = new TextEncoder().encode(password);
    try {
      // Single Argon2id pass: verifies canary + inits contacts session.
      const ok = await wasmApi.verifyCanaryAndInitSession(
        new Uint8Array(fromBase64(masterProtection.encryptedCanary)),
        new Uint8Array(fromBase64(masterProtection.canaryIv)),
        passwordBytes,
        new Uint8Array(fromBase64(masterProtection.kdfSalt)),
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
      );

      if (!ok) {
        setError("Wrong password.");
        // Drop the JS reference to the wrong-password string. Retries
        // build a new immutable string anyway; minimising heap lifetime.
        setPassword("");
        return;
      }
      setPassword("");
      onUnlocked();
    } catch {
      setError("Unlock failed. Try again.");
      setPassword("");
    } finally {
      passwordBytes.fill(0);
      setUnlocking(false);
    }
  };

  return (
    <div
      className="flex h-full flex-col items-center justify-center p-6"
      role="main"
      aria-label="Unlock PGP Tools"
    >
      <div className="w-full max-w-xs space-y-6 text-center">
        <div className="bg-primary/10 mx-auto flex h-14 w-14 items-center justify-center rounded-full">
          <LockIcon className="text-primary h-7 w-7" />
        </div>

        <div>
          <h1 className="text-lg font-semibold">PGP Tools</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            Your keys and contacts are encrypted. Authenticate to continue.
          </p>
        </div>

        {masterProtection.method === "passkey" && (
          <Button
            className="w-full"
            onClick={handlePasskeyUnlock}
            autoFocus
          >
            Unlock with passkey
          </Button>
        )}

        {masterProtection.method === "password" && (
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              void handlePasswordUnlock();
            }}
          >
            <input
              type="password"
              autoComplete="current-password"
              placeholder="Master password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={INPUT_CLASS}
              aria-label="Master password"
              autoFocus
            />
            <Button
              type="submit"
              className="w-full"
              disabled={unlocking || !password}
            >
              {unlocking ? "Unlocking..." : "Unlock"}
            </Button>
          </form>
        )}

        {error && (
          <p className="text-destructive text-xs" role="alert">
            {error}
          </p>
        )}

        <p className="text-muted-foreground text-xs">
          If you have lost your password, your encrypted keys and contacts cannot be
          recovered.
        </p>

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
    </div>
  );
}
