import { useState } from "react";
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
}

export function MasterUnlockScreen({
  masterProtection,
  onUnlocked,
}: MasterUnlockScreenProps) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [unlocking, setUnlocking] = useState(false);

  const handlePasskeyUnlock = async () => {
    if (masterProtection.method !== "passkey") return;
    setError(null);
    setUnlocking(true);

    try {
      const { prfOutput } = await authenticateAndGetPrf(
        masterProtection.credentialId,
        fromBase64(masterProtection.prfSalt),
      );

      await wasmApi.initContactsSessionWithPrf(
        prfOutput,
        new Uint8Array(fromBase64(masterProtection.storedSecret)),
      );
      prfOutput.fill(0);
      onUnlocked();
    } catch {
      setError("Passkey authentication failed. Try again.");
    } finally {
      setUnlocking(false);
    }
  };

  const handlePasswordUnlock = async () => {
    if (masterProtection.method !== "password") return;
    setError(null);
    setUnlocking(true);

    const passwordBytes = new TextEncoder().encode(password);
    try {
      const ok = await wasmApi.verifyCanary(
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
        return;
      }

      await wasmApi.initContactsSessionWithPassword(
        passwordBytes,
        new Uint8Array(fromBase64(masterProtection.kdfSalt)),
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
      );
      onUnlocked();
    } catch {
      setError("Unlock failed. Try again.");
    } finally {
      passwordBytes.fill(0);
      setUnlocking(false);
    }
  };

  return (
    <div className="flex h-full flex-col items-center justify-center p-6">
      <div className="w-full max-w-xs space-y-6 text-center">
        <div className="bg-primary/10 mx-auto flex h-14 w-14 items-center justify-center rounded-full">
          <LockIcon className="text-primary h-7 w-7" />
        </div>

        <div>
          <h1 className="text-lg font-semibold">PGP Tools</h1>
          <p className="text-muted-foreground mt-1 text-sm">
            {masterProtection.method === "passkey"
              ? "Tap your passkey to unlock."
              : "Enter your password to unlock."}
          </p>
        </div>

        {masterProtection.method === "passkey" && (
          <Button
            className="w-full"
            onClick={handlePasskeyUnlock}
            disabled={unlocking}
          >
            {unlocking ? "Authenticating..." : "Unlock with passkey"}
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
              placeholder="Master password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className={INPUT_CLASS}
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

        {error && <p className="text-destructive text-xs">{error}</p>}

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
