import { useEffect, useRef, useState } from "react";

import { Button } from "@amibeingpwned/ui/button";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import { serializeCrxKeyBlocks } from "../../lib/crx/backup";
import {
  closeCrxKey,
  exportCrxPrivateKeyPem,
  openCrxKey,
  resealCrxKeyUnderPassword,
} from "../../lib/crx/operations";
import { isWebAuthnCancel } from "../../lib/protection/webauthn-prf";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { Dialog } from "../shared/Dialog";

interface CrxExportPrivateDialogProps {
  open: boolean;
  onClose: () => void;
  keyBlob: CrxSigningKeyBlob;
}

/**
 * "Copy private key" for a CRX signing key -- the parity of {@link KeyCard}'s
 * private-key export, adapted to CRX. A CRX key has no persistent unlocked
 * session (it's sealed at rest and unlocked only for an action), so this
 * dialog unlocks it inline into a WASM handle, then offers the same two
 * exports as PGP: encrypted (re-sealed under an export passphrase, as a
 * portable `PGP TOOLS CRX SIGNING KEY` block you can re-import) or plaintext
 * (the raw PKCS#8 PEM, behind a type-EXPORT confirm -- for openssl / Google's
 * CLI). The handle is dropped on close and on unmount.
 */
export function CrxExportPrivateDialog({
  open,
  onClose,
  keyBlob,
}: CrxExportPrivateDialogProps) {
  const [handle, setHandle] = useState<number | null>(null);
  const handleRef = useRef<number | null>(null);
  useEffect(() => {
    handleRef.current = handle;
  }, [handle]);

  const [password, setPassword] = useState("");
  const [unlocking, setUnlocking] = useState(false);
  const [unlockError, setUnlockError] = useState<string | null>(null);
  // Synchronous in-flight guard: the `unlocking` state updates a render late,
  // so two rapid clicks / Enter-spam could open two handles and leak the first
  // (setHandle keeps only the second). This ref blocks the second call now.
  const unlockInFlight = useRef(false);

  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [unsafeConfirm, setUnsafeConfirm] = useState("");
  const [exportError, setExportError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const feedbackTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const clipboardClearTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  const isPasskey = keyBlob.protection.method === "passkey";

  /** Best-effort clipboard wipe after `delayMs` (see KeyCard for rationale). */
  const scheduleClipboardClear = (delayMs = 60_000) => {
    if (clipboardClearTimer.current) clearTimeout(clipboardClearTimer.current);
    clipboardClearTimer.current = setTimeout(() => {
      void navigator.clipboard.writeText("").catch(() => {
        /* clipboard API may have been revoked; nothing to do */
      });
    }, delayMs);
  };

  const showFeedback = (msg: string) => {
    setFeedback(msg);
    clearTimeout(feedbackTimer.current);
    feedbackTimer.current = setTimeout(() => setFeedback(null), 2000);
  };

  // Drop the handle if the dialog unmounts without a clean close, and cancel
  // both pending timers so neither fires after we're gone (a stray clipboard
  // wipe would clobber whatever the user copied next -- matches KeyCard).
  useEffect(() => {
    return () => {
      if (handleRef.current !== null) void closeCrxKey(handleRef.current);
      clearTimeout(feedbackTimer.current);
      clearTimeout(clipboardClearTimer.current);
    };
  }, []);

  const reset = () => {
    if (handleRef.current !== null) {
      void closeCrxKey(handleRef.current);
      handleRef.current = null;
    }
    setHandle(null);
    setPassword("");
    setUnlocking(false);
    setUnlockError(null);
    setPassphrase("");
    setConfirmPassphrase("");
    setUnsafeConfirm("");
    setExportError(null);
    setExporting(false);
  };

  const handleClose = () => {
    reset();
    onClose();
  };

  const handleUnlockPassword = async () => {
    if (unlockInFlight.current || handleRef.current !== null) return;
    unlockInFlight.current = true;
    setUnlockError(null);
    setUnlocking(true);
    try {
      const h = await openCrxKey(keyBlob, password);
      setHandle(h);
      setPassword("");
    } catch {
      setUnlockError("Wrong password.");
    } finally {
      unlockInFlight.current = false;
      setUnlocking(false);
    }
  };

  const handleUnlockPasskey = async () => {
    if (unlockInFlight.current || handleRef.current !== null) return;
    unlockInFlight.current = true;
    setUnlockError(null);
    setUnlocking(true);
    try {
      const h = await openCrxKey(keyBlob);
      setHandle(h);
    } catch (e) {
      if (!isWebAuthnCancel(e)) {
        setUnlockError("Passkey authentication failed.");
      }
    } finally {
      unlockInFlight.current = false;
      setUnlocking(false);
    }
  };

  const handleEncryptedCopy = async () => {
    if (handle === null) return;
    setExportError(null);
    if (passphrase.length < 8) {
      setExportError("Passphrase must be at least 8 characters.");
      return;
    }
    if (passphrase !== confirmPassphrase) {
      setExportError("Passphrases do not match.");
      return;
    }
    setExporting(true);
    try {
      const portable = await resealCrxKeyUnderPassword(
        handle,
        passphrase,
        keyBlob.label,
      );
      await navigator.clipboard.writeText(serializeCrxKeyBlocks([portable]));
      scheduleClipboardClear();
      showFeedback("Encrypted key copied (clears in 60s)");
      setPassphrase("");
      setConfirmPassphrase("");
    } catch {
      setExportError("Export failed.");
    } finally {
      setExporting(false);
    }
  };

  const handlePlaintextCopy = async () => {
    if (handle === null) return;
    setExportError(null);
    setExporting(true);
    try {
      const pem = await exportCrxPrivateKeyPem(handle);
      await navigator.clipboard.writeText(pem);
      // Plaintext key on the clipboard is high-impact; clear faster.
      scheduleClipboardClear(30_000);
      showFeedback("Unprotected key copied (clears in 30s)");
      setUnsafeConfirm("");
    } catch {
      setExportError("Export failed.");
    } finally {
      setExporting(false);
    }
  };

  return (
    <Dialog open={open} onClose={handleClose} title="Copy CRX private key">
      {handle === null ? (
        <div className="space-y-3">
          <p className="text-muted-foreground text-xs">
            Unlock this signing key to copy it.{" "}
            {isPasskey
              ? "Authenticate with your passkey."
              : "Enter the key password."}
          </p>
          {!isPasskey && (
            <input
              type="password"
              autoComplete="current-password"
              placeholder="Key password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void handleUnlockPassword();
              }}
              className={INPUT_CLASS}
              autoFocus
            />
          )}
          {unlockError && (
            <p className="text-destructive text-xs">{unlockError}</p>
          )}
          <Button
            className="w-full"
            onClick={() =>
              void (isPasskey ? handleUnlockPasskey() : handleUnlockPassword())
            }
            disabled={unlocking || (!isPasskey && !password)}
          >
            {unlocking ? "Unlocking..." : "Unlock"}
          </Button>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-muted-foreground text-xs">
            Set a passphrase to encrypt the copied key (re-importable into PGP
            Tools via Import Keys). Anyone with this passphrase and the copied
            block can sign extensions as you.
          </p>
          <input
            type="password"
            autoComplete="new-password"
            placeholder="Passphrase (min 8 characters)"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            className={INPUT_CLASS}
            autoFocus
          />
          <input
            type="password"
            autoComplete="new-password"
            placeholder="Confirm passphrase"
            value={confirmPassphrase}
            onChange={(e) => setConfirmPassphrase(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void handleEncryptedCopy();
            }}
            className={INPUT_CLASS}
          />
          {exportError && (
            <p className="text-destructive text-xs">{exportError}</p>
          )}
          {feedback && <p className="text-xs text-green-400">{feedback}</p>}
          <Button
            className="w-full"
            onClick={() => void handleEncryptedCopy()}
            disabled={exporting || !passphrase}
          >
            {exporting ? "Encrypting..." : "Copy with passphrase"}
          </Button>

          <div className="border-border space-y-2 border-t pt-3">
            <p className="text-destructive text-[11px]">
              Plaintext export (raw PKCS#8 PEM). Anyone who reads your clipboard
              gets full control of this signing key. Type{" "}
              <span className="font-mono font-bold">EXPORT</span> to confirm:
            </p>
            <input
              type="text"
              autoComplete="off"
              spellCheck={false}
              value={unsafeConfirm}
              onChange={(e) => setUnsafeConfirm(e.target.value)}
              placeholder="EXPORT"
              className={INPUT_CLASS}
            />
            <Button
              variant="destructive"
              size="sm"
              className="w-full"
              disabled={exporting || unsafeConfirm !== "EXPORT"}
              onClick={() => void handlePlaintextCopy()}
            >
              Copy without passphrase (unsafe)
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  );
}
