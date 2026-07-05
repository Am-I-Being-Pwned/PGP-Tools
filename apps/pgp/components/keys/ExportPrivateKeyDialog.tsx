import { useEffect, useRef, useState } from "react";

import { Button } from "@amibeingpwned/ui/button";

import { isWebAuthnCancel } from "../../lib/protection/webauthn-prf";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { Dialog } from "../shared/Dialog";

/**
 * Pluggable crypto for {@link ExportPrivateKeyDialog}. The dialog is pure UI +
 * clipboard lifecycle; the exporter supplies the WASM handlers so the same
 * dialog serves both PGP private keys (already unlocked in the session) and CRX
 * signing keys (sealed at rest, unlocked transiently inside the dialog).
 */
export interface PrivateKeyExporter {
  title: string;
  isPasskey: boolean;
  /** true ⇒ the dialog shows an unlock gate first and holds the handle it
   *  opens (CRX). false ⇒ no gate; a live handle is acquired+released around
   *  each export (PGP session handle). */
  needsUnlock: boolean;
  /** Acquire a usable WASM handle. CRX opens a transient handle from the
   *  password/passkey (throws on wrong password); PGP returns the live session
   *  handle (throws if the key has since locked). */
  acquire: (password?: string) => Promise<number>;
  /** Release a handle from {@link acquire}. CRX drops the transient handle; PGP
   *  is a no-op (the session owns its handle). */
  release: (handle: number) => void;
  exportEncrypted: (handle: number, passphrase: string) => Promise<string>;
  exportPlaintext: (handle: number) => Promise<string>;
  /** Muted copy above the passphrase inputs. */
  encryptedBlurb: string;
  encryptedButton: string;
  /** Red warning line above the type-EXPORT confirm. */
  plaintextBlurb: string;
  plaintextButton: string;
  /** CRX-only: copy shown on the unlock gate. */
  unlockBlurb?: string;
}

interface ExportPrivateKeyDialogProps {
  open: boolean;
  onClose: () => void;
  exporter: PrivateKeyExporter;
}

/**
 * Unified "copy private key" flow for PGP and CRX keys: an optional unlock gate
 * (CRX), then a passphrase-encrypted copy or a type-`EXPORT` plaintext escape
 * hatch. Both paths write to the clipboard and schedule a best-effort wipe --
 * 60s for the encrypted blob, 30s for the higher-impact plaintext key. A CRX
 * handle opened by the gate is dropped on close and on unmount.
 */
export function ExportPrivateKeyDialog({
  open,
  onClose,
  exporter,
}: ExportPrivateKeyDialogProps) {
  // Handle held for the dialog's life in gated (CRX) mode. In un-gated (PGP)
  // mode this stays null and a fresh handle is acquired per export action.
  const [handle, setHandle] = useState<number | null>(null);
  const handleRef = useRef<number | null>(null);
  useEffect(() => {
    handleRef.current = handle;
  }, [handle]);

  const [password, setPassword] = useState("");
  const [unlocking, setUnlocking] = useState(false);
  const [unlockError, setUnlockError] = useState<string | null>(null);
  // Synchronous in-flight guard: `unlocking` lands a render late, so rapid
  // clicks / Enter-spam could open two handles and leak the first (setHandle
  // keeps only the second). This ref blocks the second call now.
  const unlockInFlight = useRef(false);

  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [unsafeConfirm, setUnsafeConfirm] = useState("");
  const [exportError, setExportError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);
  const feedbackTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const clipboardClearTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  const { isPasskey, needsUnlock } = exporter;
  // The unlock gate only exists in gated mode and only until we hold a handle.
  const showGate = needsUnlock && handle === null;

  /** Best-effort clipboard wipe after `delayMs`. We can't read the clipboard
   *  to know if the user has since copied something else (no permission), so
   *  the wipe is unconditional -- acceptable to avoid leaving key material. */
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

  // Drop a held handle if the dialog unmounts without a clean close, and cancel
  // both timers so neither fires after we're gone (a stray clipboard wipe would
  // clobber whatever the user copied next).
  useEffect(() => {
    return () => {
      if (handleRef.current !== null) exporter.release(handleRef.current);
      clearTimeout(feedbackTimer.current);
      clearTimeout(clipboardClearTimer.current);
    };
    // exporter is captured per-open; releasing the latest handle is all we need.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Bumped on every reset so an unlock still in flight when the dialog closes
  // can detect it resolved into a closed dialog and drop its handle rather than
  // leave it lingering in WASM untracked.
  const openGen = useRef(0);

  const reset = () => {
    openGen.current++;
    if (handleRef.current !== null) {
      exporter.release(handleRef.current);
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

  const handleUnlock = async () => {
    if (unlockInFlight.current || handleRef.current !== null) return;
    unlockInFlight.current = true;
    const gen = openGen.current;
    setUnlockError(null);
    setUnlocking(true);
    try {
      const h = await exporter.acquire(isPasskey ? undefined : password);
      // The dialog was closed/reset while this unlock was in flight: the handle
      // now belongs to nobody, so drop it instead of storing it.
      if (gen !== openGen.current) {
        exporter.release(h);
        return;
      }
      setHandle(h);
      setPassword("");
    } catch (e) {
      if (isPasskey) {
        if (!isWebAuthnCancel(e)) {
          setUnlockError("Passkey authentication failed.");
        }
      } else {
        setUnlockError("Wrong password.");
      }
    } finally {
      unlockInFlight.current = false;
      setUnlocking(false);
    }
  };

  /** Run `producer` against a handle, copy the result, and clear the clipboard
   *  after `clearMs`. In gated mode the held handle is reused; otherwise a fresh
   *  handle is acquired and released around this single action. */
  const runExport = async (
    producer: (h: number) => Promise<string>,
    successMsg: string,
    clearMs: number,
    afterSuccess: () => void,
  ) => {
    setExportError(null);
    setExporting(true);
    let acquired: number | null = null;
    let h = handle;
    // Acquire (PGP session handle) can fail with a controlled, safe message
    // (e.g. "Key is not unlocked."); surface it. Everything after is crypto,
    // whose errors may carry WASM context -- keep those generic (SECURITY.md).
    if (h === null) {
      try {
        h = await exporter.acquire();
        acquired = h;
      } catch (e) {
        setExportError(
          e instanceof Error && e.message ? e.message : "Key is not unlocked.",
        );
        setExporting(false);
        return;
      }
    }
    try {
      const text = await producer(h);
      await navigator.clipboard.writeText(text);
      scheduleClipboardClear(clearMs);
      showFeedback(successMsg);
      afterSuccess();
    } catch {
      setExportError("Export failed.");
    } finally {
      if (acquired !== null) exporter.release(acquired);
      setExporting(false);
    }
  };

  const handleEncryptedExport = async () => {
    setExportError(null);
    if (passphrase.length < 8) {
      setExportError("Passphrase must be at least 8 characters.");
      return;
    }
    if (passphrase !== confirmPassphrase) {
      setExportError("Passphrases do not match.");
      return;
    }
    await runExport(
      (h) => exporter.exportEncrypted(h, passphrase),
      "Encrypted key copied (clears in 60s)",
      60_000,
      () => {
        setPassphrase("");
        setConfirmPassphrase("");
      },
    );
  };

  const handlePlaintextExport = () =>
    runExport(
      (h) => exporter.exportPlaintext(h),
      "Unprotected key copied (clears in 30s)",
      30_000,
      () => setUnsafeConfirm(""),
    );

  return (
    <Dialog open={open} onClose={handleClose} title={exporter.title}>
      {showGate ? (
        <div className="space-y-3">
          <p className="text-muted-foreground text-xs">
            {exporter.unlockBlurb ??
              (isPasskey
                ? "Authenticate with your passkey to copy this key."
                : "Enter the key password to copy this key.")}
          </p>
          {!isPasskey && (
            <input
              type="password"
              autoComplete="current-password"
              placeholder="Key password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void handleUnlock();
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
            onClick={() => void handleUnlock()}
            disabled={unlocking || (!isPasskey && !password)}
          >
            {unlocking ? "Unlocking..." : "Unlock"}
          </Button>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-muted-foreground text-xs">
            {exporter.encryptedBlurb}
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
              if (e.key === "Enter") void handleEncryptedExport();
            }}
            className={INPUT_CLASS}
          />
          {exportError && (
            <p className="text-destructive text-xs">{exportError}</p>
          )}
          {feedback && <p className="text-xs text-green-400">{feedback}</p>}
          <Button
            className="w-full"
            onClick={() => void handleEncryptedExport()}
            disabled={exporting || !passphrase}
          >
            {exporting ? "Encrypting..." : exporter.encryptedButton}
          </Button>

          <div className="border-border space-y-2 border-t pt-3">
            <p className="text-destructive text-[11px]">
              {exporter.plaintextBlurb} Type{" "}
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
              onClick={() => void handlePlaintextExport()}
            >
              {exporter.plaintextButton}
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  );
}
