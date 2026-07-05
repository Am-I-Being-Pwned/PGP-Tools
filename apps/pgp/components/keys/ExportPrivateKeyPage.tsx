import { useEffect, useRef, useState } from "react";

import { Button } from "@amibeingpwned/ui/button";

import { isWebAuthnCancel } from "../../lib/protection/webauthn-prf";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { SubPage } from "../shared/SubPage";

/**
 * Pluggable crypto for {@link ExportPrivateKeyPage}. The page is pure UI +
 * clipboard lifecycle; the exporter supplies the WASM handlers so the same
 * page serves both PGP private keys (already unlocked in the session) and CRX
 * signing keys (sealed at rest, unlocked transiently inside the page).
 */
export interface PrivateKeyExporter {
  title: string;
  isPasskey: boolean;
  /** true ⇒ the page shows an unlock gate first and holds the handle it
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

interface ExportPrivateKeyPageProps {
  /** Called after the slide-out finishes (parent unmounts the page). */
  onClose: () => void;
  exporter: PrivateKeyExporter;
}

/**
 * Unified "copy private key" flow for PGP and CRX keys: an optional unlock gate
 * (CRX), then a passphrase-encrypted copy or a type-`EXPORT` plaintext escape
 * hatch. Both paths write to the clipboard and schedule a best-effort wipe --
 * 60s for the encrypted blob, 30s for the higher-impact plaintext key. A CRX
 * handle opened by the gate is dropped on unmount.
 */
export function ExportPrivateKeyPage({
  onClose,
  exporter,
}: ExportPrivateKeyPageProps) {
  // Handle held for the page's life in gated (CRX) mode. In un-gated (PGP)
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

  // True once the page has unmounted, so an unlock still in flight can detect
  // it resolved into a dead page and drop its handle rather than leave it
  // lingering in WASM untracked.
  const unmounted = useRef(false);

  // Drop a held handle on unmount and cancel the feedback timer. The
  // clipboard-wipe timer deliberately survives unmount: the whole point of
  // copying is to close this page and paste elsewhere, so the wipe must
  // still fire at its scheduled deadline -- not be cancelled (key material
  // would linger in the clipboard forever) and not fire early (the paste
  // window would vanish). Its callback touches only the clipboard, never
  // React state. If the side panel itself closes, the JS context -- and
  // with it the clipboard copy's source -- dies anyway.
  useEffect(() => {
    return () => {
      unmounted.current = true;
      if (handleRef.current !== null) exporter.release(handleRef.current);
      clearTimeout(feedbackTimer.current);
    };
    // exporter is captured per-mount; releasing the latest handle is all we need.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleUnlock = async () => {
    if (unlockInFlight.current || handleRef.current !== null) return;
    unlockInFlight.current = true;
    setUnlockError(null);
    setUnlocking(true);
    try {
      const h = await exporter.acquire(isPasskey ? undefined : password);
      // The page unmounted while this unlock was in flight: the handle now
      // belongs to nobody, so drop it instead of storing it.
      if (unmounted.current) {
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
    <SubPage title={exporter.title} onClose={onClose}>
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
    </SubPage>
  );
}
