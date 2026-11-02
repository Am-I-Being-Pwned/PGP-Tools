import { useEffect, useRef, useState } from "react";

import { Button } from "@amibeingpwned/ui/button";
import { Input } from "@amibeingpwned/ui/input";

import { useAsyncAction } from "../../hooks/useAsyncAction";
import { useCopyToClipboard } from "../../hooks/useCopyToClipboard";
import { useFlashMessage } from "../../hooks/useFlashMessage";
import { t } from "../../lib/i18n";
import { isWebAuthnCancel } from "../../lib/protection/webauthn-prf";
import { SubPage } from "../shared/SubPage";
import {
  ExportPassphraseFields,
  useExportPassphrase,
} from "./ExportPassphraseFields";

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
 * "Copy private key" for PGP and CRX keys: an optional unlock gate (CRX),
 * then a passphrase-encrypted copy or a type-`EXPORT` plaintext escape
 * hatch. The key stays on the clipboard and in any clipboard history --
 * nothing is wiped (T-CLIPBOARD-EXFIL). A gate-opened handle is dropped
 * on unmount.
 */
export function ExportPrivateKeyPage({
  onClose,
  exporter,
}: ExportPrivateKeyPageProps) {
  // Gated (CRX) mode holds one handle for the page's life; un-gated (PGP)
  // acquires per export.
  const [handle, setHandle] = useState<number | null>(null);
  const handleRef = useRef<number | null>(null);
  useEffect(() => {
    handleRef.current = handle;
  }, [handle]);

  const { isPasskey, needsUnlock } = exporter;
  const [password, setPassword] = useState("");
  // Generic copy only: the engine's unlock error says nothing safe.
  const unlock = useAsyncAction((e) =>
    isPasskey
      ? isWebAuthnCancel(e)
        ? null
        : { message: t("keygen_error_passkey_failed") }
      : { message: t("keygen_error_wrong_password") },
  );
  const exporting = useAsyncAction(() => ({
    message: t("keygen_export_failed"),
  }));
  const fields = useExportPassphrase();
  const [feedback, flash] = useFlashMessage();
  const { copy } = useCopyToClipboard();

  const showGate = needsUnlock && handle === null;

  // An unlock that resolves into an unmounted page drops its handle
  // rather than leave it live in WASM untracked.
  const unmounted = useRef(false);
  useEffect(() => {
    return () => {
      unmounted.current = true;
      if (handleRef.current !== null) exporter.release(handleRef.current);
    };
    // exporter is captured per-mount; releasing the latest handle is all we need.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // The in-flight guard matters: two opens would leak the first handle.
  const handleUnlock = () =>
    unlock.run(async () => {
      if (handleRef.current !== null) return;
      const h = await exporter.acquire(isPasskey ? undefined : password);
      if (unmounted.current) {
        exporter.release(h);
        return;
      }
      setHandle(h);
      setPassword("");
    });

  /** Run `producer` against a handle and copy the result: the held one
   *  (gated) or one acquired and released around this action. */
  const runExport = (
    producer: (h: number) => Promise<string>,
    successMsg: string,
    afterSuccess: () => void,
  ) =>
    exporting.run(async () => {
      let acquired: number | null = null;
      let h = handle;
      // Acquire fails with a controlled message ("Key is not unlocked.");
      // show it. Everything after is crypto: keep that generic.
      if (h === null) {
        try {
          h = await exporter.acquire();
          acquired = h;
        } catch (e) {
          exporting.setError(
            e instanceof Error && e.message
              ? e.message
              : t("keygen_error_key_not_unlocked"),
          );
          return;
        }
      }
      try {
        const text = await producer(h);
        // No label: the inline feedback is the success UI. A rejected
        // write has already toasted.
        if (await copy(text, { sensitive: true })) {
          flash(successMsg);
          afterSuccess();
        }
      } finally {
        if (acquired !== null) exporter.release(acquired);
      }
    });

  const handleEncryptedExport = () => {
    const invalid = fields.validate();
    if (invalid) {
      exporting.setError(invalid);
      return;
    }
    void runExport(
      (h) => exporter.exportEncrypted(h, fields.passphrase),
      t("keygen_copied_encrypted"),
      fields.clearPassphrase,
    );
  };

  const handlePlaintextExport = () =>
    void runExport(
      (h) => exporter.exportPlaintext(h),
      t("keygen_copied_plaintext"),
      fields.clearUnsafeConfirm,
    );

  return (
    <SubPage title={exporter.title} onClose={onClose}>
      {showGate ? (
        <div className="space-y-3">
          <p className="text-muted-foreground text-xs">
            {exporter.unlockBlurb ??
              (isPasskey
                ? t("keygen_unlock_gate_passkey")
                : t("keygen_unlock_gate_password"))}
          </p>
          {!isPasskey && (
            <Input
              type="password"
              autoComplete="current-password"
              placeholder={t("keygen_key_password_placeholder")}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void handleUnlock();
              }}
              autoFocus
            />
          )}
          {unlock.error && (
            <p className="text-destructive text-xs">{unlock.error.message}</p>
          )}
          <Button
            className="w-full"
            onClick={() => void handleUnlock()}
            disabled={unlock.busy || (!isPasskey && !password)}
          >
            {unlock.busy ? t("keygen_unlocking") : t("common_unlock")}
          </Button>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-muted-foreground text-xs">
            {exporter.encryptedBlurb}
          </p>
          <ExportPassphraseFields
            fields={fields}
            error={exporting.error?.message}
            feedback={feedback}
            busy={exporting.busy}
            submitLabel={exporter.encryptedButton}
            busyLabel={t("keygen_encrypting")}
            onSubmit={handleEncryptedExport}
            plaintext={{
              warning: exporter.plaintextBlurb,
              button: exporter.plaintextButton,
              onExport: handlePlaintextExport,
            }}
          />
        </div>
      )}
    </SubPage>
  );
}
