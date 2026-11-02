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

/** Pluggable crypto: PGP keys use the live session handle, CRX keys a
 *  transient one opened by the page's unlock gate. */
export interface PrivateKeyExporter {
  title: string;
  isPasskey: boolean;
  needsUnlock: boolean;
  /** Throws on a wrong password (CRX) or a since-locked key (PGP). */
  acquire: (password?: string) => Promise<number>;
  /** PGP: no-op, the session owns its handle. */
  release: (handle: number) => void;
  exportEncrypted: (handle: number, passphrase: string) => Promise<string>;
  exportPlaintext: (handle: number) => Promise<string>;
  encryptedBlurb: string;
  encryptedButton: string;
  plaintextBlurb: string;
  plaintextButton: string;
  unlockBlurb?: string;
}

interface ExportPrivateKeyPageProps {
  onClose: () => void;
  exporter: PrivateKeyExporter;
}

/**
 * "Copy private key". The key stays on the clipboard and in any clipboard
 * history; nothing is wiped (T-CLIPBOARD-EXFIL). A gate-opened handle is
 * dropped on unmount.
 */
export function ExportPrivateKeyPage({
  onClose,
  exporter,
}: ExportPrivateKeyPageProps) {
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

  // A late unlock into an unmounted page drops its handle.
  const unmounted = useRef(false);
  useEffect(() => {
    return () => {
      unmounted.current = true;
      if (handleRef.current !== null) exporter.release(handleRef.current);
    };
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

  const runExport = (
    producer: (h: number) => Promise<string>,
    successMsg: string,
    afterSuccess: () => void,
  ) =>
    exporting.run(async () => {
      let acquired: number | null = null;
      let h = handle;
      // Acquire's message is controlled; everything after is crypto: keep generic.
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
