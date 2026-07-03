import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@amibeingpwned/ui/button";

import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import {
  encryptKeyForExportWithHandle,
  getKeyArmored,
} from "../../lib/pgp/wasm";
import { downloadText } from "../../lib/utils/download";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { Dialog } from "../shared/Dialog";

interface ExportAllKeysDialogProps {
  open: boolean;
  onClose: () => void;
  myKeys: ProtectedKeyBlob[];
  contacts: PublicContactKey[];
  isUnlocked: (keyId: string) => boolean;
  getKeyHandle: (keyId: string) => number | null;
}

function backupFileName(): string {
  return `pgp-tools-keys-${new Date().toISOString().slice(0, 10)}.asc`;
}

/**
 * Bulk export: every contact's public key plus every *unlocked* private
 * key, concatenated into one armored file. Same trust pattern as the
 * per-key export in KeyCard: private keys are re-encrypted under a
 * user-chosen passphrase by default; a plaintext export exists but is
 * gated behind a type-to-confirm.
 */
export function ExportAllKeysDialog({
  open,
  onClose,
  myKeys,
  contacts,
  isUnlocked,
  getKeyHandle,
}: ExportAllKeysDialogProps) {
  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [unsafeConfirm, setUnsafeConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  const unlockedKeys = myKeys.filter((k) => isUnlocked(k.keyId));
  const lockedKeys = myKeys.filter((k) => !isUnlocked(k.keyId));
  const hasPrivate = unlockedKeys.length > 0;
  const hasAnything = hasPrivate || contacts.length > 0;

  const resetAndClose = () => {
    setPassphrase("");
    setConfirmPassphrase("");
    setUnsafeConfirm("");
    setError(null);
    onClose();
  };

  /** Build the armored bundle. `privateArmor` renders each unlocked
   *  private key; contacts are appended as-is (public data). */
  const buildAndDownload = async (
    privateArmor: (handle: number) => Promise<string>,
  ) => {
    const parts: string[] = [];
    for (const key of unlockedKeys) {
      const handle = getKeyHandle(key.keyId);
      if (handle === null) continue; // locked since the dialog rendered
      parts.push((await privateArmor(handle)).trim());
    }
    for (const contact of contacts) {
      parts.push(contact.armoredPublicKey.trim());
    }
    downloadText(parts.join("\n\n") + "\n", backupFileName());
    return parts.length;
  };

  const handleEncryptedExport = async () => {
    setError(null);
    if (hasPrivate) {
      if (passphrase.length < 8) {
        setError("Passphrase must be at least 8 characters.");
        return;
      }
      if (passphrase !== confirmPassphrase) {
        setError("Passphrases do not match.");
        return;
      }
    }
    setExporting(true);
    const passphraseBytes = new TextEncoder().encode(passphrase);
    try {
      const count = await buildAndDownload((handle) =>
        encryptKeyForExportWithHandle(handle, passphraseBytes),
      );
      toast.success(`Exported ${count} key${count === 1 ? "" : "s"}`);
      resetAndClose();
    } catch {
      setError("Export failed.");
    } finally {
      passphraseBytes.fill(0);
      setExporting(false);
    }
  };

  const handleUnsafeExport = async () => {
    setError(null);
    setExporting(true);
    try {
      const count = await buildAndDownload(getKeyArmored);
      toast.success(
        `Exported ${count} key${count === 1 ? "" : "s"} (private keys UNENCRYPTED)`,
      );
      resetAndClose();
    } catch {
      setError("Export failed.");
    } finally {
      setExporting(false);
    }
  };

  return (
    <Dialog open={open} onClose={resetAndClose} title="Export All Keys">
      <div className="space-y-3">
        <p className="text-muted-foreground text-xs">
          Downloads a single armored file with{" "}
          {contacts.length > 0
            ? `your ${contacts.length} contact${contacts.length === 1 ? "" : "s"}' public keys`
            : "your contacts' public keys"}{" "}
          and your unlocked private keys ({unlockedKeys.length} of{" "}
          {myKeys.length} unlocked).
        </p>

        {lockedKeys.length > 0 && (
          <p className="rounded border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-700 dark:text-amber-400">
            Locked keys can't be exported:{" "}
            {lockedKeys
              .map((k) => k.userIds[0] ?? k.keyId.slice(-8))
              .join(", ")}
            . Unlock them in the Keys tab first to include them.
          </p>
        )}

        {!hasAnything && (
          <p className="text-muted-foreground text-xs">Nothing to export.</p>
        )}

        {hasAnything && !hasPrivate && (
          <Button
            className="w-full"
            onClick={() => void handleEncryptedExport()}
            disabled={exporting}
          >
            {exporting ? "Exporting..." : "Export public keys"}
          </Button>
        )}

        {hasPrivate && (
          <>
            <p className="text-muted-foreground text-xs">
              Set a passphrase to encrypt the exported private keys. Anyone with
              this passphrase and the file can decrypt your messages and sign as
              you.
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
          </>
        )}

        {error && <p className="text-destructive text-xs">{error}</p>}

        {hasPrivate && (
          <>
            <Button
              className="w-full"
              onClick={() => void handleEncryptedExport()}
              disabled={exporting || !passphrase}
            >
              {exporting ? "Exporting..." : "Export with passphrase"}
            </Button>
            <div className="border-border space-y-2 border-t pt-3">
              <p className="text-destructive text-[11px]">
                Plaintext export. Anyone who reads the downloaded file gets full
                control of every key in it. Type{" "}
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
                onClick={() => void handleUnsafeExport()}
              >
                Export without passphrase (unsafe)
              </Button>
            </div>
          </>
        )}
      </div>
    </Dialog>
  );
}
