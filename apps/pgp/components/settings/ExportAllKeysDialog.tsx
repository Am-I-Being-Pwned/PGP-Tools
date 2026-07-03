import { useEffect, useState } from "react";
import { CheckIcon, LockIcon } from "lucide-react";
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

type Step = "unlock" | "export";

interface ExportAllKeysDialogProps {
  open: boolean;
  onClose: () => void;
  myKeys: ProtectedKeyBlob[];
  contacts: PublicContactKey[];
  isUnlocked: (keyId: string) => boolean;
  getKeyHandle: (keyId: string) => number | null;
  onUnlockWithPassword: (
    blob: ProtectedKeyBlob,
    password: string,
  ) => Promise<boolean>;
  onUnlockWithPasskey: (
    blob: ProtectedKeyBlob,
  ) => Promise<boolean | "cancelled">;
}

function backupFileName(): string {
  return `pgp-tools-keys-${new Date().toISOString().slice(0, 10)}.asc`;
}

/**
 * Bulk export of EVERYTHING: every private key plus every contact's
 * public key, in one armored `.asc` file.
 *
 * Exporting a private key needs its decrypted WASM handle, so any locked
 * key must be unlocked first (password / passkey) -- same requirement as
 * the per-key "Copy private key" flow, just applied to the whole set.
 *
 * Output format: standard ASCII-armored OpenPGP. Private keys are
 * `PGP PRIVATE KEY BLOCK`s, re-encrypted under the passphrase you set
 * (OpenPGP S2K -- identical to GnuPG, imports anywhere) or written
 * unencrypted via the type-to-confirm path. Contacts are
 * `PGP PUBLIC KEY BLOCK`s.
 */
export function ExportAllKeysDialog({
  open,
  onClose,
  myKeys,
  contacts,
  isUnlocked,
  getKeyHandle,
  onUnlockWithPassword,
  onUnlockWithPasskey,
}: ExportAllKeysDialogProps) {
  const [step, setStep] = useState<Step>("unlock");
  const [passwords, setPasswords] = useState<Record<string, string>>({});
  const [unlockErrors, setUnlockErrors] = useState<Record<string, string>>({});
  const [unlockingId, setUnlockingId] = useState<string | null>(null);

  const [passphrase, setPassphrase] = useState("");
  const [confirmPassphrase, setConfirmPassphrase] = useState("");
  const [unsafeConfirm, setUnsafeConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  const lockedKeys = myKeys.filter((k) => !isUnlocked(k.keyId));
  const unlockedKeys = myKeys.filter((k) => isUnlocked(k.keyId));
  const allUnlocked = lockedKeys.length === 0;
  // Gate the passphrase UI on what will actually be written -- if the
  // user skips every locked key, this becomes a public-only export.
  const hasPrivate = unlockedKeys.length > 0;

  // On open, land on the unlock step only if something is still locked.
  useEffect(() => {
    if (open) setStep(allUnlocked ? "export" : "unlock");
    // Intentionally keyed on `open` only: once inside the dialog the user
    // drives the step; unlocking the last key advances it (below).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // Advance to the export step the moment the last key is unlocked.
  useEffect(() => {
    if (open && step === "unlock" && allUnlocked) setStep("export");
  }, [open, step, allUnlocked]);

  const resetAndClose = () => {
    setStep("unlock");
    setPasswords({});
    setUnlockErrors({});
    setUnlockingId(null);
    setPassphrase("");
    setConfirmPassphrase("");
    setUnsafeConfirm("");
    setError(null);
    onClose();
  };

  const handleUnlockPassword = async (blob: ProtectedKeyBlob) => {
    setUnlockingId(blob.keyId);
    setUnlockErrors((e) => ({ ...e, [blob.keyId]: "" }));
    try {
      const ok = await onUnlockWithPassword(blob, passwords[blob.keyId] ?? "");
      if (!ok) {
        setUnlockErrors((e) => ({ ...e, [blob.keyId]: "Wrong password." }));
      } else {
        setPasswords((p) => ({ ...p, [blob.keyId]: "" }));
      }
    } finally {
      setUnlockingId(null);
    }
  };

  const handleUnlockPasskey = async (blob: ProtectedKeyBlob) => {
    setUnlockingId(blob.keyId);
    setUnlockErrors((e) => ({ ...e, [blob.keyId]: "" }));
    try {
      const res = await onUnlockWithPasskey(blob);
      if (res !== true && res !== "cancelled") {
        setUnlockErrors((e) => ({
          ...e,
          [blob.keyId]: "Passkey authentication failed.",
        }));
      }
    } finally {
      setUnlockingId(null);
    }
  };

  /** Build the armored bundle from the now-unlocked keys + contacts.
   *  `privateArmor` renders each private key (encrypted or plaintext). */
  const buildAndDownload = async (
    privateArmor: (handle: number) => Promise<string>,
  ) => {
    const parts: string[] = [];
    for (const key of myKeys) {
      const handle = getKeyHandle(key.keyId);
      if (handle === null) continue; // re-locked mid-flight; shouldn't happen
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
      {step === "unlock" ? (
        <div className="space-y-3">
          <p className="text-muted-foreground text-xs">
            Exporting a private key requires unlocking it first. Unlock the keys
            below to include them in the backup.
          </p>

          <div className="space-y-2">
            {myKeys.map((blob) => {
              const unlocked = isUnlocked(blob.keyId);
              const name = blob.userIds[0] ?? blob.keyId.slice(-16);
              const isPasskey = blob.protection.method === "passkey";
              const busy = unlockingId === blob.keyId;
              return (
                <div
                  key={blob.keyId}
                  className="border-border rounded-md border p-2"
                >
                  <div className="flex items-center gap-2">
                    <span
                      className={
                        unlocked ? "text-green-400" : "text-muted-foreground"
                      }
                    >
                      {unlocked ? (
                        <CheckIcon className="h-4 w-4" />
                      ) : (
                        <LockIcon className="h-4 w-4" />
                      )}
                    </span>
                    <span className="min-w-0 flex-1 truncate text-sm">
                      {name}
                    </span>
                    {!unlocked && isPasskey && (
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={busy}
                        onClick={() => void handleUnlockPasskey(blob)}
                      >
                        {busy ? "..." : "Unlock"}
                      </Button>
                    )}
                  </div>

                  {!unlocked && !isPasskey && (
                    <div className="mt-2 flex items-stretch gap-2">
                      <input
                        type="password"
                        autoComplete="current-password"
                        placeholder="Key password"
                        value={passwords[blob.keyId] ?? ""}
                        onChange={(e) =>
                          setPasswords((p) => ({
                            ...p,
                            [blob.keyId]: e.target.value,
                          }))
                        }
                        onKeyDown={(e) => {
                          if (e.key === "Enter")
                            void handleUnlockPassword(blob);
                        }}
                        className={`${INPUT_CLASS} h-9 flex-1 py-0`}
                      />
                      <Button
                        size="sm"
                        className="h-9 shrink-0"
                        disabled={busy || !(passwords[blob.keyId] ?? "")}
                        onClick={() => void handleUnlockPassword(blob)}
                      >
                        {busy ? "..." : "Unlock"}
                      </Button>
                    </div>
                  )}

                  {unlockErrors[blob.keyId] && (
                    <p className="text-destructive mt-1 text-xs">
                      {unlockErrors[blob.keyId]}
                    </p>
                  )}
                </div>
              );
            })}
          </div>

          {contacts.length > 0 && (
            <p className="text-muted-foreground text-xs">
              {contacts.length} contact{contacts.length === 1 ? "" : "s"} will
              also be included (public keys, no unlock needed).
            </p>
          )}

          <Button
            variant="outline"
            className="w-full"
            onClick={() => setStep("export")}
          >
            {myKeys.length === 0 ? "Continue" : "Skip locked keys and continue"}
          </Button>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-muted-foreground text-xs">
            Downloads one <span className="font-mono">.asc</span> file (standard
            ASCII-armored OpenPGP): your {unlockedKeys.length} unlocked private
            key{unlockedKeys.length === 1 ? "" : "s"} as{" "}
            <span className="font-mono">PGP PRIVATE KEY BLOCK</span>s and your{" "}
            {contacts.length} contact{contacts.length === 1 ? "" : "s"} as{" "}
            <span className="font-mono">PGP PUBLIC KEY BLOCK</span>s.
          </p>

          {lockedKeys.length > 0 && (
            <p className="rounded border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-700 dark:text-amber-400">
              {lockedKeys.length} key{lockedKeys.length === 1 ? "" : "s"} still
              locked and will be left out.{" "}
              <button
                type="button"
                className="underline"
                onClick={() => setStep("unlock")}
              >
                Go back to unlock
              </button>
              .
            </p>
          )}

          {hasPrivate ? (
            <>
              <p className="text-muted-foreground text-xs">
                Set a passphrase to encrypt the exported private keys (OpenPGP
                S2K -- imports into GnuPG and other tools). Anyone with this
                passphrase and the file can decrypt your messages and sign as
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
              {error && <p className="text-destructive text-xs">{error}</p>}
              <Button
                className="w-full"
                onClick={() => void handleEncryptedExport()}
                disabled={exporting || !passphrase}
              >
                {exporting ? "Exporting..." : "Export with passphrase"}
              </Button>

              <div className="border-border space-y-2 border-t pt-3">
                <p className="text-destructive text-[11px]">
                  Plaintext export. Anyone who reads the downloaded file gets
                  full control of every key in it. Type{" "}
                  <span className="font-mono font-bold">EXPORT</span> to
                  confirm:
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
          ) : contacts.length > 0 ? (
            <>
              {error && <p className="text-destructive text-xs">{error}</p>}
              <Button
                className="w-full"
                onClick={() => void handleEncryptedExport()}
                disabled={exporting}
              >
                {exporting ? "Exporting..." : "Export public keys"}
              </Button>
            </>
          ) : (
            <p className="text-muted-foreground text-xs">Nothing to export.</p>
          )}
        </div>
      )}
    </Dialog>
  );
}
