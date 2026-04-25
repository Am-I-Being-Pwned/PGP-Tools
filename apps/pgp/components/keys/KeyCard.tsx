import { useEffect, useRef, useState } from "react";
import { EllipsisVerticalIcon, LockIcon, LockOpenIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@amibeingpwned/ui/dropdown-menu";

import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import {
  encryptKeyForExportWithHandle,
  getKeyArmored,
} from "../../lib/pgp/wasm";
import { formatAlgorithm, formatFingerprint } from "../../lib/utils/formatting";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { Dialog } from "../shared/Dialog";

interface KeyCardProps {
  keyBlob: ProtectedKeyBlob;
  isUnlocked: boolean;
  onUnlockWithPassword: (password: string) => Promise<boolean>;
  onUnlockWithPasskey: () => Promise<boolean | "cancelled">;
  onLock: () => void;
  onDelete: () => void;
  onExportPublic: () => void;
  onExportPrivate: () => number | null;
  advancedMode?: boolean;
  autoExpand?: boolean;
}

export function KeyCard({
  keyBlob,
  isUnlocked,
  onUnlockWithPassword,
  onUnlockWithPasskey,
  onLock,
  onDelete,
  onExportPublic,
  onExportPrivate,
  advancedMode,
  autoExpand,
}: KeyCardProps) {
  const [showPasswordUnlock, setShowPasswordUnlock] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [showExportPrivateConfirm, setShowExportPrivateConfirm] =
    useState(false);
  const [password, setPassword] = useState("");
  const [unlocking, setUnlocking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);
  const [exportPassphrase, setExportPassphrase] = useState("");
  const [exportConfirmPassphrase, setExportConfirmPassphrase] = useState("");
  const [exportError, setExportError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [unsafeExportConfirm, setUnsafeExportConfirm] = useState("");
  const feedbackTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const clipboardClearTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  /** Schedule a best-effort clipboard wipe after `delayMs`.
   *  We can't read the clipboard to know if the user has since copied
   *  something else (no permission), so the wipe is unconditional --
   *  acceptable trade-off for not leaving secret key material indefinitely. */
  const scheduleClipboardClear = (delayMs = 60_000) => {
    if (clipboardClearTimer.current) clearTimeout(clipboardClearTimer.current);
    clipboardClearTimer.current = setTimeout(() => {
      void navigator.clipboard.writeText("").catch(() => {
        /* clipboard API may have been revoked; nothing to do */
      });
    }, delayMs);
  };

  useEffect(() => {
    return () => {
      if (clipboardClearTimer.current) {
        clearTimeout(clipboardClearTimer.current);
      }
    };
  }, []);

  const displayName = keyBlob.userIds[0] ?? "Unknown";
  const shortId = keyBlob.keyId.slice(-16);
  const isPasskey = keyBlob.protection.method === "passkey";

  const didAutoExpand = useRef(false);
  useEffect(() => {
    if (!autoExpand || isUnlocked || didAutoExpand.current) return;
    didAutoExpand.current = true;
    if (isPasskey) {
      void onUnlockWithPasskey();
    } else {
      setShowPasswordUnlock(true);
    }
  }, [autoExpand, isUnlocked, isPasskey, onUnlockWithPasskey]);

  const showFeedback = (msg: string) => {
    setFeedback(msg);
    clearTimeout(feedbackTimer.current);
    feedbackTimer.current = setTimeout(() => setFeedback(null), 2000);
  };

  const handlePasswordUnlock = async () => {
    setError(null);
    setUnlocking(true);
    const success = await onUnlockWithPassword(password);
    if (success) {
      setShowPasswordUnlock(false);
      setPassword("");
    } else {
      setError("Wrong password");
    }
    setUnlocking(false);
  };

  const handlePasskeyUnlock = async () => {
    setError(null);
    const result = await onUnlockWithPasskey();
    if (result === "cancelled") return;
    if (!result) {
      setError("Passkey authentication failed");
    }
  };

  const handleExportPrivate = async () => {
    setExportError(null);
    if (exportPassphrase.length < 8) {
      setExportError("Passphrase must be at least 8 characters.");
      return;
    }
    if (exportPassphrase !== exportConfirmPassphrase) {
      setExportError("Passphrases do not match.");
      return;
    }
    const handle = onExportPrivate();
    if (handle === null) {
      setExportError("Key is not unlocked.");
      return;
    }
    setExporting(true);
    const passphraseBytes = new TextEncoder().encode(exportPassphrase);
    try {
      const encryptedArmor = await encryptKeyForExportWithHandle(
        handle,
        passphraseBytes,
      );
      await navigator.clipboard.writeText(encryptedArmor);
      // Encrypted-armored is safer than plaintext but still gates secrecy
      // on the export passphrase -- clear the clipboard after 60s so it
      // doesn't sit indefinitely.
      scheduleClipboardClear();
      showFeedback("Encrypted key copied (clears in 60s)");
      setShowExportPrivateConfirm(false);
      setExportPassphrase("");
      setExportConfirmPassphrase("");
    } catch {
      setExportError("Failed to encrypt key.");
    } finally {
      passphraseBytes.fill(0);
      setExporting(false);
    }
  };

  return (
    <div className="border-border rounded-md border p-3">
      <div className="flex items-center gap-2">
        <span
          className={`shrink-0 text-sm ${isUnlocked ? "text-green-400" : "text-muted-foreground"}`}
          title={isUnlocked ? "Unlocked" : "Locked"}
        >
          {isUnlocked ? (
            <LockOpenIcon className="h-4 w-4" />
          ) : (
            <LockIcon className="h-4 w-4" />
          )}
        </span>

        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium">{displayName}</p>
          <p className="text-muted-foreground font-mono text-xs">
            {shortId} · {formatAlgorithm(keyBlob.algorithm)}
          </p>
          {advancedMode && (
            <p className="text-muted-foreground mt-0.5 font-mono text-[10px] leading-relaxed">
              {formatFingerprint(keyBlob.keyId)}
            </p>
          )}
        </div>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              className="text-muted-foreground hover:text-foreground rounded p-1 transition-colors"
              aria-label="Key options"
            >
              <EllipsisVerticalIcon className="h-4 w-4" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem
              onClick={() => {
                onExportPublic();
                showFeedback("Public key copied");
              }}
            >
              Copy public key
            </DropdownMenuItem>
            {isUnlocked && (
              <DropdownMenuItem
                className="text-destructive focus:text-destructive"
                onClick={() => setShowExportPrivateConfirm(true)}
              >
                Copy private key
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
            <DropdownMenuItem
              className="text-destructive focus:text-destructive"
              onClick={() => setShowDeleteConfirm(true)}
            >
              Delete key
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <p className="text-muted-foreground mt-0.5 ml-6 text-xs">
        {isPasskey ? "Passkey" : "Password"}
      </p>

      {feedback && (
        <p className="mt-1 ml-6 text-xs text-green-400">{feedback}</p>
      )}

      {showPasswordUnlock && !isUnlocked && !isPasskey && (
        <div className="mt-2 space-y-2">
          <input
            type="password"
            autoComplete="current-password"
            placeholder="Enter password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void handlePasswordUnlock();
            }}
            className={INPUT_CLASS}
          />
          {error && <p className="text-destructive text-xs">{error}</p>}
          <div className="flex justify-between gap-1">
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                setShowPasswordUnlock(false);
                setPassword("");
                setError(null);
              }}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={() => void handlePasswordUnlock()}
              disabled={unlocking}
            >
              {unlocking ? "..." : "Unlock"}
            </Button>
          </div>
        </div>
      )}

      {error && isPasskey && !isUnlocked && (
        <p className="text-destructive mt-2 text-xs">{error}</p>
      )}

      <Dialog
        open={showExportPrivateConfirm}
        onClose={() => {
          setShowExportPrivateConfirm(false);
          setExportPassphrase("");
          setExportConfirmPassphrase("");
          setUnsafeExportConfirm("");
          setExportError(null);
        }}
        title="Export Private Key"
      >
        <div className="space-y-3">
          <p className="text-muted-foreground text-xs">
            Set a passphrase to encrypt the exported key. Anyone with this
            passphrase and the exported key can decrypt your messages and sign
            as you.
          </p>
          <input
            type="password"
            autoComplete="new-password"
            placeholder="Passphrase (min 8 characters)"
            value={exportPassphrase}
            onChange={(e) => setExportPassphrase(e.target.value)}
            className={INPUT_CLASS}
            autoFocus
          />
          <input
            type="password"
            autoComplete="new-password"
            placeholder="Confirm passphrase"
            value={exportConfirmPassphrase}
            onChange={(e) => setExportConfirmPassphrase(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void handleExportPrivate();
            }}
            className={INPUT_CLASS}
          />
          {exportError && (
            <p className="text-destructive text-xs">{exportError}</p>
          )}
          <Button
            className="w-full"
            onClick={() => void handleExportPrivate()}
            disabled={exporting || !exportPassphrase}
          >
            {exporting ? "Encrypting..." : "Export with passphrase"}
          </Button>
          <div className="border-border border-t pt-3 space-y-2">
            <p className="text-destructive text-[11px]">
              Plaintext export. Anyone who reads your clipboard gets full
              control of this key. Type <span className="font-mono font-bold">EXPORT</span>{" "}
              to confirm:
            </p>
            <input
              type="text"
              autoComplete="off"
              spellCheck={false}
              value={unsafeExportConfirm}
              onChange={(e) => setUnsafeExportConfirm(e.target.value)}
              placeholder="EXPORT"
              className={INPUT_CLASS}
            />
            <Button
              variant="destructive"
              size="sm"
              className="w-full"
              disabled={exporting || unsafeExportConfirm !== "EXPORT"}
              onClick={async () => {
                const handle = onExportPrivate();
                if (handle === null) {
                  setExportError("Key is not unlocked.");
                  return;
                }
                const armored = await getKeyArmored(handle);
                await navigator.clipboard.writeText(armored);
                // Plaintext key on clipboard is high-impact; clear faster.
                scheduleClipboardClear(30_000);
                showFeedback("Unprotected key copied (clears in 30s)");
                setShowExportPrivateConfirm(false);
                setExportPassphrase("");
                setExportConfirmPassphrase("");
                setUnsafeExportConfirm("");
              }}
            >
              Export without passphrase (unsafe)
            </Button>
          </div>
        </div>
      </Dialog>

      {showDeleteConfirm && (
        <div className="bg-destructive/5 border-destructive/30 mt-2 rounded-md border p-2">
          <p className="text-destructive text-xs font-medium">
            Delete this key? Data encrypted with it will be unrecoverable.
          </p>
          <div className="mt-2 flex gap-1">
            <Button
              size="sm"
              variant="outline"
              onClick={() => setShowDeleteConfirm(false)}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              variant="destructive"
              onClick={() => {
                setShowDeleteConfirm(false);
                onDelete();
              }}
            >
              Yes, delete
            </Button>
          </div>
        </div>
      )}

      {!showDeleteConfirm && !showPasswordUnlock && (
        <div className="mt-2 flex justify-end">
          {isUnlocked ? (
            <Button size="sm" variant="outline" onClick={onLock}>
              Lock
            </Button>
          ) : isPasskey ? (
            <Button
              size="sm"
              variant="outline"
              onClick={() => void handlePasskeyUnlock()}
            >
              Unlock
            </Button>
          ) : (
            <Button
              size="sm"
              variant="outline"
              onClick={() => setShowPasswordUnlock(true)}
            >
              Unlock
            </Button>
          )}
        </div>
      )}
    </div>
  );
}
