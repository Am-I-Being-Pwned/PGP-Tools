import { useEffect, useRef, useState } from "react";

import { Button } from "@amibeingpwned/ui/button";

import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { importKey } from "../../lib/pgp/key-management";
import {
  decryptAndStoreImportedKey,
  dropKey,
  storeKey,
} from "../../lib/pgp/wasm";
import { protectHandleAndBuildBlob } from "../../lib/protection/protect-handle";
import { Dialog } from "../shared/Dialog";
import {
  getDefaultProtectionMethod,
  ProtectionMethodPicker,
  validatePassword,
} from "./ProtectionMethodPicker";

type Step = "paste" | "unlock" | "protect";

interface UnlockedPrivate {
  /** WASM key handle - decrypted secret material lives only in WASM.
   *  null while the key is still S2K-encrypted (unlock step pending). */
  handle: number | null;
  publicKeyArmored: string;
  keyInfo: import("../../lib/pgp/types").KeyInfo;
}

interface ImportKeyDialogProps {
  open: boolean;
  onClose: () => void;
  onImportPrivate: (blob: ProtectedKeyBlob) => Promise<void>;
  onImportPublic: (contact: PublicContactKey) => Promise<void>;
  /** Pass the primary key's passkey credential ID to allow reuse. */
  reusePasskeyCredentialId?: string;
}

export function ImportKeyDialog({
  open,
  onClose,
  onImportPrivate,
  onImportPublic,
  reusePasskeyCredentialId,
}: ImportKeyDialogProps) {
  const [step, setStep] = useState<Step>("paste");
  const [armored, setArmored] = useState("");
  const [method, setMethod] = useState(getDefaultProtectionMethod);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [detectedType, setDetectedType] = useState<"public" | "private" | null>(
    null,
  );
  const [reusePasskey, setReusePasskey] = useState(true);
  const [sourcePassphrase, setSourcePassphrase] = useState("");
  const [unlocked, setUnlocked] = useState<UnlockedPrivate | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  // Authoritative handle for cleanup paths (effect, abandon, error).
  // useState is mirrored on `unlocked.handle` for render purposes.
  const liveHandleRef = useRef<number | null>(null);

  // Drop any live WASM handle if the dialog unmounts mid-flow.
  useEffect(() => {
    return () => {
      const h = liveHandleRef.current;
      if (h != null) {
        liveHandleRef.current = null;
        void dropKey(h);
      }
    };
  }, []);

  // Drop the handle if the parent closes the dialog (open -> false)
  // without going through resetAndClose (e.g. external state change).
  useEffect(() => {
    if (!open) {
      const h = liveHandleRef.current;
      if (h != null) {
        liveHandleRef.current = null;
        void dropKey(h);
      }
    }
  }, [open]);

  const releaseHandle = () => {
    const h = liveHandleRef.current;
    if (h != null) {
      liveHandleRef.current = null;
      void dropKey(h);
    }
  };

  if (!open) return null;

  const resetAndClose = () => {
    releaseHandle();
    setStep("paste");
    setArmored("");
    setPassword("");
    setConfirmPassword("");
    setDetectedType(null);
    setError(null);
    setReusePasskey(true);
    setSourcePassphrase("");
    setUnlocked(null);
    onClose();
  };

  const handleArmoredChange = (text: string) => {
    setArmored(text);
    if (text.includes("PRIVATE KEY")) {
      setDetectedType("private");
    } else if (text.includes("PUBLIC KEY")) {
      setDetectedType("public");
    } else {
      setDetectedType(null);
    }
  };

  const handlePasteNext = async () => {
    setError(null);
    if (!armored.trim()) return;
    if (detectedType === "public" || !armored.includes("PRIVATE KEY")) {
      void handleImportPublic();
      return;
    }

    // Re-Next from the paste step abandons any previously-loaded key.
    releaseHandle();
    setUnlocked(null);

    setImporting(true);
    try {
      const result = await importKey(armored);
      if (result.type !== "private") {
        setError("Expected a private key.");
        return;
      }
      if (result.secretEncrypted) {
        // Defer storeKey() until we have the passphrase; storeKey rejects
        // certs whose secret material is still S2K-encrypted.
        setUnlocked({
          handle: null,
          publicKeyArmored: result.publicKeyArmored,
          keyInfo: result.keyInfo,
        });
        setStep("unlock");
      } else {
        const handle = await storeKey(result.privateKeyArmored);
        liveHandleRef.current = handle;
        setUnlocked({
          handle,
          publicKeyArmored: result.publicKeyArmored,
          keyInfo: result.keyInfo,
        });
        setStep("protect");
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Import failed");
    } finally {
      setImporting(false);
    }
  };

  const handleUnlock = async () => {
    if (!unlocked) return;
    if (!sourcePassphrase) {
      setError("Enter the key's passphrase.");
      return;
    }
    setError(null);
    setImporting(true);
    const passphraseBytes = new TextEncoder().encode(sourcePassphrase);
    try {
      // Drop any prior handle (e.g. user typed the wrong passphrase, then
      // tried again — the previous attempt may have left a handle).
      releaseHandle();
      const handle = await decryptAndStoreImportedKey(
        armored.trim(),
        passphraseBytes,
      );
      liveHandleRef.current = handle;
      setUnlocked({ ...unlocked, handle });
      setSourcePassphrase("");
      setStep("protect");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to unlock key");
    } finally {
      passphraseBytes.fill(0);
      setImporting(false);
    }
  };

  const handleImportPublic = async () => {
    setImporting(true);
    setError(null);
    try {
      const result = await importKey(armored);
      if (result.type !== "public") {
        setStep("protect");
        setImporting(false);
        return;
      }
      await onImportPublic({
        keyId: result.keyInfo.keyId,
        userIds: result.keyInfo.userIds,
        algorithm: result.keyInfo.algorithm,
        armoredPublicKey: result.armored,
        addedAt: Date.now(),
        lastUsedAt: Date.now(),
      });
      resetAndClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Import failed");
    } finally {
      setImporting(false);
    }
  };

  const handleImportPrivate = async () => {
    setError(null);

    if (method === "password") {
      const pwError = validatePassword(password, confirmPassword);
      if (pwError) {
        setError(pwError);
        return;
      }
    }

    if (!unlocked || unlocked.handle == null) {
      setError("No key to import.");
      return;
    }

    setImporting(true);
    let success = false;
    try {
      const blob = await protectHandleAndBuildBlob({
        handle: unlocked.handle,
        keyInfo: unlocked.keyInfo,
        publicKeyArmored: unlocked.publicKeyArmored,
        method,
        password,
        reusePasskeyCredentialId:
          method === "passkey" && reusePasskey
            ? reusePasskeyCredentialId
            : undefined,
      });

      await onImportPrivate(blob);
      success = true;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Import failed");
    } finally {
      setImporting(false);
      // Drop the handle whether import succeeded or failed -- on failure
      // the user must restart from paste, and we don't want to leak the
      // decrypted cert in WASM.
      releaseHandle();
      if (success) resetAndClose();
    }
  };

  return (
    <Dialog open={open} onClose={resetAndClose} title="Import Key">
      {step === "paste" && (
        <div className="space-y-3">
          <textarea
            placeholder="Paste a key here, or browse for a file..."
            value={armored}
            onChange={(e) => handleArmoredChange(e.target.value)}
            className="border-border bg-background placeholder:text-muted-foreground focus:ring-ring w-full rounded-md border p-3 font-mono text-xs focus:ring-2 focus:outline-none"
            rows={6}
          />
          <input
            ref={fileInputRef}
            type="file"
            accept=".asc,.gpg,.pub,.key,.pgp,.txt"
            className="hidden"
            onChange={async (e) => {
              const file = e.target.files?.[0];
              if (file) handleArmoredChange(await file.text());
              e.target.value = "";
            }}
          />
          <Button
            variant="outline"
            size="sm"
            onClick={() => fileInputRef.current?.click()}
          >
            Browse for key file
          </Button>

          {detectedType && (
            <p className="text-muted-foreground text-xs">
              Detected:{" "}
              <span className="font-medium capitalize">{detectedType}</span> key
            </p>
          )}

          {error && (
            <p className="text-destructive text-xs" role="alert">
              {error}
            </p>
          )}

          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              className="flex-1"
              onClick={resetAndClose}
              disabled={importing}
            >
              Cancel
            </Button>
            <Button
              size="sm"
              className="flex-1"
              onClick={() => void handlePasteNext()}
              disabled={importing || !armored.trim()}
            >
              {importing ? "Importing..." : "Next"}
            </Button>
          </div>
        </div>
      )}

      {step === "unlock" && (
        <div className="space-y-3">
          <p className="text-muted-foreground text-xs">
            This key is protected with a passphrase. Enter it to decrypt the
            key — it will then be re-protected with your chosen method on the
            next step.
          </p>
          {unlocked && (
            <div className="bg-muted/30 rounded border p-2 text-xs">
              <div className="font-medium">
                {unlocked.keyInfo.userIds[0] ?? "(no user ID)"}
              </div>
              <div className="text-muted-foreground font-mono">
                {unlocked.keyInfo.keyId.slice(-16)}
              </div>
            </div>
          )}
          <input
            type="password"
            autoFocus
            autoComplete="current-password"
            value={sourcePassphrase}
            onChange={(e) => setSourcePassphrase(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && sourcePassphrase && !importing) {
                void handleUnlock();
              }
            }}
            placeholder="Key passphrase"
            className="border-border bg-background placeholder:text-muted-foreground focus:ring-ring w-full rounded-md border p-2 font-mono text-xs focus:ring-2 focus:outline-none"
          />
          {error && (
            <p className="text-destructive text-xs" role="alert">
              {error}
            </p>
          )}
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              className="flex-1"
              onClick={() => {
                releaseHandle();
                setUnlocked(null);
                setStep("paste");
                setError(null);
                setSourcePassphrase("");
              }}
              disabled={importing}
            >
              Back
            </Button>
            <Button
              size="sm"
              className="flex-1"
              onClick={() => void handleUnlock()}
              disabled={importing || !sourcePassphrase}
            >
              {importing ? "Unlocking..." : "Unlock"}
            </Button>
          </div>
        </div>
      )}

      {step === "protect" && (
        <ProtectionMethodPicker
          method={method}
          onMethodChange={setMethod}
          password={password}
          onPasswordChange={setPassword}
          confirmPassword={confirmPassword}
          onConfirmPasswordChange={setConfirmPassword}
          error={error}
          onSubmit={handleImportPrivate}
          onBack={() => {
            releaseHandle();
            setUnlocked(null);
            setStep("paste");
            setError(null);
          }}
          submitting={importing}
          submitLabel="Import"
          reusePasskeyCredentialId={reusePasskeyCredentialId}
          reusePasskey={reusePasskey}
          onReusePasskeyChange={setReusePasskey}
        />
      )}
    </Dialog>
  );
}
