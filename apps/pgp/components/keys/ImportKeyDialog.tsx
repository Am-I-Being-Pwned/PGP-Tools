import { useRef, useState } from "react";

import { Button } from "@amibeingpwned/ui/button";

import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { importKey } from "../../lib/pgp/key-management";
import { protectAndStoreKey } from "../../lib/protection/protect-key";
import { Dialog } from "../shared/Dialog";
import {
  getDefaultProtectionMethod,
  ProtectionMethodPicker,
  validatePassword,
} from "./ProtectionMethodPicker";

type Step = "paste" | "protect";

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
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!open) return null;

  const resetAndClose = () => {
    setStep("paste");
    setArmored("");
    setPassword("");
    setConfirmPassword("");
    setDetectedType(null);
    setError(null);
    setReusePasskey(true);
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

  const handlePasteNext = () => {
    setError(null);
    if (!armored.trim()) return;
    if (detectedType === "public" || !armored.includes("PRIVATE KEY")) {
      void handleImportPublic();
    } else {
      setStep("protect");
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

    setImporting(true);
    try {
      const result = await importKey(armored);
      if (result.type !== "private") {
        setError("Expected a private key.");
        setImporting(false);
        return;
      }

      const { blob } = await protectAndStoreKey({
        privateKeyArmored: result.privateKeyArmored,
        publicKeyArmored: result.publicKeyArmored,
        keyInfo: result.keyInfo,
        method,
        password,
        reusePasskeyCredentialId:
          method === "passkey" && reusePasskey
            ? reusePasskeyCredentialId
            : undefined,
      });

      await onImportPrivate(blob);
      resetAndClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Import failed");
    } finally {
      setImporting(false);
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
              onClick={handlePasteNext}
              disabled={importing || !armored.trim()}
            >
              {importing ? "Importing..." : "Next"}
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
