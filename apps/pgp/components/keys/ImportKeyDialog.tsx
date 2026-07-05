import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";

import { Button } from "@amibeingpwned/ui/button";

import type { CrxProtectionInput } from "../../lib/crx/operations";
import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { KeyInfo } from "../../lib/pgp/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { importCrxKey } from "../../lib/crx/operations";
import {
  importRejectionMessage,
  isUsableContact,
} from "../../lib/import-public-keys";
import { importKey } from "../../lib/pgp/key-management";
import { parseKeys } from "../../lib/pgp/wasm";
import { importAndProtect } from "../../lib/protection/protect-flow";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { Dialog } from "../shared/Dialog";
import {
  getDefaultProtectionMethod,
  ProtectionMethodPicker,
  validatePassword,
} from "./ProtectionMethodPicker";

type Step = "paste" | "unlock" | "protect";

/** A raw RSA private key PEM (PKCS#8 or PKCS#1) — a CRX signing key, not
 *  OpenPGP. Matched only when it is NOT a PGP armored block. */
const RSA_PEM_RE = /-----BEGIN (?:RSA )?PRIVATE KEY-----/;
function isRsaPrivatePem(text: string): boolean {
  return RSA_PEM_RE.test(text) && !text.includes("PGP");
}

interface ParsedPrivate {
  publicKeyArmored: string;
  keyInfo: KeyInfo;
  secretEncrypted: boolean;
}

interface ImportKeyDialogProps {
  open: boolean;
  onClose: () => void;
  onImportPrivate: (blob: ProtectedKeyBlob) => Promise<void>;
  onImportPublic: (contact: PublicContactKey) => Promise<void>;
  /** Pass the primary key's passkey credential ID to allow reuse. */
  reusePasskeyCredentialId?: string;
  /** When provided (and the dialog opens), prefill the paste step with this
   *  armored key. Cleared on close by the parent. */
  initialArmored?: string | null;
  /** When true, also accept a raw RSA private key PEM as a CRX signing key. */
  crxSigningEnabled?: boolean;
  /** Persist an imported CRX signing key. Required for the CRX path. */
  onImportCrx?: (blob: CrxSigningKeyBlob) => Promise<void>;
}

type DetectedType = "public" | "private" | "crx" | null;

export function ImportKeyDialog({
  open,
  onClose,
  onImportPrivate,
  onImportPublic,
  reusePasskeyCredentialId,
  initialArmored,
  crxSigningEnabled,
  onImportCrx,
}: ImportKeyDialogProps) {
  const [step, setStep] = useState<Step>("paste");
  const [armored, setArmored] = useState("");
  const [label, setLabel] = useState("");
  const [method, setMethod] = useState(getDefaultProtectionMethod);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [detectedType, setDetectedType] = useState<DetectedType>(null);
  const [reusePasskey, setReusePasskey] = useState(true);
  const [sourcePassphrase, setSourcePassphrase] = useState("");
  const [parsed, setParsed] = useState<ParsedPrivate | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Apply a prefill when the dialog opens with one. Runs only on the
  // open-edge so user edits inside the dialog aren't clobbered.
  const detectType = (text: string): DetectedType => {
    if (crxSigningEnabled && onImportCrx && isRsaPrivatePem(text)) return "crx";
    if (text.includes("PRIVATE KEY")) return "private";
    if (text.includes("PUBLIC KEY")) return "public";
    return null;
  };

  useEffect(() => {
    if (!open || !initialArmored) return;
    setArmored(initialArmored);
    setDetectedType(detectType(initialArmored));
    setStep("paste");
    setError(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, initialArmored]);

  if (!open) return null;

  const resetAndClose = () => {
    setStep("paste");
    setArmored("");
    setLabel("");
    setPassword("");
    setConfirmPassword("");
    setDetectedType(null);
    setError(null);
    setReusePasskey(true);
    setSourcePassphrase("");
    setParsed(null);
    onClose();
  };

  const handleArmoredChange = (text: string) => {
    setArmored(text);
    setDetectedType(detectType(text));
  };

  const handlePasteNext = async () => {
    setError(null);
    if (!armored.trim()) return;
    // A raw RSA PEM is a CRX signing key: no PGP parse, straight to the
    // protection step (the label was entered alongside the paste box).
    if (detectedType === "crx") {
      setStep("protect");
      return;
    }
    if (detectedType === "public" || !armored.includes("PRIVATE KEY")) {
      void handleImportPublic();
      return;
    }

    setImporting(true);
    try {
      const result = await importKey(armored);
      if (result.type !== "private") {
        setError("Expected a private key.");
        return;
      }
      if (
        !result.keyInfo.usableForEncryption &&
        !result.keyInfo.usableForSigning
      ) {
        setError(
          result.keyInfo.policyError ??
            "This key cannot be used for encryption or signing.",
        );
        return;
      }
      setParsed({
        publicKeyArmored: result.publicKeyArmored,
        keyInfo: result.keyInfo,
        secretEncrypted: result.secretEncrypted,
      });
      if (result.keyInfo.securityWarning) {
        toast.warning(result.keyInfo.securityWarning);
      }
      setStep(result.secretEncrypted ? "unlock" : "protect");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Import failed");
    } finally {
      setImporting(false);
    }
  };

  const handleUnlockNext = () => {
    if (!sourcePassphrase) {
      setError("Enter the key's passphrase.");
      return;
    }
    setError(null);
    setStep("protect");
  };

  const handleImportPublic = async () => {
    setImporting(true);
    setError(null);
    try {
      // A pasted blob may bundle several certs (e.g. yearly-rotated
      // keys). Import every live one against its own armor; ignore the
      // stale rotations.
      const certs = await parseKeys(armored);
      const usable = certs.filter((c) => isUsableContact(c.keyInfo));
      if (usable.length === 0) {
        setError(importRejectionMessage(certs[0]?.keyInfo));
        return;
      }
      let warning: string | undefined;
      for (const { keyInfo, armored: certArmored } of usable) {
        await onImportPublic({
          keyId: keyInfo.keyId,
          userIds: keyInfo.userIds,
          algorithm: keyInfo.algorithm,
          armoredPublicKey: certArmored,
          addedAt: Date.now(),
          lastUsedAt: Date.now(),
          expiresAt: keyInfo.expiresAt,
          usableForEncryption: keyInfo.usableForEncryption,
          // Allowed, but flagged (e.g. SHA-1 binding signature).
          securityWarning: keyInfo.securityWarning,
        });
        warning ??= keyInfo.securityWarning;
      }
      if (warning) toast.warning(warning);
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

    if (!parsed) {
      setError("No key to import.");
      return;
    }

    setImporting(true);
    try {
      const { blob } = await importAndProtect(
        armored.trim(),
        parsed.secretEncrypted ? sourcePassphrase : null,
        method === "password"
          ? { method: "password", password }
          : {
              method: "passkey",
              reusePasskeyCredentialId: reusePasskey
                ? reusePasskeyCredentialId
                : undefined,
            },
        { userIdHint: parsed.keyInfo.userIds[0] ?? "Imported PGP Key" },
      );
      await onImportPrivate(blob);
      resetAndClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Import failed");
    } finally {
      setImporting(false);
    }
  };

  const handleImportCrx = async () => {
    setError(null);
    if (method === "password") {
      const pwError = validatePassword(password, confirmPassword);
      if (pwError) {
        setError(pwError);
        return;
      }
    }
    if (!onImportCrx) return;

    setImporting(true);
    try {
      const protection: CrxProtectionInput =
        method === "password"
          ? { method: "password", password }
          : {
              method: "passkey",
              reusePasskeyCredentialId: reusePasskey
                ? reusePasskeyCredentialId
                : undefined,
            };
      const blob = await importCrxKey(
        armored.trim(),
        protection,
        label.trim() || undefined,
      );
      await onImportCrx(blob);
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
            accept=".asc,.gpg,.pub,.key,.pgp,.txt,.pem"
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

          {detectedType === "crx" ? (
            <>
              <p className="text-muted-foreground text-xs">
                Detected: <span className="font-medium">RSA signing key</span>{" "}
                for a Chrome extension (.crx).
              </p>
              <div>
                <label className="text-muted-foreground mb-1 block text-xs">
                  Label{" "}
                  <span className="text-muted-foreground/60">optional</span>
                </label>
                <input
                  type="text"
                  placeholder="e.g. My Extension"
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                  className={INPUT_CLASS}
                />
              </div>
            </>
          ) : (
            detectedType && (
              <p className="text-muted-foreground text-xs">
                Detected:{" "}
                <span className="font-medium capitalize">{detectedType}</span>{" "}
                key
              </p>
            )
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
            This key is protected with a passphrase. Enter it to unlock the key
            - you'll then re-protect it with your chosen method on the next
            step.
          </p>
          {parsed && (
            <div className="bg-muted/30 rounded border p-2 text-xs">
              <div className="font-medium">
                {parsed.keyInfo.userIds[0] ?? "(no user ID)"}
              </div>
              <div className="text-muted-foreground font-mono">
                {parsed.keyInfo.keyId.slice(-16)}
              </div>
            </div>
          )}
          {parsed?.keyInfo.securityWarning && (
            <p className="rounded border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-700 dark:text-amber-400">
              ⚠ {parsed.keyInfo.securityWarning}
            </p>
          )}
          <input
            type="password"
            autoFocus
            autoComplete="current-password"
            value={sourcePassphrase}
            onChange={(e) => setSourcePassphrase(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && sourcePassphrase) handleUnlockNext();
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
                setParsed(null);
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
              onClick={handleUnlockNext}
              disabled={importing || !sourcePassphrase}
            >
              Next
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
          onSubmit={
            detectedType === "crx" ? handleImportCrx : handleImportPrivate
          }
          onBack={() => {
            // The CRX path has no unlock step; PGP returns to unlock only
            // when the source key was passphrase-protected.
            setStep(
              detectedType !== "crx" && parsed?.secretEncrypted
                ? "unlock"
                : "paste",
            );
            if (detectedType !== "crx" && !parsed?.secretEncrypted)
              setParsed(null);
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
