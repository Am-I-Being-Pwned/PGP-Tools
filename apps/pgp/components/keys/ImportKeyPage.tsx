import { useEffect, useRef, useState } from "react";
import { format } from "date-fns";
import { TriangleAlertIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import type { CrxProtectionInput } from "../../lib/crx/operations";
import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { ImportOverwrite } from "../../lib/import-overwrite";
import type { KeyInfo } from "../../lib/pgp/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { readKeyFile } from "../../lib/binary-armor";
import { importCrxKey } from "../../lib/crx/operations";
import { detectImportOverwrite } from "../../lib/import-overwrite";
import {
  importRejectionMessage,
  isUsableContact,
} from "../../lib/import-public-keys";
import { importKey } from "../../lib/pgp/key-management";
import { parseKeys } from "../../lib/pgp/wasm";
import { importAndProtect } from "../../lib/protection/protect-flow";
import { toast } from "../../lib/toast";
import { errorMessage } from "../../lib/utils/errors";
import { INPUT_CLASS } from "../../lib/utils/styles";
import {
  SlideOverHeader,
  SlideOverPanel,
  useSlideOver,
} from "../shared/SlideOver";
import {
  getDefaultProtectionMethod,
  ProtectionMethodPicker,
  validatePassword,
} from "./ProtectionMethodPicker";

type Step = "paste" | "confirm-replace" | "unlock" | "protect";

/** A raw RSA private key PEM (PKCS#8 or PKCS#1) — a CRX signing key, not
 *  OpenPGP. Matched only when it is NOT a PGP armored block. */
const RSA_PEM_RE = /-----BEGIN (?:RSA )?PRIVATE KEY-----/;
function isRsaPrivatePem(text: string): boolean {
  return RSA_PEM_RE.test(text) && !text.includes("PGP");
}

type DetectedType = "public" | "private" | "crx" | null;

function detectType(text: string, crxEnabled: boolean): DetectedType {
  if (crxEnabled && isRsaPrivatePem(text)) return "crx";
  if (text.includes("PRIVATE KEY")) return "private";
  if (text.includes("PUBLIC KEY")) return "public";
  return null;
}

interface ParsedPrivate {
  publicKeyArmored: string;
  keyInfo: KeyInfo;
  secretEncrypted: boolean;
}

interface ImportKeyPageProps {
  /** Called after the slide-out finishes (cancel or success). */
  onClose: () => void;
  onImportPrivate: (blob: ProtectedKeyBlob) => Promise<void>;
  onImportPublic: (contact: PublicContactKey) => Promise<void>;
  /** Current keyring/contacts, to detect an import that would replace an
   *  existing key (same fingerprint) and confirm before saving. */
  existingKeys?: ProtectedKeyBlob[];
  existingContacts?: PublicContactKey[];
  /** Pass the primary key's passkey credential ID to allow reuse. */
  reusePasskeyCredentialId?: string;
  /** When provided, prefill the paste step with this armored key (e.g. from
   *  a global drop). Read once at mount. */
  initialArmored?: string | null;
  /** When true, also accept a raw RSA private key PEM as a CRX signing key. */
  crxSigningEnabled?: boolean;
  /** Persist an imported CRX signing key. Required for the CRX path. */
  onImportCrx?: (blob: CrxSigningKeyBlob) => Promise<void>;
}

/**
 * Full-page key import, using the same slide-over pattern as key generation
 * and details. Paste or browse for a key, unlock it if the source is
 * passphrase-protected, then re-protect it with the chosen method. Public
 * keys import straight from the paste step; the back button lives in the
 * header and steps back through the flow.
 */
export function ImportKeyPage({
  onClose,
  onImportPrivate,
  onImportPublic,
  existingKeys = [],
  existingContacts = [],
  reusePasskeyCredentialId,
  initialArmored,
  crxSigningEnabled,
  onImportCrx,
}: ImportKeyPageProps) {
  const crxEnabled = !!crxSigningEnabled && !!onImportCrx;
  const { entered, close } = useSlideOver(onClose);
  const [step, setStep] = useState<Step>("paste");
  const [label, setLabel] = useState("");
  const [method, setMethod] = useState(getDefaultProtectionMethod);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [detectedType, setDetectedType] = useState<DetectedType>(
    initialArmored ? detectType(initialArmored, crxEnabled) : null,
  );
  const [reusePasskey, setReusePasskey] = useState(true);
  const [sourcePassphrase, setSourcePassphrase] = useState("");
  const [parsed, setParsed] = useState<ParsedPrivate | null>(null);
  // A fingerprint collision with a stored key: the confirm-replace step
  // shows what would be overwritten before the import proceeds.
  const [overwrite, setOverwrite] = useState<ImportOverwrite | null>(null);
  const [overwriteKind, setOverwriteKind] = useState<"private" | "public">(
    "private",
  );
  const fileInputRef = useRef<HTMLInputElement>(null);

  // The pasted key armor is the crown-jewel secret, so it lives in a ref
  // rather than useState. A ref is a single mutable slot shared by both of a
  // fiber's double-buffered copies, so clearing it on close drops the only
  // reference -- whereas a useState value is snapshotted into the previous
  // fiber, which React keeps alive for the whole slide-out animation, leaving
  // the private key lingering in the GC heap. Keeping it out of state lets the
  // panel animate out without retaining key material (see SECURITY.md's
  // zeroization table; the same WASM-isolation philosophy as the heap test).
  // `hasContent` mirrors only whether the box is non-empty, for the button.
  const armoredRef = useRef(initialArmored ?? "");
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [hasContent, setHasContent] = useState(!!initialArmored?.trim());

  // Record a new armor value (from typing): stash it in the ref and refresh
  // the derived, non-sensitive UI state.
  const syncArmor = (text: string) => {
    armoredRef.current = text;
    setHasContent(!!text.trim());
    setDetectedType(detectType(text, crxEnabled));
  };

  // Set the armor programmatically (file browse): also write it into the
  // uncontrolled textarea's DOM node so the paste box reflects it.
  const setArmorValue = (text: string) => {
    if (textareaRef.current) textareaRef.current.value = text;
    syncArmor(text);
  };

  const resetAndClose = () => {
    // Drop the pasted armor before the panel slides out. Because it's in a
    // ref (not double-buffered state), this releases the only reference, so
    // the animation can run without holding key material in the JS heap.
    armoredRef.current = "";
    if (textareaRef.current) textareaRef.current.value = "";
    close();
  };

  // The paste box is uncontrolled (armor never enters render state), so seed
  // its DOM value from the ref whenever the paste step (re)mounts -- the
  // initial prefill from a global drop, and restoring the text after the Back
  // button returns from the protect/unlock step.
  useEffect(() => {
    if (step === "paste" && textareaRef.current) {
      textareaRef.current.value = armoredRef.current;
    }
  }, [step]);

  // Header back mirrors the step order; from the first step it slides out.
  const handleBack = () => {
    if (importing) return;
    setError(null);
    if (step === "confirm-replace") {
      setOverwrite(null);
      if (overwriteKind === "private") setParsed(null);
      setStep("paste");
    } else if (step === "unlock") {
      setParsed(null);
      setSourcePassphrase("");
      setStep("paste");
    } else if (step === "protect") {
      // The CRX path has no unlock step; PGP returns to unlock only when the
      // source key was passphrase-protected.
      if (detectedType !== "crx" && parsed?.secretEncrypted) {
        setStep("unlock");
      } else {
        if (detectedType !== "crx") setParsed(null);
        setStep("paste");
      }
    } else {
      resetAndClose();
    }
  };

  const handlePasteNext = async () => {
    setError(null);
    const armored = armoredRef.current;
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
        // Stable id: re-pasting the same key must not stack duplicates.
        toast.warning(result.keyInfo.securityWarning, {
          id: "import-key-warning",
        });
      }
      // Same fingerprint as a stored key: confirm the replacement before
      // continuing (the keyring upserts by keyId, silently otherwise).
      const collision = detectImportOverwrite(
        result.keyInfo.keyId,
        existingKeys,
        {
          userIds: result.keyInfo.userIds,
        },
      );
      if (collision) {
        setOverwrite(collision);
        setOverwriteKind("private");
        setStep("confirm-replace");
      } else {
        setStep(result.secretEncrypted ? "unlock" : "protect");
      }
    } catch (e) {
      setError(errorMessage(e, "Import failed"));
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

  const handleImportPublic = async (confirmedReplace = false) => {
    setImporting(true);
    setError(null);
    try {
      // A pasted blob may bundle several certs (e.g. yearly-rotated
      // keys). Import every live one against its own armor; ignore the
      // stale rotations.
      const certs = await parseKeys(armoredRef.current);
      const usable = certs.filter((c) => isUsableContact(c.keyInfo));
      if (usable.length === 0) {
        setError(importRejectionMessage(certs[0]?.keyInfo));
        return;
      }
      // Any cert matching a stored contact replaces it -- confirm first
      // (once; the confirm step re-enters here with confirmedReplace).
      if (!confirmedReplace) {
        for (const { keyInfo } of usable) {
          const collision = detectImportOverwrite(
            keyInfo.keyId,
            existingContacts,
            { expiresAt: keyInfo.expiresAt, userIds: keyInfo.userIds },
          );
          if (collision) {
            setOverwrite(collision);
            setOverwriteKind("public");
            setStep("confirm-replace");
            return;
          }
        }
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
      if (warning) toast.warning(warning, { id: "import-key-warning" });
      resetAndClose();
    } catch (e) {
      setError(errorMessage(e, "Import failed"));
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
        armoredRef.current.trim(),
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
      setError(errorMessage(e, "Import failed"));
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
        armoredRef.current.trim(),
        protection,
        label.trim() || undefined,
      );
      await onImportCrx(blob);
      resetAndClose();
    } catch (e) {
      setError(errorMessage(e, "Import failed"));
    } finally {
      setImporting(false);
    }
  };

  return (
    <SlideOverPanel entered={entered} ariaLabel="Import key">
      <SlideOverHeader title="Import key" onBack={handleBack} />
      <div className="flex flex-1 flex-col overflow-hidden">
        {step === "paste" && (
          <div className="flex flex-1 flex-col overflow-hidden">
            <div className="flex flex-1 flex-col gap-3 overflow-y-auto p-3">
              {/* Uncontrolled: the armor is held in armoredRef, never in
                  React state, so it can't linger in a double-buffered fiber
                  during the slide-out. The mount effect above seeds/restores
                  its value from the ref. */}
              <textarea
                ref={textareaRef}
                placeholder="Paste a key here, or browse for a file..."
                onChange={(e) => syncArmor(e.target.value)}
                className="border-border bg-background placeholder:text-muted-foreground focus:ring-ring min-h-32 w-full flex-1 resize-none rounded-md border p-3 font-mono text-xs focus:ring-2 focus:outline-none"
              />
              <input
                ref={fileInputRef}
                type="file"
                accept=".asc,.gpg,.pub,.key,.pgp,.txt,.pem"
                className="hidden"
                onChange={async (e) => {
                  const file = e.target.files?.[0];
                  if (file) setArmorValue(await readKeyFile(file));
                  e.target.value = "";
                }}
              />
              <Button
                variant="outline"
                size="sm"
                className="self-start"
                onClick={() => fileInputRef.current?.click()}
              >
                Browse for key file
              </Button>

              {detectedType === "crx" ? (
                <>
                  <p className="text-muted-foreground text-xs">
                    Detected:{" "}
                    <span className="font-medium">RSA signing key</span> for a
                    Chrome extension (.crx).
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
                    <span className="font-medium capitalize">
                      {detectedType}
                    </span>{" "}
                    key
                  </p>
                )
              )}
            </div>

            <div className="border-border space-y-2 border-t p-3">
              {error && (
                <p className="text-destructive text-xs" role="alert">
                  {error}
                </p>
              )}
              <Button
                className="w-full"
                onClick={() => void handlePasteNext()}
                disabled={importing || !hasContent}
              >
                {importing
                  ? "Importing..."
                  : detectedType === "public"
                    ? "Import"
                    : "Next"}
              </Button>
            </div>
          </div>
        )}

        {step === "confirm-replace" && overwrite && (
          <div className="flex flex-1 flex-col overflow-hidden">
            <div className="flex-1 space-y-3 overflow-y-auto p-3">
              <div className="border-destructive/30 bg-destructive/5 flex items-start gap-2 rounded-md border p-3">
                <TriangleAlertIcon className="text-destructive mt-0.5 h-4 w-4 shrink-0" />
                <div className="min-w-0 flex-1 text-xs">
                  <p>
                    This replaces your existing key for{" "}
                    <span className="font-medium">{overwrite.userId}</span>
                    {overwrite.addedAt
                      ? ` (added ${format(overwrite.addedAt, "PPP")})`
                      : ""}
                    .
                  </p>
                  {overwrite.changes.length > 0 && (
                    <p className="text-muted-foreground mt-2">
                      Changes: {overwrite.changes.join(", ")}.
                    </p>
                  )}
                  <p className="mt-2">
                    The stored key is overwritten; if this import is a mistake,
                    you'd need to re-import the old key.
                  </p>
                </div>
              </div>
            </div>

            <div className="border-border space-y-2 border-t p-3">
              {error && (
                <p className="text-destructive text-xs" role="alert">
                  {error}
                </p>
              )}
              <Button
                variant="destructive"
                className="w-full"
                disabled={importing}
                onClick={() => {
                  if (overwriteKind === "public") {
                    void handleImportPublic(true);
                  } else {
                    setOverwrite(null);
                    setStep(parsed?.secretEncrypted ? "unlock" : "protect");
                  }
                }}
              >
                {importing ? "Importing..." : "Replace key"}
              </Button>
            </div>
          </div>
        )}

        {step === "unlock" && (
          <div className="flex flex-1 flex-col overflow-hidden">
            <div className="flex-1 space-y-3 overflow-y-auto p-3">
              <p className="text-muted-foreground text-xs">
                This key is protected with a passphrase. Enter it to unlock the
                key - you'll then re-protect it with your chosen method on the
                next step.
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
                <p className="rounded border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-400">
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
            </div>

            <div className="border-border space-y-2 border-t p-3">
              {error && (
                <p className="text-destructive text-xs" role="alert">
                  {error}
                </p>
              )}
              <Button
                className="w-full"
                onClick={handleUnlockNext}
                disabled={importing || !sourcePassphrase}
              >
                Next
              </Button>
            </div>
          </div>
        )}

        {step === "protect" && (
          <div className="flex-1 overflow-y-auto p-3">
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
              onBack={handleBack}
              submitting={importing}
              submitLabel="Import"
              reusePasskeyCredentialId={reusePasskeyCredentialId}
              reusePasskey={reusePasskey}
              onReusePasskeyChange={setReusePasskey}
            />
          </div>
        )}
      </div>
    </SlideOverPanel>
  );
}
