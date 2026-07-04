import { useRef, useState } from "react";
import { toast } from "sonner";

import { Button } from "@amibeingpwned/ui/button";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { KeyInfo } from "../../lib/pgp/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { parseCrxKeyBlocks } from "../../lib/crx/backup";
import { splitArmoredKeyBlocks } from "../../lib/armor-blocks";
import { importPublicKeyBlocks } from "../../lib/import-public-keys";
import { importKey } from "../../lib/pgp/key-management";
import { importAndProtect } from "../../lib/protection/protect-flow";
import {
  authenticateAndGetPrf,
  generatePrfSalt,
  isWebAuthnCancel,
  registerPasskey,
} from "../../lib/protection/webauthn-prf";
import {
  getDefaultProtectionMethod,
  ProtectionMethodPicker,
  validatePassword,
} from "../keys/ProtectionMethodPicker";
import { Dialog } from "../shared/Dialog";

type Step = "paste" | "unlock" | "protect";

interface ParsedPrivate {
  armored: string;
  keyInfo: KeyInfo;
  secretEncrypted: boolean;
}

interface ImportAllKeysDialogProps {
  open: boolean;
  onClose: () => void;
  myKeys: ProtectedKeyBlob[];
  contacts: PublicContactKey[];
  onAddKey: (blob: ProtectedKeyBlob) => Promise<void>;
  onAddContact: (contact: PublicContactKey) => Promise<void>;
  /** Restore CRX signing keys found in the backup (self-protected blobs). */
  onAddCrxKey?: (blob: CrxSigningKeyBlob) => Promise<void>;
  /** Pass the primary key's passkey credential ID to allow reuse. */
  reusePasskeyCredentialId?: string;
}

/**
 * Bulk import: accepts a pasted/browsed dump with any mix of armored
 * private and public keys (e.g. a file from "Export All Keys"). Private
 * keys share one source passphrase (the export wrote them under a
 * single passphrase) and are re-protected under one chosen method --
 * for passkeys, a single WebAuthn ceremony covers every key via PRF
 * reuse. Public keys become contacts.
 */
export function ImportAllKeysDialog({
  open,
  onClose,
  myKeys,
  contacts,
  onAddKey,
  onAddContact,
  onAddCrxKey,
  reusePasskeyCredentialId,
}: ImportAllKeysDialogProps) {
  const [step, setStep] = useState<Step>("paste");
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const [parsedPrivates, setParsedPrivates] = useState<ParsedPrivate[]>([]);
  const [publicBlocks, setPublicBlocks] = useState<string[]>([]);
  const [skippedPrivates, setSkippedPrivates] = useState(0);
  const [sourcePassphrase, setSourcePassphrase] = useState("");
  const [method, setMethod] = useState(getDefaultProtectionMethod);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [reusePasskey, setReusePasskey] = useState(true);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const resetAndClose = () => {
    setStep("paste");
    setText("");
    setError(null);
    setParsedPrivates([]);
    setPublicBlocks([]);
    setSkippedPrivates(0);
    setSourcePassphrase("");
    setPassword("");
    setConfirmPassword("");
    setReusePasskey(true);
    onClose();
  };

  const importPublics = async (blocks: string[]) => {
    if (blocks.length === 0) return;
    const { added, skipped, failed, flagged, rejectionReasons } =
      await importPublicKeyBlocks(
        blocks,
        contacts.map((c) => c.keyId),
        onAddContact,
      );
    if (added > 0)
      toast.success(`Added ${added} contact${added > 1 ? "s" : ""}`);
    if (flagged > 0)
      toast.warning(
        `${flagged} imported key${flagged > 1 ? "s" : ""} flagged for weak crypto (SHA-1)`,
      );
    if (skipped > 0) toast.info(`${skipped} already in contacts`);
    if (failed > 0)
      toast.error(
        `${failed} public key${failed > 1 ? "s" : ""} rejected${
          rejectionReasons[0] ? `: ${rejectionReasons[0]}` : ""
        }`,
      );
  };

  const handlePasteNext = async () => {
    setError(null);
    const crxBlobs = onAddCrxKey ? parseCrxKeyBlocks(text) : [];
    const { publicKeys, privateKeys } = splitArmoredKeyBlocks(text);
    if (
      publicKeys.length === 0 &&
      privateKeys.length === 0 &&
      crxBlobs.length === 0
    ) {
      setError("No keys found in the input.");
      return;
    }

    setImporting(true);
    try {
      if (crxBlobs.length > 0 && onAddCrxKey) {
        for (const blob of crxBlobs) await onAddCrxKey(blob);
        toast.success(
          `Imported ${crxBlobs.length} CRX signing key${crxBlobs.length > 1 ? "s" : ""}`,
        );
      }
      const existing = new Set(myKeys.map((k) => k.keyId));
      const privates: ParsedPrivate[] = [];
      let skipped = 0;
      let unparseable = 0;
      for (const block of privateKeys) {
        try {
          const result = await importKey(block);
          if (result.type !== "private") {
            unparseable++;
            continue;
          }
          if (existing.has(result.keyInfo.keyId)) {
            skipped++;
            continue;
          }
          privates.push({
            armored: block,
            keyInfo: result.keyInfo,
            secretEncrypted: result.secretEncrypted,
          });
        } catch {
          unparseable++;
        }
      }

      if (unparseable > 0) {
        setError(
          `${unparseable} private key${unparseable > 1 ? "s" : ""} could not be parsed.`,
        );
      }

      if (privates.length === 0) {
        // Nothing to protect -- import the public keys and finish.
        await importPublics(publicKeys);
        if (skipped > 0)
          toast.info(
            `${skipped} private key${skipped > 1 ? "s" : ""} already imported`,
          );
        if (unparseable === 0) resetAndClose();
        return;
      }

      setParsedPrivates(privates);
      setPublicBlocks(publicKeys);
      setSkippedPrivates(skipped);
      setStep(privates.some((p) => p.secretEncrypted) ? "unlock" : "protect");
    } finally {
      setImporting(false);
    }
  };

  const handleProtectSubmit = async () => {
    setError(null);

    if (method === "password") {
      const pwError = validatePassword(password, confirmPassword);
      if (pwError) {
        setError(pwError);
        return;
      }
    }

    setImporting(true);
    let prfOutput: Uint8Array | undefined;
    try {
      // One WebAuthn ceremony for the whole batch: resolve the
      // credential (reuse or register), authenticate once, and hand the
      // PRF output to every importAndProtect call below.
      let passkeyReuse:
        | { credentialId: string; prfOutput: Uint8Array; prfSalt: ArrayBuffer }
        | undefined;
      if (method === "passkey") {
        let credentialId =
          reusePasskey && reusePasskeyCredentialId
            ? reusePasskeyCredentialId
            : undefined;
        if (!credentialId) {
          const reg = await registerPasskey(
            "PGP Tools Import",
            "PGP Tools Import",
          );
          if (!reg.prfEnabled) {
            throw new Error(
              "Your authenticator doesn't support PRF. Try a different passkey or use a password instead.",
            );
          }
          credentialId = reg.credentialId;
        }
        const prfSalt = generatePrfSalt();
        ({ prfOutput } = await authenticateAndGetPrf(credentialId, prfSalt));
        passkeyReuse = { credentialId, prfOutput, prfSalt };
      }

      let imported = 0;
      for (const key of parsedPrivates) {
        try {
          const { blob } = await importAndProtect(
            key.armored,
            key.secretEncrypted ? sourcePassphrase : null,
            passkeyReuse
              ? {
                  method: "passkey",
                  reusePasskeyCredentialId: passkeyReuse.credentialId,
                  prfReuse: {
                    prfOutput: passkeyReuse.prfOutput,
                    prfSalt: passkeyReuse.prfSalt,
                  },
                }
              : { method: "password", password },
            { userIdHint: key.keyInfo.userIds[0] ?? "Imported PGP Key" },
          );
          await onAddKey(blob);
          imported++;
        } catch (e) {
          // A wrong source passphrase fails every encrypted key the same
          // way -- stop at the first failure instead of piling up errors.
          if (imported > 0)
            toast.success(
              `Imported ${imported} private key${imported > 1 ? "s" : ""}`,
            );
          const name = key.keyInfo.userIds[0] ?? key.keyInfo.keyId.slice(-8);
          setError(
            `Failed to import "${name}": ${
              e instanceof Error ? e.message : "unknown error"
            }`,
          );
          if (key.secretEncrypted) setStep("unlock");
          return;
        }
      }

      toast.success(
        `Imported ${imported} private key${imported > 1 ? "s" : ""}`,
      );
      if (skippedPrivates > 0)
        toast.info(
          `${skippedPrivates} private key${skippedPrivates > 1 ? "s" : ""} already imported`,
        );
      await importPublics(publicBlocks);
      resetAndClose();
    } catch (e) {
      if (!isWebAuthnCancel(e)) {
        setError(e instanceof Error ? e.message : "Import failed");
      }
    } finally {
      prfOutput?.fill(0);
      setImporting(false);
    }
  };

  const encryptedCount = parsedPrivates.filter((p) => p.secretEncrypted).length;

  return (
    <Dialog open={open} onClose={resetAndClose} title="Import Keys">
      {step === "paste" && (
        <div className="space-y-3">
          <p className="text-muted-foreground text-xs">
            Paste or browse for a key file -- for example one from "Export All
            Keys". Private keys are re-protected with your chosen method; public
            keys become contacts.
          </p>
          <textarea
            placeholder="Paste keys here, or browse for a file..."
            value={text}
            onChange={(e) => setText(e.target.value)}
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
              if (file) setText(await file.text());
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
              disabled={importing || !text.trim()}
            >
              {importing ? "Importing..." : "Next"}
            </Button>
          </div>
        </div>
      )}

      {step === "unlock" && (
        <div className="space-y-3">
          <p className="text-muted-foreground text-xs">
            {encryptedCount} of the {parsedPrivates.length} private key
            {parsedPrivates.length > 1 ? "s are" : " is"} protected with a
            passphrase. Enter it to unlock them -- you'll then re-protect every
            key with your chosen method on the next step.
          </p>
          <input
            type="password"
            autoFocus
            autoComplete="current-password"
            value={sourcePassphrase}
            onChange={(e) => setSourcePassphrase(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && sourcePassphrase) {
                setError(null);
                setStep("protect");
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
              onClick={() => {
                setError(null);
                setStep("protect");
              }}
              disabled={importing || !sourcePassphrase}
            >
              Next
            </Button>
          </div>
        </div>
      )}

      {step === "protect" && (
        <div className="space-y-3">
          <p className="text-muted-foreground text-xs">
            Choose how to protect the {parsedPrivates.length} imported private
            key{parsedPrivates.length > 1 ? "s" : ""}.
          </p>
          <ProtectionMethodPicker
            method={method}
            onMethodChange={setMethod}
            password={password}
            onPasswordChange={setPassword}
            confirmPassword={confirmPassword}
            onConfirmPasswordChange={setConfirmPassword}
            error={error}
            onSubmit={() => void handleProtectSubmit()}
            onBack={() => {
              setStep(encryptedCount > 0 ? "unlock" : "paste");
              setError(null);
            }}
            submitting={importing}
            submitLabel={`Import ${parsedPrivates.length} key${parsedPrivates.length > 1 ? "s" : ""}`}
            reusePasskeyCredentialId={reusePasskeyCredentialId}
            reusePasskey={reusePasskey}
            onReusePasskeyChange={setReusePasskey}
          />
        </div>
      )}
    </Dialog>
  );
}
