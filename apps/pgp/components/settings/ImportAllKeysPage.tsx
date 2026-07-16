import { useRef, useState } from "react";

import { Button } from "@amibeingpwned/ui/button";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { KeyInfo } from "../../lib/pgp/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { SubPageAction } from "../shared/SubPage";
import { splitArmoredKeyBlocks } from "../../lib/armor-blocks";
import { parseCrxKeyBlocks } from "../../lib/crx/backup";
import { crxBlobIdentityMatches } from "../../lib/crx/types";
import { importPublicKeyBlocks } from "../../lib/import-public-keys";
import { importKey } from "../../lib/pgp/key-management";
import { importAndProtect } from "../../lib/protection/protect-flow";
import {
  authenticateAndGetPrf,
  generatePrfSalt,
  isWebAuthnCancel,
  registerPasskey,
} from "../../lib/protection/webauthn-prf";
import { toast } from "../../lib/toast";
import {
  getDefaultProtectionMethod,
  ProtectionMethodPicker,
  validatePassword,
} from "../keys/ProtectionMethodPicker";
import { SubPage } from "../shared/SubPage";

type Step = "paste" | "unlock" | "protect";

interface ParsedPrivate {
  armored: string;
  keyInfo: KeyInfo;
  secretEncrypted: boolean;
}

interface ImportAllKeysPageProps {
  /** Called after the slide-out finishes (parent unmounts the page). */
  onClose: () => void;
  myKeys: ProtectedKeyBlob[];
  contacts: PublicContactKey[];
  onAddKey: (blob: ProtectedKeyBlob) => Promise<void>;
  onAddContact: (contact: PublicContactKey) => Promise<void>;
  /** Restore CRX signing keys found in the backup (self-protected blobs). */
  onAddCrxKey?: (blob: CrxSigningKeyBlob) => Promise<void>;
  /** Currently stored CRX keys, for skip-if-present dedupe (mirrors the
   *  PGP path's keyId dedupe — an import must never overwrite a live key). */
  crxKeys?: CrxSigningKeyBlob[];
  /** Pass the primary key's passkey credential ID to allow reuse. */
  reusePasskeyCredentialId?: string;
}

/**
 * Bulk import subpage: accepts a pasted/browsed dump with any mix of
 * armored private and public keys (e.g. a file from "Export all keys").
 * Private keys share one source passphrase (the export wrote them under
 * a single passphrase) and are re-protected under one chosen method --
 * for passkeys, a single WebAuthn ceremony covers every key via PRF
 * reuse. Public keys become contacts.
 */
export function ImportAllKeysPage({
  onClose,
  myKeys,
  contacts,
  onAddKey,
  onAddContact,
  onAddCrxKey,
  crxKeys,
  reusePasskeyCredentialId,
}: ImportAllKeysPageProps) {
  const [step, setStep] = useState<Step>("paste");
  const [text, setText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);
  const [parsedPrivates, setParsedPrivates] = useState<ParsedPrivate[]>([]);
  const [publicBlocks, setPublicBlocks] = useState<string[]>([]);
  const [parsedCrx, setParsedCrx] = useState<CrxSigningKeyBlob[]>([]);
  const [skippedPrivates, setSkippedPrivates] = useState(0);
  const [sourcePassphrase, setSourcePassphrase] = useState("");
  const [method, setMethod] = useState(getDefaultProtectionMethod);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [reusePasskey, setReusePasskey] = useState(true);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const importPublics = async (blocks: string[]) => {
    if (blocks.length === 0) return;
    const { added, updated, failed, flagged, rejectionReasons } =
      await importPublicKeyBlocks(
        blocks,
        contacts.map((c) => c.keyId),
        onAddContact,
      );
    // Stable ids: re-running the import with the same backup must update
    // the previous toasts, not stack duplicates.
    if (added > 0)
      toast.success(`Added ${added} contact${added > 1 ? "s" : ""}`, {
        id: "contacts-added",
      });
    if (flagged > 0)
      toast.warning(
        `${flagged} imported key${flagged > 1 ? "s" : ""} flagged for weak crypto (SHA-1)`,
        { id: "contacts-flagged" },
      );
    if (updated > 0)
      toast.info(`${updated} contact${updated > 1 ? "s" : ""} updated`, {
        id: "contacts-updated",
      });
    if (failed > 0)
      toast.error(
        `${failed} public key${failed > 1 ? "s" : ""} rejected${
          rejectionReasons[0] ? `: ${rejectionReasons[0]}` : ""
        }`,
        { id: "contacts-rejected" },
      );
  };

  /** Commit the parsed CRX blobs (already identity-checked and deduped at
   *  the paste step). Runs at the same point PGP keys are written — never
   *  before the user has passed the whole flow. */
  const importCrxBlobs = async (blobs: CrxSigningKeyBlob[]) => {
    if (blobs.length === 0 || !onAddCrxKey) return;
    let added = 0;
    const failures: string[] = [];
    for (const blob of blobs) {
      try {
        await onAddCrxKey(blob);
        added++;
      } catch (e) {
        failures.push(
          `${blob.label ?? blob.extensionId.slice(0, 8)}: ${
            e instanceof Error ? e.message : "unknown error"
          }`,
        );
      }
    }
    if (failures.length > 0)
      toast.error(
        `${failures.length} CRX key${failures.length > 1 ? "s" : ""} failed to restore`,
        { id: "crx-restore-failed", description: failures[0] },
      );
    if (added > 0)
      toast.success(
        `Restored ${added} CRX signing key${added > 1 ? "s" : ""}`,
        { id: "crx-restored" },
      );
  };

  const handlePasteNext = async (close: () => void) => {
    setError(null);
    const crxBlocks = onAddCrxKey ? parseCrxKeyBlocks(text) : [];
    const { publicKeys, privateKeys } = splitArmoredKeyBlocks(text);
    if (
      publicKeys.length === 0 &&
      privateKeys.length === 0 &&
      crxBlocks.length === 0
    ) {
      setError("No keys found in the input.");
      return;
    }

    setImporting(true);
    try {
      // Vet CRX blocks now, write them only at the end of the flow:
      // - a blob whose public key doesn't hash to its extension id is
      //   forged/corrupt (the field isn't AEAD-covered) -> reject;
      // - an extension id we already hold is skipped, never overwritten
      //   (an old backup must not clobber the live signing key).
      const existingCrx = new Set((crxKeys ?? []).map((k) => k.extensionId));
      const crxBlobs: CrxSigningKeyBlob[] = [];
      let skippedCrx = 0;
      let invalidCrx = 0;
      for (const blob of crxBlocks) {
        if (!(await crxBlobIdentityMatches(blob))) {
          invalidCrx++;
        } else if (existingCrx.has(blob.extensionId)) {
          skippedCrx++;
        } else {
          crxBlobs.push(blob);
        }
      }
      if (skippedCrx > 0)
        toast.info(
          `${skippedCrx} CRX signing key${skippedCrx > 1 ? "s" : ""} already imported`,
          { id: "crx-skipped" },
        );
      if (invalidCrx > 0)
        toast.error(
          `${invalidCrx} CRX signing key${invalidCrx > 1 ? "s" : ""} rejected: public key does not match its extension id`,
          { id: "crx-rejected" },
        );

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
        // Nothing to protect -- import the CRX/public keys and finish.
        await importCrxBlobs(crxBlobs);
        await importPublics(publicKeys);
        if (skipped > 0)
          toast.info(
            `${skipped} private key${skipped > 1 ? "s" : ""} already imported`,
            { id: "private-keys-skipped" },
          );
        if (unparseable === 0) close();
        return;
      }

      setParsedPrivates(privates);
      setPublicBlocks(publicKeys);
      setParsedCrx(crxBlobs);
      setSkippedPrivates(skipped);
      setStep(privates.some((p) => p.secretEncrypted) ? "unlock" : "protect");
    } finally {
      setImporting(false);
    }
  };

  const handleProtectSubmit = async (close: () => void) => {
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
              { id: "private-keys-imported" },
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
        { id: "private-keys-imported" },
      );
      if (skippedPrivates > 0)
        toast.info(
          `${skippedPrivates} private key${skippedPrivates > 1 ? "s" : ""} already imported`,
          { id: "private-keys-skipped" },
        );
      await importCrxBlobs(parsedCrx);
      await importPublics(publicBlocks);
      close();
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

  // Footer per step; the protect step's buttons live inside
  // ProtectionMethodPicker (it owns Back/submit).
  const actions: SubPageAction[] | undefined =
    step === "paste"
      ? [
          {
            text: "Next",
            busyText: "Importing...",
            disabled: !text.trim(),
            onClick: (api) => handlePasteNext(api.close),
          },
          { type: "outline", text: "Cancel" },
        ]
      : step === "unlock"
        ? [
            {
              text: "Next",
              disabled: !sourcePassphrase,
              onClick: () => {
                setError(null);
                setStep("protect");
              },
            },
            {
              type: "outline",
              text: "Back",
              onClick: () => {
                setStep("paste");
                setError(null);
                setSourcePassphrase("");
              },
            },
          ]
        : undefined;

  return (
    <SubPage title="Import keys" onClose={onClose} actions={actions}>
      {(api) => (
        <>
          {step === "paste" && (
            <div className="space-y-3">
              <p className="text-muted-foreground text-xs">
                Paste or browse for a key file -- for example one from "Export
                all keys". Private keys are re-protected with your chosen
                method; public keys become contacts.
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
            </div>
          )}

          {step === "unlock" && (
            <div className="space-y-3">
              <p className="text-muted-foreground text-xs">
                {encryptedCount} of the {parsedPrivates.length} private key
                {parsedPrivates.length > 1 ? "s are" : " is"} protected with a
                passphrase. Enter it to unlock them -- you'll then re-protect
                every key with your chosen method on the next step.
              </p>
              <input
                type="password"
                autoFocus
                autoComplete="current-password"
                value={sourcePassphrase}
                onChange={(e) => setSourcePassphrase(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") api.runAction(0);
                }}
                placeholder="Key passphrase"
                className="border-border bg-background placeholder:text-muted-foreground focus:ring-ring w-full rounded-md border p-2 font-mono text-xs focus:ring-2 focus:outline-none"
              />
              {error && (
                <p className="text-destructive text-xs" role="alert">
                  {error}
                </p>
              )}
            </div>
          )}

          {step === "protect" && (
            <div className="space-y-3">
              <p className="text-muted-foreground text-xs">
                Choose how to protect the {parsedPrivates.length} imported
                private key{parsedPrivates.length > 1 ? "s" : ""}.
              </p>
              <ProtectionMethodPicker
                method={method}
                onMethodChange={setMethod}
                password={password}
                onPasswordChange={setPassword}
                confirmPassword={confirmPassword}
                onConfirmPasswordChange={setConfirmPassword}
                error={error}
                onSubmit={() => void handleProtectSubmit(api.close)}
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
        </>
      )}
    </SubPage>
  );
}
