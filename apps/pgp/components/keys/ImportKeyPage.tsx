import { useEffect, useRef, useState } from "react";
import { LoaderIcon, UploadCloudIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import type { CrxProtectionInput } from "../../lib/crx/operations";
import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { IncomingKey } from "../../lib/import/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { readKeyFile } from "../../lib/binary-armor";
import { importCrxKey } from "../../lib/crx/operations";
import { importable, prepareImport } from "../../lib/import/prepare";
import { importAndProtect } from "../../lib/protection/protect-flow";
import { toast } from "../../lib/toast";
import { errorMessage } from "../../lib/utils/errors";
import { INPUT_CLASS } from "../../lib/utils/styles";
import {
  SlideOverHeader,
  SlideOverPanel,
  useSlideOver,
} from "../shared/SlideOver";
import { ImportPreview } from "./ImportPreviewPage";
import {
  getDefaultProtectionMethod,
  ProtectionMethodPicker,
  validatePassword,
} from "./ProtectionMethodPicker";

type Step = "source" | "preview" | "protect";

/** "⌘V" on a Mac, "Ctrl+V" everywhere else. */
function modKeyLabel(): string {
  return navigator.platform.includes("Mac") ? "⌘V" : "Ctrl+V";
}

/** A raw RSA private key PEM (PKCS#8 or PKCS#1) — a CRX signing key, not
 *  OpenPGP. Matched only when it is NOT a PGP armored block. */
const RSA_PEM_RE = /-----BEGIN (?:RSA )?PRIVATE KEY-----/;
function isRsaPrivatePem(text: string): boolean {
  return RSA_PEM_RE.test(text) && !text.includes("PGP");
}

interface ImportKeyPageProps {
  /** Called after the slide-out finishes (cancel or success). */
  onClose: () => void;
  onImportPrivate: (blob: ProtectedKeyBlob) => Promise<void>;
  onImportPublic: (contact: PublicContactKey) => Promise<void>;
  /** Current keyring/contacts: what an incoming key is compared against
   *  to decide new / update / already-imported. */
  existingKeys?: ProtectedKeyBlob[];
  existingContacts?: PublicContactKey[];
  /** Pass the primary key's passkey credential ID to allow reuse. */
  reusePasskeyCredentialId?: string;
  /** When provided, skip the source step and preview this armored key
   *  (e.g. from a global drop). Read once at mount. */
  initialArmored?: string | null;
  /** When true, also accept a raw RSA private key PEM as a CRX signing key. */
  crxSigningEnabled?: boolean;
  /** Persist an imported CRX signing key. Required for the CRX path. */
  onImportCrx?: (blob: CrxSigningKeyBlob) => Promise<void>;
  /** Fingerprints to scroll to and highlight once the panel slides away:
   *  what was just written, or -- with `reveal` -- a key that was already
   *  stored and the user asked to be shown. `reveal` also means "the user
   *  wants to look at the list", so the caller should stay on it. */
  onImported?: (keyIds: string[], opts?: { reveal?: boolean }) => void;
}

/**
 * Key import: get a key, look at it, import it.
 *
 * The old flow opened on a textarea full of armor and made you press
 * Next to find out whose key it was and whether you already had it. This
 * one parses first and shows the key -- identity, fingerprint, health,
 * and whether it's new, an update, or already stored -- so the armor is
 * never rendered at all. Private keys pick up one extra step to choose
 * how the secret is protected at rest.
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
  onImported,
}: ImportKeyPageProps) {
  const crxEnabled = !!crxSigningEnabled && !!onImportCrx;
  const { entered, close } = useSlideOver(onClose);
  const [step, setStep] = useState<Step>("source");
  const [label, setLabel] = useState("");
  const [method, setMethod] = useState(getDefaultProtectionMethod);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [importing, setImporting] = useState(false);
  const [parsing, setParsing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reusePasskey, setReusePasskey] = useState(true);
  const [sourcePassphrase, setSourcePassphrase] = useState("");
  const [dragOver, setDragOver] = useState(false);
  // Re-entrancy guard for the parse. A ref, not the `parsing` state: two
  // handlers can fire for one gesture (the paste box and the panel-wide
  // listener) inside a single render, before state catches up.
  const parsingRef = useRef(false);
  // The paste box swallows typing (it holds nothing); say why rather
  // than looking broken when someone starts typing into it.
  const [typedIntoPasteBox, setTypedIntoPasteBox] = useState(false);
  /** The key being previewed/imported. Safe for React state: it carries
   *  the PUBLIC armor only (see IncomingKey). */
  const [incoming, setIncoming] = useState<IncomingKey | null>(null);
  const [isCrx, setIsCrx] = useState(false);
  const [secretEncrypted, setSecretEncrypted] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Secret key material is the crown jewel, so it lives in refs rather than
  // useState. A ref is a single mutable slot shared by both of a fiber's
  // double-buffered copies, so clearing it on close drops the only
  // reference -- whereas a useState value is snapshotted into the previous
  // fiber, which React keeps alive for the whole slide-out animation,
  // leaving the private key lingering in the GC heap (see SECURITY.md's
  // zeroization table).
  const secretArmorRef = useRef<string | null>(null);
  /** Raw source text for the CRX path, which has no OpenPGP parse. */
  const crxPemRef = useRef<string | null>(null);

  const clearSecrets = () => {
    secretArmorRef.current = null;
    crxPemRef.current = null;
  };

  const resetAndClose = () => {
    // Drop key material before the panel slides out: because it's in refs
    // (not double-buffered state) this releases the only reference, so the
    // animation runs without holding secrets in the JS heap.
    clearSecrets();
    close();
  };

  const finish = (keyIds: string[], opts?: { reveal?: boolean }) => {
    clearSecrets();
    onImported?.(keyIds, opts);
    close();
  };

  const importPublicKeys = async (keys: IncomingKey[]) => {
    setImporting(true);
    try {
      for (const key of keys) {
        await onImportPublic({
          keyId: key.keyId,
          userIds: key.userIds,
          algorithm: key.info?.algorithm ?? "",
          armoredPublicKey: key.publicArmored,
          addedAt: Date.now(),
          lastUsedAt: Date.now(),
          expiresAt: key.info?.expiresAt ?? null,
          // Sign-only keys are valid contacts (for verification) but can't
          // be offered as encryption recipients -- record which is which.
          usableForEncryption: key.info?.usableForEncryption ?? true,
          // Allowed, but flagged (e.g. SHA-1 binding signature).
          securityWarning: key.securityWarning,
        });
      }
      const flagged = keys.filter((k) => k.securityWarning).length;
      if (flagged > 0) {
        toast.warning(
          `${flagged} key${flagged > 1 ? "s use" : " uses"} weak crypto (SHA-1) and ${
            flagged > 1 ? "were" : "was"
          } flagged - see the warning on the contact.`,
          { id: "contacts-flagged" },
        );
      }
      // Only bundles get a toast: a single import is confirmed by the
      // card lighting up in the list behind the panel.
      if (keys.length > 1) {
        const added = keys.filter((k) => k.status === "new").length;
        const updated = keys.filter((k) => k.status === "update").length;
        if (added > 0) {
          toast.success(`Added ${added} contact${added > 1 ? "s" : ""}`, {
            id: "contacts-added",
          });
        }
        if (updated > 0) {
          toast.info(`${updated} contact${updated > 1 ? "s" : ""} updated`, {
            id: "contacts-updated",
          });
        }
      }
      finish(keys.map((k) => k.keyId));
    } catch (e) {
      setError(errorMessage(e, "Import failed"));
      setImporting(false);
    }
  };

  /**
   * Classify pasted/dropped/browsed text and route it: a CRX PEM goes
   * straight to protection, a bundle of several importable keys imports
   * in one go (no point previewing five certs one at a time), and a
   * single key gets the preview.
   */
  const handleSource = async (text: string) => {
    setError(null);
    if (!text.trim() || parsingRef.current) return;

    if (crxEnabled && isRsaPrivatePem(text)) {
      crxPemRef.current = text.trim();
      setIsCrx(true);
      setStep("protect");
      return;
    }

    setParsing(true);
    parsingRef.current = true;
    try {
      const prepared = await prepareImport(text, {
        own: existingKeys.map((k) => ({
          keyId: k.keyId,
          userIds: k.userIds,
          armored: k.publicKeyArmored,
          createdAt: k.createdAt,
        })),
        contacts: existingContacts.map((c) => ({
          keyId: c.keyId,
          userIds: c.userIds,
          armored: c.armoredPublicKey,
          addedAt: c.addedAt,
          expiresAt: c.expiresAt,
        })),
      });

      if (prepared.unparseable || prepared.keys.length === 0) {
        setError(
          "That doesn't look like a PGP key. Paste an armored key block, or browse for a .asc file.",
        );
        return;
      }

      const worthImporting = importable(prepared.keys);

      // A bundle of public keys: import the lot. Previewing five certs
      // one at a time would be worse than the summary toast.
      if (
        worthImporting.length > 1 &&
        worthImporting.every((k) => k.kind === "public")
      ) {
        await importPublicKeys(worthImporting);
        return;
      }

      const key = worthImporting[0] ?? prepared.keys[0];
      if (key.kind === "private") {
        const secret = prepared.secrets.get(key.keyId);
        if (!secret) {
          setError("Could not read that private key.");
          return;
        }
        secretArmorRef.current = secret;
        setSecretEncrypted(await isSecretProtected(secret));
      }
      if (key.securityWarning) {
        // Stable id: re-pasting the same key must not stack duplicates.
        toast.warning(key.securityWarning, { id: "import-key-warning" });
      }
      setIncoming(key);
      setStep("preview");
    } catch (e) {
      setError(errorMessage(e, "Import failed"));
    } finally {
      setParsing(false);
      parsingRef.current = false;
    }
  };

  // Keep the latest handler reachable from the document listeners below
  // without re-binding them on every render (the useShortcut idiom).
  const handleSourceRef = useRef(handleSource);
  useEffect(() => {
    handleSourceRef.current = handleSource;
  });

  // A drop/paste that arrived with the panel (global drop, workspace
  // banner) skips the source step entirely: parse it and show the key.
  const prefill = useRef(initialArmored ?? null);
  /** True when the panel opened with a key already in hand, so there is
   *  no source step behind the preview. */
  const openedWithKey = useRef(!!initialArmored);
  useEffect(() => {
    const text = prefill.current;
    prefill.current = null;
    if (text) void handleSourceRef.current(text);
  }, []);

  // Paste anywhere on the source step -- there's no textarea to aim at.
  useEffect(() => {
    if (step !== "source") return;
    const onPaste = (e: ClipboardEvent) => {
      const text = e.clipboardData?.getData("text/plain");
      if (!text?.trim()) return;
      e.preventDefault();
      void handleSourceRef.current(text);
    };
    document.addEventListener("paste", onPaste);
    return () => document.removeEventListener("paste", onPaste);
  }, [step]);

  const handleConfirm = () => {
    if (!incoming) return;
    if (incoming.kind === "public") {
      void importPublicKeys([incoming]);
      return;
    }
    setStep("protect");
  };

  const handleBack = () => {
    if (importing || parsing) return;
    setError(null);
    if (step === "protect") {
      // The CRX path has no preview to go back to.
      if (isCrx) {
        crxPemRef.current = null;
        setIsCrx(false);
        setStep("source");
      } else {
        setStep("preview");
      }
    } else if (step === "preview") {
      // Opened with a key already in hand (a drop, or the workspace
      // banner): there is no source step behind this one, so Back means
      // "leave" -- not "here's an empty drop zone you never used".
      if (openedWithKey.current) {
        resetAndClose();
        return;
      }
      secretArmorRef.current = null;
      setIncoming(null);
      setStep("source");
    } else {
      resetAndClose();
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
    const secret = secretArmorRef.current;
    if (!incoming || !secret) {
      setError("No key to import.");
      return;
    }
    if (secretEncrypted && !sourcePassphrase) {
      setError("Enter the key's passphrase.");
      return;
    }

    setImporting(true);
    try {
      const { blob } = await importAndProtect(
        secret,
        secretEncrypted ? sourcePassphrase : null,
        method === "password"
          ? { method: "password", password }
          : {
              method: "passkey",
              reusePasskeyCredentialId: reusePasskey
                ? reusePasskeyCredentialId
                : undefined,
            },
        { userIdHint: incoming.userIds[0] ?? "Imported PGP Key" },
      );
      await onImportPrivate(blob);
      finish([blob.keyId]);
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
    const pem = crxPemRef.current;
    if (!onImportCrx || !pem) return;

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
        pem,
        protection,
        label.trim() || undefined,
      );
      await onImportCrx(blob);
      finish([blob.extensionId]);
    } catch (e) {
      setError(errorMessage(e, "Import failed"));
    } finally {
      setImporting(false);
    }
  };

  const title =
    step === "preview" && incoming?.status === "update"
      ? "Update key"
      : "Import key";

  return (
    <SlideOverPanel entered={entered} ariaLabel="Import key">
      <SlideOverHeader title={title} onBack={handleBack} />
      <div className="flex flex-1 flex-col overflow-hidden">
        {step === "source" && (
          <div className="flex flex-1 flex-col overflow-hidden">
            <div className="flex flex-1 flex-col gap-3 overflow-y-auto p-3">
              {/* A one-line box purely as a target for the paste: it gives
                  the gesture somewhere obvious to land (and somewhere to
                  focus on open), but it never holds the key. The armor is
                  taken straight off the clipboard event and parsed -- so
                  it is never rendered, never in React state, and never in
                  the DOM. Hence the permanently empty value. */}
              <input
                type="text"
                // The slide-over's focus trap picks the first element
                // marked `autofocus` -- but React consumes its own
                // autoFocus prop rather than rendering the attribute, so
                // mark the node itself. Without this the trap lands on
                // the header's Back button and the paste has no home.
                ref={(el) => el?.setAttribute("autofocus", "")}
                spellCheck={false}
                autoComplete="off"
                aria-label="Paste a key"
                placeholder={`Paste a key with ${modKeyLabel()}`}
                value=""
                disabled={parsing}
                onChange={() => setTypedIntoPasteBox(true)}
                onPaste={(e) => {
                  // Handled here, so the panel-wide listener must not
                  // also fire for this one.
                  e.preventDefault();
                  e.stopPropagation();
                  setTypedIntoPasteBox(false);
                  void handleSource(e.clipboardData.getData("text/plain"));
                }}
                className={INPUT_CLASS}
              />
              {typedIntoPasteBox && (
                <p className="text-muted-foreground -mt-2 text-xs">
                  Paste the whole key block - a key is too long to type out.
                </p>
              )}
              <div
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragOver(true);
                }}
                onDragLeave={() => setDragOver(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setDragOver(false);
                  if (e.dataTransfer.files.length > 0) {
                    void readKeyFile(e.dataTransfer.files[0]).then(
                      handleSource,
                    );
                    return;
                  }
                  void handleSource(e.dataTransfer.getData("text/plain"));
                }}
                className={`flex flex-col items-center justify-center gap-2 rounded-md border-2 border-dashed p-6 text-center transition-colors ${
                  dragOver
                    ? "border-primary bg-primary/10"
                    : "border-border hover:border-muted-foreground/50"
                }`}
              >
                {parsing ? (
                  <>
                    <LoaderIcon className="text-primary h-5 w-5 animate-spin" />
                    <p className="text-muted-foreground text-xs">
                      Reading key...
                    </p>
                  </>
                ) : (
                  <>
                    <UploadCloudIcon className="text-muted-foreground h-6 w-6" />
                    <p className="text-sm font-medium">Drop a key file here</p>
                    <Button
                      variant="outline"
                      size="sm"
                      className="mt-1"
                      onClick={() => fileInputRef.current?.click()}
                    >
                      Browse for key file
                    </Button>
                  </>
                )}
              </div>
              <input
                ref={fileInputRef}
                type="file"
                accept=".asc,.gpg,.pub,.key,.pgp,.txt,.pem"
                className="hidden"
                onChange={async (e) => {
                  const file = e.target.files?.[0];
                  e.target.value = "";
                  if (file) await handleSource(await readKeyFile(file));
                }}
              />
              <p className="text-muted-foreground text-xs">
                Public keys are added as contacts. A private key stays on this
                device - you'll choose how it's protected next.
              </p>
              {error && (
                <p className="text-destructive text-xs" role="alert">
                  {error}
                </p>
              )}
            </div>
          </div>
        )}

        {step === "preview" && incoming && (
          <ImportPreview
            incoming={incoming}
            onConfirm={handleConfirm}
            onDone={resetAndClose}
            // Already stored: close and take the user to it in the list,
            // highlighted, instead of writing anything.
            onReveal={() => finish([incoming.keyId], { reveal: true })}
            busy={importing}
            error={error}
          />
        )}

        {step === "protect" && (
          <div className="flex-1 space-y-3 overflow-y-auto p-3">
            {isCrx && (
              <>
                {/* A CRX key is a bare RSA PEM: there's no OpenPGP cert to
                    preview, so the protect step has to say what was
                    detected -- otherwise this path shows the user nothing
                    at all about what they're importing. */}
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
            )}
            {/* Unlocking the source key and choosing its new protection are
                one screen: they're both "how is this secret handled", and
                splitting them cost a Next press for no decision. */}
            {secretEncrypted && (
              <div className="space-y-1">
                <label className="text-muted-foreground block text-xs">
                  This key is protected with a passphrase
                </label>
                <input
                  type="password"
                  autoFocus
                  autoComplete="current-password"
                  value={sourcePassphrase}
                  onChange={(e) => setSourcePassphrase(e.target.value)}
                  placeholder="Key passphrase"
                  className={INPUT_CLASS}
                />
              </div>
            )}
            <ProtectionMethodPicker
              method={method}
              onMethodChange={setMethod}
              password={password}
              onPasswordChange={setPassword}
              confirmPassword={confirmPassword}
              onConfirmPasswordChange={setConfirmPassword}
              error={error}
              onSubmit={isCrx ? handleImportCrx : handleImportPrivate}
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

/** Whether the secret half carries an S2K passphrase. Imported lazily so
 *  the WASM module isn't pulled in until a private key actually shows up. */
async function isSecretProtected(armored: string): Promise<boolean> {
  const { isSecretEncrypted } = await import("../../lib/pgp/wasm");
  return isSecretEncrypted(armored);
}
