import { useEffect, useRef, useState } from "react";
import { InfoIcon, LoaderIcon, UploadCloudIcon } from "lucide-react";

import { Button, cn, Input } from "@amibeingpwned/ui";

import {
  SlideOverHeader,
  SlideOverPanel,
  useSlideOver,
} from "~/components/shared/SlideOver";
import { engineMessage, useAsyncAction } from "~/hooks";
import { importSshIdentity } from "~/lib/age/protect-flow";
import { recoverArmorIfNeeded } from "~/lib/armor-recovery";
import { readKeyFile } from "~/lib/binary-armor";
import { importCrxKey } from "~/lib/crx/operations";
import type { CrxSigningKeyBlob } from "~/lib/crx/types";
import { AppError } from "~/lib/errors/app-error";
import { t, tn } from "~/lib/i18n";
import { classifyLookup } from "~/lib/import/lookup";
import {
  importable,
  prepareImport,
  storedKeysFrom,
} from "~/lib/import/prepare";
import {
  applyReview,
  defaultDecision,
  type ReviewDecision,
  type ReviewedContact,
} from "~/lib/import/review";
import { runKeyLookup } from "~/lib/import/run-lookup";
import {
  isPublicKind,
  isSecretKind,
  type IncomingKey,
} from "~/lib/import/types";
import { importAndProtect } from "~/lib/protection/protect-flow";
import type { PublicContactKey } from "~/lib/storage/contacts";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import { toast } from "~/lib/toast";
import { ImportPreview } from "./ImportPreviewPage";
import { ImportReview } from "./ImportReview";
import { ProtectionMethodPicker } from "./ProtectionMethodPicker";
import { useProtectionChoice } from "./useProtectionChoice";

/** Every key here is public-only; a secret half lives in a ref. */
type Step =
  | { kind: "source" }
  | {
      kind: "preview";
      incoming: IncomingKey;
      secretEncrypted: boolean;
      grouping?: { separates: IncomingKey[]; name: string };
    }
  | { kind: "review"; keys: IncomingKey[]; secretEncrypted: boolean }
  | { kind: "protect"; incoming: IncomingKey; secretEncrypted: boolean };

type ProtectStep = Extract<Step, { kind: "protect" }>;

function needsReview(keys: IncomingKey[]): boolean {
  return (
    keys.length > 1 ||
    keys.some((k) => k.conflict !== undefined || k.allKeysOff === true)
  );
}

function modKeyLabel(): string {
  return navigator.platform.includes("Mac") ? "⌘V" : "Ctrl+V";
}

interface ImportKeyPageProps {
  onClose: () => void;
  onImportPrivate: (blob: ProtectedKeyBlob) => Promise<void>;
  onImportPublic: (contact: ReviewedContact) => Promise<void>;
  onRemoveContact: (keyId: string) => Promise<void>;
  existingKeys?: ProtectedKeyBlob[];
  existingContacts?: PublicContactKey[];
  reusePasskeyCredentialId?: string;
  /** With reuse, seal under the master's PRF salt so the vault unlock
   *  opens the key. */
  masterSealSalt?: ArrayBuffer;
  /** Read once at mount. */
  initialArmored?: string | null;
  /** Read once at mount; ignored when key discovery is off. */
  initialLookup?: string | null;
  crxSigningEnabled?: boolean;
  /** Defaults to true to match `DEFAULT_PREFERENCES`. */
  keyDiscoveryEnabled?: boolean;
  onImportCrx?: (blob: CrxSigningKeyBlob) => Promise<void>;
  onImported?: (keyIds: string[], opts?: { reveal?: boolean }) => void;
}

/** Key import. The key is parsed and summarised, never rendered as armor. */
export function ImportKeyPage({
  onClose,
  onImportPrivate,
  onImportPublic,
  onRemoveContact,
  existingKeys = [],
  existingContacts = [],
  reusePasskeyCredentialId,
  masterSealSalt,
  initialArmored,
  initialLookup,
  crxSigningEnabled,
  keyDiscoveryEnabled = true,
  onImportCrx,
  onImported,
}: ImportKeyPageProps) {
  const crxEnabled = !!crxSigningEnabled && !!onImportCrx;
  const { entered, close } = useSlideOver(onClose);
  const [step, setStep] = useState<Step>({ kind: "source" });
  const choice = useProtectionChoice({
    reusePasskeyCredentialId,
    masterSealSalt,
  });
  // The engine's text is the message: it says what to fix.
  const parser = useAsyncAction(engineMessage(t("import_failed")));
  const importer = useAsyncAction(engineMessage(t("import_failed")));
  const parsing = parser.busy;
  const importing = importer.busy;
  const error = (parser.error ?? importer.error)?.message ?? null;
  const setError = (message: string | null) => {
    parser.reset();
    importer.setError(message);
  };
  const [label, setLabel] = useState("");
  const [sourcePassphrase, setSourcePassphrase] = useState("");
  const [dragOver, setDragOver] = useState(false);
  const [lookupInput, setLookupInput] = useState(initialLookup ?? "");
  const [notice, setNotice] = useState<string | null>(null);
  const lookupInputRef = useRef<HTMLInputElement>(null);
  const [typedIntoPasteBox, setTypedIntoPasteBox] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Secret half lives in a ref, not state: state is snapshotted into the
  // previous fiber for the whole slide-out (SECURITY.md, zeroization table).
  const secretArmorRef = useRef<string | null>(null);

  const clearSecrets = () => {
    secretArmorRef.current = null;
    // A JS string can't be zeroized; this only bounds the lifetime.
    choice.clear();
    setSourcePassphrase("");
  };

  const resetAndClose = () => {
    clearSecrets();
    close();
  };

  // Set once a write lands: nothing may start a second write.
  const finishedRef = useRef(false);
  const runImport = (task: () => Promise<void>) =>
    finishedRef.current ? Promise.resolve(null) : importer.run(task);

  const finish = (keyIds: string[], opts?: { reveal?: boolean }) => {
    finishedRef.current = true;
    clearSecrets();
    onImported?.(keyIds, opts);
    close();
  };

  const toSource = () => {
    // Never pre-fill one key file's passphrase for the next.
    secretArmorRef.current = null;
    setSourcePassphrase("");
    setStep({ kind: "source" });
  };

  const show = (keys: IncomingKey[], secretEncrypted = false) => {
    if (keys.length === 0) {
      parser.setError(t("import_unreadable"));
    } else if (needsReview(keys)) {
      setStep({ kind: "review", keys, secretEncrypted });
    } else {
      setStep({ kind: "preview", incoming: keys[0], secretEncrypted });
    }
  };

  const importPublicKeys = (
    keys: IncomingKey[],
    decisions: ReadonlyMap<string, ReviewDecision> = new Map(),
  ) =>
    runImport(async () => {
      const outcome = await applyReview(keys, decisions, {
        contacts: existingContacts,
        add: onImportPublic,
        remove: onRemoveContact,
      });
      const saved = new Set(outcome.keyIds);
      const flagged = keys.filter(
        (k) => saved.has(k.keyId) && k.securityWarning?.includes("SHA-1"),
      ).length;
      if (flagged > 0) {
        toast.warning(tn("import_flagged_toast", flagged), {
          id: "contacts-flagged",
        });
      }
      if (outcome.replaced > 0) {
        toast.info(tn("import_replaced_contacts", outcome.replaced), {
          id: "contacts-replaced",
        });
      }
      if (keys.length > 1) {
        const { added, updated } = outcome;
        if (added > 0) {
          toast.success(tn("import_added_contacts", added), {
            id: "contacts-added",
          });
        }
        if (updated > 0) {
          toast.info(tn("import_updated_contacts", updated), {
            id: "contacts-updated",
          });
        }
      }
      finish(outcome.keyIds);
    });

  const storedForImport = () => storedKeysFrom(existingKeys, existingContacts);

  const handleSource = async (text: string) => {
    setError(null);
    setNotice(null);
    // One guard for parse and lookup: the box and the panel-wide listener
    // can both fire.
    if (!text.trim() || parser.inFlight) return;
    await parser.run(async () => {
      const prepared = await prepareImport(text, storedForImport(), {
        crx: crxEnabled,
        ssh: true,
      });

      if (prepared.unparseable || prepared.keys.length === 0) {
        parser.setError(t("import_unreadable"));
        return;
      }

      const worthImporting = importable(prepared.keys);

      // Ambiguous SSH names: ask, unless one claims an identity (a blank name
      // would save it without the Review's decision).
      if (prepared.groupProposal && !worthImporting.some((k) => k.conflict)) {
        setStep({
          kind: "preview",
          incoming: prepared.groupProposal,
          secretEncrypted: false,
          grouping: { separates: worthImporting, name: "" },
        });
        return;
      }

      if (
        worthImporting.length > 1 &&
        worthImporting.every((k) => isPublicKind(k.kind))
      ) {
        show(prepared.keys.filter((k) => isPublicKind(k.kind)));
        return;
      }

      const key = worthImporting[0] ?? prepared.keys[0];
      let secretEncrypted = false;
      if (isSecretKind(key.kind)) {
        const secret = prepared.secrets.get(key.keyId);
        if (!secret) {
          parser.setError(t("import_private_unreadable"));
          return;
        }
        secretArmorRef.current = secret;
        // Only OpenPGP secrets are probed; the engine asks for an SSH passphrase.
        secretEncrypted =
          key.kind === "pgp-private" ? await isSecretProtected(secret) : false;
      }
      if (key.securityWarning) {
        // Stable id: re-pasting must not stack duplicates.
        toast.warning(key.securityWarning, { id: "import-key-warning" });
      }
      show([key], secretEncrypted);
    });
  };

  /** A 40-hex string is a GitHub name AND a fingerprint; see `classifyLookup`. */
  const runLookup = async (input = lookupInput) => {
    setError(null);
    setNotice(null);
    if (parser.inFlight) return;
    const routed = classifyLookup(input);
    if (!routed) {
      parser.setError(t("import_lookup_invalid"));
      return;
    }
    await parser.run(
      async () => {
        const outcome = await runKeyLookup(routed, {
          own: existingKeys,
          contacts: existingContacts,
        });
        if (outcome.kind === "notice") setNotice(outcome.message);
        else if (outcome.kind === "error") parser.setError(outcome.message);
        else {
          for (const w of outcome.warnings)
            toast.warning(w.message, { id: w.id });
          show(outcome.keys);
        }
      },
      engineMessage(t("import_lookup_failed")),
    );
  };

  /** Only pasted text gets armor repair; a file on disk has its newlines. */
  const handleTextSource = (text: string) =>
    handleSource(recoverArmorIfNeeded(text));

  const handleSourceRef = useRef(handleTextSource);
  const runLookupRef = useRef(runLookup);
  useEffect(() => {
    handleSourceRef.current = handleTextSource;
    runLookupRef.current = runLookup;
  });

  const prefill = useRef(initialArmored ?? null);
  const openedWithKey = useRef(!!initialArmored);
  useEffect(() => {
    const text = prefill.current;
    prefill.current = null;
    if (text) void handleSourceRef.current(text);
  }, []);

  const lookupPrefill = useRef(keyDiscoveryEnabled ? initialLookup : null);
  useEffect(() => {
    const query = lookupPrefill.current;
    lookupPrefill.current = null;
    if (query) void runLookupRef.current(query);
  }, []);

  const stepKind = step.kind;
  useEffect(() => {
    if (stepKind !== "source") return;
    const onPaste = (e: ClipboardEvent) => {
      const target = e.target;
      if (
        target instanceof Node &&
        lookupInputRef.current?.contains(target) === true
      ) {
        return;
      }
      const text = e.clipboardData?.getData("text/plain");
      if (!text?.trim()) return;
      e.preventDefault();
      void handleSourceRef.current(text);
    };
    document.addEventListener("paste", onPaste);
    return () => document.removeEventListener("paste", onPaste);
  }, [stepKind]);

  const handleConfirm = () => {
    if (step.kind !== "preview") return;
    const { incoming, grouping } = step;
    if (grouping) {
      const name = grouping.name.trim();
      if (!name || !incoming.group) {
        void importPublicKeys(grouping.separates);
        return;
      }
      void importPublicKeys([
        {
          ...incoming,
          userIds: [name],
          group: { ...incoming.group, label: name },
        },
      ]);
      return;
    }
    if (isPublicKind(incoming.kind)) {
      void importPublicKeys([incoming]);
      return;
    }
    setStep({
      kind: "protect",
      incoming,
      secretEncrypted: step.secretEncrypted,
    });
  };

  const handleBack = () => {
    if (importing || parsing) return;
    setError(null);
    setNotice(null);
    switch (step.kind) {
      case "protect":
        setStep({
          kind: "preview",
          incoming: step.incoming,
          secretEncrypted: step.secretEncrypted,
        });
        return;
      case "review":
      case "preview":
        if (openedWithKey.current) resetAndClose();
        else toSource();
        return;
      case "source":
        resetAndClose();
    }
  };

  const handleImportPrivate = async ({
    incoming,
    secretEncrypted,
  }: ProtectStep) => {
    const secret = secretArmorRef.current;
    if (!secret) {
      setError(t("import_no_key"));
      return;
    }
    if (secretEncrypted && !sourcePassphrase) {
      setError(t("import_enter_passphrase"));
      return;
    }
    await runImport(async () => {
      const { blob } = await importAndProtect(
        secret,
        secretEncrypted ? sourcePassphrase : null,
        choice.toInput(),
        { userIdHint: incoming.userIds[0] ?? t("import_default_pgp_name") },
      );
      await onImportPrivate(blob);
      finish([blob.keyId]);
    });
  };

  const handleImportCrx = async () => {
    const pem = secretArmorRef.current;
    if (!onImportCrx || !pem) return;
    await runImport(async () => {
      const blob = await importCrxKey(
        pem,
        choice.toCrxInput(),
        label.trim() || undefined,
      );
      await onImportCrx(blob);
      finish([blob.extensionId]);
    });
  };

  /** OpenSSH key crosses into wasm as BYTES, wiped there, so each attempt
   *  encodes a fresh copy. */
  const handleImportSsh = async ({
    incoming,
    secretEncrypted,
  }: ProtectStep) => {
    if (secretEncrypted && !sourcePassphrase) {
      setError(t("import_enter_passphrase"));
      return;
    }
    const keyText = secretArmorRef.current;
    if (!keyText) {
      setError(t("import_no_key"));
      return;
    }
    await runImport(async () => {
      try {
        const { blob } = await importSshIdentity(
          new TextEncoder().encode(keyText),
          sourcePassphrase || null,
          choice.toInput(),
          { userIdHint: incoming.userIds[0] ?? t("import_default_ssh_name") },
        );
        await onImportPrivate(blob);
        secretArmorRef.current = null;
        finish([blob.keyId]);
      } catch (e) {
        // Keyed on the tagged code, never the engine's wording.
        if (e instanceof AppError && e.code === "ssh-passphrase-required") {
          setStep((s) =>
            s.kind === "protect" ? { ...s, secretEncrypted: true } : s,
          );
        }
        throw e;
      }
    });
  };

  const handleProtectSubmit = () => {
    if (step.kind !== "protect") return;
    const invalid = choice.validate();
    if (invalid) {
      setError(invalid);
      return;
    }
    switch (step.incoming.kind) {
      case "crx":
        void handleImportCrx();
        return;
      case "ssh-private":
        void handleImportSsh(step);
        return;
      default:
        void handleImportPrivate(step);
    }
  };

  const title =
    step.kind === "review"
      ? t("import_review_title")
      : step.kind === "preview" && step.incoming.status === "update"
        ? t("import_title_update")
        : t("import_title");

  return (
    <SlideOverPanel
      entered={entered}
      ariaLabel={t("import_title")}
      onDismiss={close}
    >
      <SlideOverHeader title={title} onBack={handleBack} />
      <div className="flex flex-1 flex-col overflow-hidden">
        {step.kind === "source" && (
          <div className="flex flex-1 flex-col overflow-hidden">
            <div className="flex flex-1 flex-col gap-3 overflow-y-auto p-3">
              {/* Paste target only: armor is never rendered, in state, or
                  in the DOM. */}
              <Input
                type="text"
                // React consumes autoFocus; the focus trap needs the attribute.
                ref={(el) => el?.setAttribute("autofocus", "")}
                spellCheck={false}
                autoComplete="off"
                aria-label={t("import_paste_label")}
                placeholder={t("import_paste_placeholder", {
                  shortcut: modKeyLabel(),
                })}
                value=""
                disabled={parsing}
                onChange={() => setTypedIntoPasteBox(true)}
                onPaste={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  setTypedIntoPasteBox(false);
                  void handleTextSource(e.clipboardData.getData("text/plain"));
                }}
              />
              {typedIntoPasteBox && (
                <p className="text-muted-foreground -mt-2 text-xs">
                  {t("import_paste_hint")}
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
                  void handleTextSource(e.dataTransfer.getData("text/plain"));
                }}
                className={cn(
                  "flex flex-col items-center justify-center gap-2 rounded-xl p-6 text-center transition-colors",
                  dragOver ? "bg-on" : "bg-card",
                )}
              >
                {parsing ? (
                  <>
                    <LoaderIcon className="text-primary h-5 w-5 animate-spin" />
                    <p className="text-muted-foreground text-xs">
                      {t("import_reading")}
                    </p>
                  </>
                ) : (
                  <>
                    <UploadCloudIcon className="text-muted-foreground h-6 w-6" />
                    <p className="text-sm font-medium">
                      {t("import_drop_here")}
                    </p>
                    <Button
                      variant="outline"
                      size="sm"
                      className="mt-1"
                      onClick={() => fileInputRef.current?.click()}
                    >
                      {t("import_browse")}
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
              {/* Absent with key discovery off: a disabled control
                  invites turning it on. */}
              {keyDiscoveryEnabled && (
                <div className="space-y-1">
                  <label
                    htmlFor="key-lookup"
                    className="text-muted-foreground block text-xs"
                  >
                    {t("import_lookup_label")}
                  </label>
                  <div className="flex gap-2">
                    <Input
                      id="key-lookup"
                      ref={lookupInputRef}
                      type="text"
                      spellCheck={false}
                      autoComplete="off"
                      autoCapitalize="off"
                      placeholder={t("import_lookup_placeholder")}
                      value={lookupInput}
                      disabled={parsing}
                      onChange={(e) => setLookupInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key !== "Enter") return;
                        e.preventDefault();
                        void runLookup();
                      }}
                    />
                    <Button
                      variant="outline"
                      onClick={() => void runLookup()}
                      disabled={parsing || !lookupInput.trim()}
                    >
                      {t("import_lookup_button")}
                    </Button>
                  </div>
                  {notice && (
                    <div
                      role="status"
                      className="text-warn mt-2 flex items-start gap-2 rounded-lg bg-[#252012] px-3 py-2.5 text-xs"
                    >
                      <InfoIcon className="mt-px h-3.5 w-3.5 shrink-0" />
                      <span>{notice}</span>
                    </div>
                  )}
                </div>
              )}
              <p className="text-muted-foreground text-xs">
                {t("import_source_help")}
              </p>
              {error && (
                <p className="text-destructive text-xs" role="alert">
                  {error}
                </p>
              )}
            </div>
          </div>
        )}

        {step.kind === "review" && (
          <ImportReview
            keys={step.keys}
            busy={importing}
            error={error}
            allowImportAll={step.keys.length > 1}
            onImport={(decisions) => {
              // Never saved as a contact.
              const secret = step.keys.find((k) => isSecretKind(k.kind));
              if (secret) {
                if (
                  (decisions.get(secret.keyId) ?? defaultDecision(secret)) !==
                  "skip"
                ) {
                  setStep({
                    kind: "protect",
                    incoming: secret,
                    secretEncrypted: step.secretEncrypted,
                  });
                }
                return;
              }
              void importPublicKeys(step.keys, decisions);
            }}
          />
        )}

        {step.kind === "preview" && (
          <ImportPreview
            incoming={step.incoming}
            onConfirm={handleConfirm}
            onDone={resetAndClose}
            onReveal={() => finish([step.incoming.keyId], { reveal: true })}
            busy={importing}
            error={error}
            grouping={
              step.grouping
                ? {
                    name: step.grouping.name,
                    onNameChange: (name) =>
                      setStep((s) =>
                        s.kind === "preview" && s.grouping
                          ? { ...s, grouping: { ...s.grouping, name } }
                          : s,
                      ),
                    separateCount: step.grouping.separates.length,
                  }
                : undefined
            }
          />
        )}

        {step.kind === "protect" && (
          <div className="flex-1 space-y-3 overflow-y-auto p-3">
            {step.incoming.kind === "crx" && (
              <div>
                <label className="text-muted-foreground mb-1 block text-xs">
                  {t("import_label_field")}{" "}
                  <span className="text-muted-foreground/60">
                    {t("import_optional")}
                  </span>
                </label>
                <Input
                  type="text"
                  placeholder={t("import_label_placeholder")}
                  value={label}
                  onChange={(e) => setLabel(e.target.value)}
                />
              </div>
            )}
            {step.secretEncrypted && (
              <div className="space-y-1">
                <label className="text-muted-foreground block text-xs">
                  {t("import_passphrase_label")}
                </label>
                <Input
                  type="password"
                  autoFocus
                  autoComplete="current-password"
                  value={sourcePassphrase}
                  onChange={(e) => setSourcePassphrase(e.target.value)}
                  placeholder={t("import_passphrase_placeholder")}
                />
              </div>
            )}
            <ProtectionMethodPicker
              {...choice.pickerProps}
              error={error}
              onSubmit={handleProtectSubmit}
              onBack={handleBack}
              submitting={importing}
              submitLabel={t("import_submit")}
            />
          </div>
        )}
      </div>
    </SlideOverPanel>
  );
}

/** Lazy import keeps WASM out until a private key shows up. */
async function isSecretProtected(armored: string): Promise<boolean> {
  const { isSecretEncrypted } = await import("../../lib/pgp/wasm");
  return isSecretEncrypted(armored);
}
