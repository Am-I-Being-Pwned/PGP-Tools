import { useEffect, useRef, useState } from "react";
import { InfoIcon, LoaderIcon, UploadCloudIcon } from "lucide-react";

import { cn } from "@amibeingpwned/ui";
import { Button } from "@amibeingpwned/ui/button";
import { Input } from "@amibeingpwned/ui/input";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { ReviewDecision, ReviewedContact } from "../../lib/import/review";
import type { IncomingKey } from "../../lib/import/types";
import type { KeyserverQuery } from "../../lib/keyserver/query";
import type {
  GithubKeysRequest,
  GithubKeysResponse,
  KeyserverKeyRequest,
  KeyserverKeyResponse,
} from "../../lib/messages";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { engineMessage, useAsyncAction } from "../../hooks/useAsyncAction";
import { importSshIdentity } from "../../lib/age/protect-flow";
import { recoverArmorIfNeeded } from "../../lib/armor-recovery";
import { readKeyFile } from "../../lib/binary-armor";
import { importCrxKey } from "../../lib/crx/operations";
import { AppError } from "../../lib/errors/app-error";
import { t, tn } from "../../lib/i18n";
import {
  githubFailureCopy,
  prepareGithubImport,
} from "../../lib/import/github";
import {
  KEYSERVER_HOST,
  keyserverFailureCopy,
  prepareKeyserverImport,
} from "../../lib/import/keyserver";
import { classifyLookup } from "../../lib/import/lookup";
import {
  importable,
  prepareImport,
  storedKeysFrom,
} from "../../lib/import/prepare";
import { applyReview, defaultDecision } from "../../lib/import/review";
import { isPublicKind, isSecretKind } from "../../lib/import/types";
import { importAndProtect } from "../../lib/protection/protect-flow";
import { toast } from "../../lib/toast";
import {
  SlideOverHeader,
  SlideOverPanel,
  useSlideOver,
} from "../shared/SlideOver";
import { ImportPreview } from "./ImportPreviewPage";
import { ImportReview } from "./ImportReview";
import { ProtectionMethodPicker } from "./ProtectionMethodPicker";
import { useProtectionChoice } from "./useProtectionChoice";

/** Where the panel is, with exactly the data that step needs. Every key
 *  here is public-only (see IncomingKey); a secret half lives in a ref. */
type Step =
  | { kind: "source" }
  | {
      kind: "preview";
      incoming: IncomingKey;
      secretEncrypted: boolean;
      /** Several pasted SSH keys offered as one contact: `incoming` is the
       *  grouped reading, `separates` what a blank name imports instead. */
      grouping?: { separates: IncomingKey[]; name: string };
    }
  /** Every key found, before anything is saved: a bundle, or a key that
   *  claims an identity someone else holds. */
  | { kind: "review"; keys: IncomingKey[]; secretEncrypted: boolean }
  | { kind: "protect"; incoming: IncomingKey; secretEncrypted: boolean };

type ProtectStep = Extract<Step, { kind: "protect" }>;

/** Several keys, an identity collision, or an update that would leave
 *  only keys the user turned off: the Review, not the single preview. */
function needsReview(keys: IncomingKey[]): boolean {
  return (
    keys.length > 1 ||
    keys.some((k) => k.conflict !== undefined || k.allKeysOff === true)
  );
}

/** "⌘V" on a Mac, "Ctrl+V" everywhere else. */
function modKeyLabel(): string {
  return navigator.platform.includes("Mac") ? "⌘V" : "Ctrl+V";
}

interface ImportKeyPageProps {
  /** Called after the slide-out finishes (cancel or success). */
  onClose: () => void;
  onImportPrivate: (blob: ProtectedKeyBlob) => Promise<void>;
  /** Save a contact the user has reviewed (see `lib/import/review`). */
  onImportPublic: (contact: ReviewedContact) => Promise<void>;
  /** Remove a contact -- the old one, when a key REPLACES it. */
  onRemoveContact: (keyId: string) => Promise<void>;
  /** What an incoming key is compared against: new / update / stored. */
  existingKeys?: ProtectedKeyBlob[];
  existingContacts?: PublicContactKey[];
  /** Pass the primary key's passkey credential ID to allow reuse. */
  reusePasskeyCredentialId?: string;
  /** With reuse, seal under the master's PRF salt so the vault ceremony
   *  opens the key ("unlock keys when the vault unlocks"). */
  masterSealSalt?: ArrayBuffer;
  /** Skip the source step and preview this armored key (a global drop).
   *  Read once at mount. */
  initialArmored?: string | null;
  /** Open with this lookup typed and running (an unknown signer's key
   *  id). Read once at mount; ignored when key discovery is off. */
  initialLookup?: string | null;
  /** When true, also accept a raw RSA private key PEM as a CRX signing key. */
  crxSigningEnabled?: boolean;
  /** Master enable for the network lookups. DEFAULTS TO TRUE, matching
   *  `DEFAULT_PREFERENCES`: an omitted prop must not silently withdraw
   *  the lookup. */
  keyDiscoveryEnabled?: boolean;
  /** Persist an imported CRX signing key. Required for the CRX path. */
  onImportCrx?: (blob: CrxSigningKeyBlob) => Promise<void>;
  /** Fingerprints to highlight once the panel slides away: what was
   *  written, or -- with `reveal` -- a stored key the user asked to see
   *  (so the caller should stay on the list). */
  onImported?: (keyIds: string[], opts?: { reveal?: boolean }) => void;
}

/**
 * Key import: get a key, look at it, import it. The key is parsed and
 * shown (identity, fingerprint, health, new / update / stored) so its
 * armor is never rendered; a private key adds a step choosing how the
 * secret is protected at rest.
 */
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
  // The engine's text is the message here ("Incorrect passphrase", an
  // offline-primary key's explanation): it says what to fix.
  const parser = useAsyncAction(engineMessage(t("import_failed")));
  const importer = useAsyncAction(engineMessage(t("import_failed")));
  const parsing = parser.busy;
  const importing = importer.busy;
  const error = (parser.error ?? importer.error)?.message ?? null;
  const setError = (message: string | null) => {
    parser.reset();
    importer.setError(message);
  };
  /** A CRX key's name: it has no User ID of its own. */
  const [label, setLabel] = useState("");
  /** The passphrase already on the user's key file. */
  const [sourcePassphrase, setSourcePassphrase] = useState("");
  const [dragOver, setDragOver] = useState(false);
  /** One lookup box: `classifyLookup` routes it to GitHub or the
   *  keyserver. */
  const [lookupInput, setLookupInput] = useState(initialLookup ?? "");
  /** The lookup's ANSWER when nothing went wrong ("no SSH keys published"):
   *  an amber callout, never the destructive error slot. */
  const [notice, setNotice] = useState<string | null>(null);
  // The panel-wide paste listener must leave a paste into this alone.
  const lookupInputRef = useRef<HTMLInputElement>(null);
  // The paste box holds nothing; say why when someone types into it.
  const [typedIntoPasteBox, setTypedIntoPasteBox] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // The previewed key's secret half (OpenPGP armor, CRX PEM, OpenSSH
  // key) lives in a ref, not state: a ref is one slot shared by both
  // fiber copies, so clearing it drops the only reference, whereas state
  // is snapshotted into the previous fiber for the whole slide-out
  // (SECURITY.md, zeroization table).
  const secretArmorRef = useRef<string | null>(null);

  const clearSecrets = () => {
    secretArmorRef.current = null;
    // Typed credentials must be state (controlled inputs); a JS string
    // can't be zeroized, so this bounds their lifetime, no more.
    choice.clear();
    setSourcePassphrase("");
  };

  // Drop key material before the slide-out, not after it.
  const resetAndClose = () => {
    clearSecrets();
    close();
  };

  // Set once a write lands: the panel is sliding out, so nothing may
  // start a second write from it.
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
    // The passphrase was for THAT key file; never pre-fill it for the next.
    secretArmorRef.current = null;
    setSourcePassphrase("");
    setStep({ kind: "source" });
  };

  /** Preview one key, or send it to the Review if it needs deciding. */
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
      // SHA-1 warnings only (a lookalike name is said on its own card),
      // and only on keys that were saved.
      const saved = new Set(outcome.keyIds);
      const flagged = keys.filter(
        (k) => saved.has(k.keyId) && k.securityWarning?.includes("SHA-1"),
      ).length;
      if (flagged > 0) {
        toast.warning(tn("import_flagged_toast", flagged), {
          id: "contacts-flagged",
        });
      }
      // A single import is confirmed by its card lighting up; only
      // bundles and replacements toast.
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

  /** Stored keys in the shape every `prepare*` entry point takes. */
  const storedForImport = () => storedKeysFrom(existingKeys, existingContacts);

  /** Classify pasted / dropped / browsed text and route it. */
  const handleSource = async (text: string) => {
    setError(null);
    setNotice(null);
    // One guard for parse and lookup: two handlers can fire for one paste
    // (the box and the panel-wide listener).
    if (!text.trim() || parser.inFlight) return;
    await parser.run(async () => {
      // SSH is not a setting: it is another kind of key the app reads.
      const prepared = await prepareImport(text, storedForImport(), {
        crx: crxEnabled,
        ssh: true,
      });

      if (prepared.unparseable || prepared.keys.length === 0) {
        parser.setError(t("import_unreadable"));
        return;
      }

      const worthImporting = importable(prepared.keys);

      // SSH keys that disagree on a name may be one person's machines or
      // several people: ask, rather than file contacts nobody can merge.
      // Not when one claims an identity -- a blank name would save it
      // without the Review's decision.
      if (prepared.groupProposal && !worthImporting.some((k) => k.conflict)) {
        setStep({
          kind: "preview",
          incoming: prepared.groupProposal,
          secretEncrypted: false,
          grouping: { separates: worthImporting, name: "" },
        });
        return;
      }

      // A bundle of public keys: every key on one Review before saving.
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
        // Only OpenPGP secrets are probed. An OpenSSH key is imported
        // optimistically and the engine asks for a passphrase if it needs
        // one (handleImportSsh); most have none.
        secretEncrypted =
          key.kind === "pgp-private" ? await isSecretProtected(secret) : false;
      }
      if (key.securityWarning) {
        // Stable id: re-pasting the same key must not stack duplicates.
        toast.warning(key.securityWarning, { id: "import-key-warning" });
      }
      show([key], secretEncrypted);
    });
  };

  /**
   * A GitHub user's published SSH keys, into the same preview as every
   * other kind. The worker owns the only fetch and api.github.com
   * literal; `prepareGithubImport` decides whether its strings are keys.
   */
  const lookupGithubUser = async (username: string) => {
    const request: GithubKeysRequest = {
      type: "GITHUB_KEYS_REQUEST",
      username,
    };
    const response = await chrome.runtime.sendMessage<
      GithubKeysRequest,
      GithubKeysResponse | undefined
    >(request);

    if (!response) {
      // The worker died or no listener answered.
      parser.setError(t("import_worker_unreachable"));
      return;
    }
    if (!response.ok) {
      // Inline, never a toast: each says what to do next.
      const copy = githubFailureCopy(
        response.error,
        username,
        response.resetAt,
      );
      if (copy.tone === "notice") setNotice(copy.message);
      else parser.setError(copy.message);
      return;
    }

    const prepared = await prepareGithubImport(
      // The worker's echo: the name the request was actually made for.
      response.username,
      response.lines,
      { contacts: existingContacts, own: existingKeys },
      // So the preview can say the list is partial.
      { omitted: response.omitted },
    );
    show(prepared.keys);
  };

  /**
   * A certificate from keys.openpgp.org: armor, classified by the same
   * `prepareImport` a paste goes through. The worker owns the only fetch;
   * what it forwards is untrusted until the engine says otherwise.
   */
  const lookupKeyserverKey = async (query: KeyserverQuery) => {
    const request: KeyserverKeyRequest = {
      type: "KEYSERVER_KEY_REQUEST",
      query,
    };
    const response = await chrome.runtime.sendMessage<
      KeyserverKeyRequest,
      KeyserverKeyResponse | undefined
    >(request);

    if (!response) {
      parser.setError(t("import_worker_unreachable"));
      return;
    }
    if (!response.ok) {
      const copy = keyserverFailureCopy(
        response.error,
        query,
        response.retryAt,
      );
      if (copy.tone === "notice") setNotice(copy.message);
      else parser.setError(copy.message);
      return;
    }

    const prepared = await prepareKeyserverImport(
      // The worker's echo: what the contact's source will record.
      response.query,
      response.armored,
      storedForImport(),
    );

    if (prepared.unparseable || prepared.keys.length === 0) {
      // The worker checks the armor markers, not that a cert is inside.
      parser.setError(
        t("import_keyserver_not_a_key", { host: KEYSERVER_HOST }),
      );
      return;
    }
    if ((response.omitted ?? 0) > 0) {
      // The endpoint returns one key by construction, so this is not the
      // answer we asked for. A toast: the notice callout is on the step
      // being left.
      toast.warning(
        t("import_keyserver_multiple_keys", { host: KEYSERVER_HOST }),
        { id: "keyserver-multiple-keys" },
      );
    }

    const key = prepared.keys[0];
    if (key.securityWarning) {
      toast.warning(key.securityWarning, { id: "import-key-warning" });
    }
    show([key]);
  };

  /** Run whichever lookup the typed text names (`classifyLookup`, pure
   *  and tested: a 40-hex string is a GitHub name AND a fingerprint). */
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
      () =>
        routed.target === "github"
          ? lookupGithubUser(routed.username)
          : lookupKeyserverKey(routed.query),
      engineMessage(t("import_lookup_failed")),
    );
  };

  /** Text that ARRIVED as text (paste, dropped selection): the only route
   *  that repairs mangled armor -- a file on disk has its newlines. */
  const handleTextSource = (text: string) =>
    handleSource(recoverArmorIfNeeded(text));

  // The latest handlers, for the document listeners and mount prefills.
  const handleSourceRef = useRef(handleTextSource);
  const runLookupRef = useRef(runLookup);
  useEffect(() => {
    handleSourceRef.current = handleTextSource;
    runLookupRef.current = runLookup;
  });

  // A key that arrived with the panel skips the source step; Back from
  // its preview then leaves.
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

  // Paste anywhere on the source step -- there's no textarea to aim at.
  const stepKind = step.kind;
  useEffect(() => {
    if (stepKind !== "source") return;
    const onPaste = (e: ClipboardEvent) => {
      // A paste into the lookup field is a username / address, not armor.
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
    // A blank group name is an answer: one contact per key.
    if (grouping) {
      const name = grouping.name.trim();
      if (!name || !incoming.group) {
        void importPublicKeys(grouping.separates);
        return;
      }
      // Through the one multi-key constructor (`groupContact`), so a
      // hand-grouped contact and a fetched one are the same record.
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
        // Opened with a key in hand: no source step behind this one.
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

  /**
   * An OpenSSH private key. It crosses into wasm as BYTES, wiped there,
   * so each attempt encodes a fresh copy. No passphrase probe: the field
   * appears only when the engine asks, and the retry runs from this step.
   */
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
        // Drop the key text now, not across the slide-out.
        secretArmorRef.current = null;
        finish([blob.keyId]);
      } catch (e) {
        // Revealing the field IS the retry. Keyed on the tagged code,
        // never the engine's wording.
        if (e instanceof AppError && e.code === "ssh-passphrase-required") {
          setStep((s) =>
            s.kind === "protect" ? { ...s, secretEncrypted: true } : s,
          );
        }
        throw e;
      }
    });
  };

  /** The protect step's one submit, routed by kind. */
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
              {/* A target for the paste only: the armor is read off the
                  clipboard event and parsed, so it is never rendered, in
                  state, or in the DOM. Hence the permanently empty value. */}
              <Input
                type="text"
                // The focus trap picks `[autofocus]`, but React consumes
                // autoFocus instead of rendering it: mark the node.
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
                  // Handled here: the panel-wide listener must not fire.
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
              {/* One field for both services, routed by what is typed.
                  Absent with key discovery off: a disabled control is
                  still an invitation to turn it on. */}
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
                    // A result, not a failure: amber and attached to the
                    // field, `status` so it announces without interrupting.
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
              // A private key held for claiming someone's identity goes on
              // to the protect step if chosen -- never saved as a contact.
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
            // Already stored: show it in the list instead of writing.
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
              // The preview said what the key is; a CRX key has no User
              // ID, so all that is left to ask is its name.
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
            {/* Unlocking the source key and choosing its new protection
                are one screen: both are "how is this secret handled". */}
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

/** Whether the secret half carries an S2K passphrase. Imported lazily so
 *  the WASM module isn't pulled in until a private key actually shows up. */
async function isSecretProtected(armored: string): Promise<boolean> {
  const { isSecretEncrypted } = await import("../../lib/pgp/wasm");
  return isSecretEncrypted(armored);
}
