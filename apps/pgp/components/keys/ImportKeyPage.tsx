import { useEffect, useRef, useState } from "react";
import { InfoIcon, LoaderIcon, UploadCloudIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

import type { CrxProtectionInput } from "../../lib/crx/operations";
import type { CrxSigningKeyBlob } from "../../lib/crx/types";
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
import { parseRecipient } from "../../lib/age/operations";
import {
  groupContact,
  importSshIdentity,
  sshContact,
} from "../../lib/age/protect-flow";
import { readKeyFile } from "../../lib/binary-armor";
import { importCrxKey } from "../../lib/crx/operations";
import { AppError } from "../../lib/errors/app-error";
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
import { importable, prepareImport } from "../../lib/import/prepare";
import { isPublicKind, isSecretKind } from "../../lib/import/types";
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
  /** Master enable for the network lookups on the source step. DEFAULTS
   *  TO TRUE, matching `DEFAULT_PREFERENCES`: an omitted prop must not
   *  silently withdraw the GitHub lookup this panel has always had. */
  keyDiscoveryEnabled?: boolean;
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
  keyDiscoveryEnabled = true,
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
  /** What is typed in the one lookup box. It is ONE box because getting
   *  a key is one question -- `classifyLookup` decides whether the
   *  answer comes from GitHub or from keys.openpgp.org. */
  const [lookupInput, setLookupInput] = useState("");
  /** A failure the user didn't cause and can't fix by retrying -- "this
   *  person has published no SSH keys", or "the keyserver has no key for
   *  that address". Rendered in its own amber callout under the lookup
   *  field, never in the destructive error slot: it is the ANSWER to the
   *  lookup, so it has to be seen, but nothing went wrong. */
  const [notice, setNotice] = useState<string | null>(null);
  // The document-level paste listener below must not swallow a username
  // or address pasted into the lookup field; it identifies it by node.
  const lookupInputRef = useRef<HTMLInputElement>(null);
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
  const [secretEncrypted, setSecretEncrypted] = useState(false);
  /**
   * The pasted SSH keys as SEPARATE contacts, held while the preview
   * offers to file them as one.
   *
   * Both readings of the same paste are on screen at once (see
   * `PreparedImport.groupProposal`): `incoming` is the grouped one, this
   * is what a blank name still produces. Safe for React state -- public
   * halves only, like `incoming` itself.
   */
  const [groupSeparates, setGroupSeparates] = useState<IncomingKey[] | null>(
    null,
  );
  /** The name typed for that group. Blank means "keep them separate". */
  const [groupName, setGroupName] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Secret key material is the crown jewel, so it lives in refs rather than
  // useState. A ref is a single mutable slot shared by both of a fiber's
  // double-buffered copies, so clearing it on close drops the only
  // reference -- whereas a useState value is snapshotted into the previous
  // fiber, which React keeps alive for the whole slide-out animation,
  // leaving the private key lingering in the GC heap (see SECURITY.md's
  // zeroization table).
  //
  // Holds whatever secret half the previewed key carries -- OpenPGP
  // private armor, or a CRX signing key's RSA PEM. One slot, because the
  // panel only ever previews one key at a time, and one slot is one
  // thing to remember to clear.
  const secretArmorRef = useRef<string | null>(null);

  const clearSecrets = () => {
    secretArmorRef.current = null;
    // The credentials typed on the protect step are secrets too, and
    // unlike the armor above they are in `useState` -- they have to be,
    // the inputs are controlled. So they get the treatment §5's first row
    // prescribes for a typed password and `MasterUnlockScreen` applies on
    // every path including failure: `setX("")`, and let V8 reclaim.
    // `sourcePassphrase` in particular is the passphrase on the user's
    // real OpenSSH key file, not one this app minted.
    //
    // This is weaker than what the ref above gets, and deliberately not
    // described as equivalent: a JS string cannot be zeroized, so the
    // old value survives until GC and the previous fiber's snapshot of
    // it survives the slide-out animation. It bounds the lifetime rather
    // than ending it -- which is the whole reason key material is in a
    // ref and these are the exception.
    setPassword("");
    setConfirmPassword("");
    setSourcePassphrase("");
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
        if (key.group) {
          // A person with several keys is ONE contact holding all of
          // them (see storage/contacts). Built by the age engine's own
          // constructor for the same reason the single-key branch below
          // is -- and `recipientsField` inside it means a user with
          // exactly one key produces the very same record that branch
          // would have written.
          await onImportPublic(groupContact(key.group));
          continue;
        }
        if (key.kind === "ssh-public") {
          // Built by the age engine's own constructor rather than
          // assembled here: `sshContact` is what decides an SSH contact's
          // shape (kind marker, comment-as-userIds, canonical recipient
          // line), and a second hand-rolled copy of that shape would be
          // free to drift from the one `importSshIdentity` writes.
          // `expiresAt: null` is added because SSH keys have no expiry
          // and `undefined` would mean "not computed yet" -- which sends
          // the contacts backfill off to parse a recipient line as PGP
          // armor on every refresh (see useContacts).
          const info = await parseRecipient(key.publicArmored);
          await onImportPublic({ ...sshContact(info), expiresAt: null });
          continue;
        }
        await onImportPublic({
          keyId: key.keyId,
          userIds: key.userIds,
          algorithm: key.info?.algorithm ?? "",
          armoredPublicKey: key.publicArmored,
          addedAt: Date.now(),
          lastUsedAt: Date.now(),
          expiresAt: key.info?.expiresAt ?? null,
          // Spread, not `source: key.source`: an absent source must stay
          // ABSENT on the stored record (it is what `sameSource` reads to
          // mean "hand-supplied"), and writing `undefined` would change
          // the bytes every pasted contact has always serialised to.
          ...(key.source ? { source: key.source } : {}),
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
   * Classify pasted/dropped/browsed text and route it: a bundle of
   * several importable public keys imports in one go (no point previewing
   * five certs one at a time), and anything else gets the preview.
   *
   * `prepareImport` recognises every engine, so there is nothing to route
   * around it -- which is what keeps the CRX path from drifting away from
   * the OpenPGP one.
   */
  /** Stored keys in the shape every `prepare*` entry point takes. Built
   *  once here so the paste path and both lookups classify against the
   *  same list. */
  const storedForImport = () => ({
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

  const handleSource = async (text: string) => {
    setError(null);
    setNotice(null);
    if (!text.trim() || parsingRef.current) return;

    setParsing(true);
    parsingRef.current = true;
    try {
      const prepared = await prepareImport(
        text,
        storedForImport(),
        // SSH is always on: unlike CRX signing it is not a setting, it
        // is simply another kind of key the app reads. Off, an `.pub`
        // line would come back `unparseable` -- which is what the panel
        // did before the engine existed (see ImportEngines).
        { crx: crxEnabled, ssh: true },
      );

      if (prepared.unparseable || prepared.keys.length === 0) {
        setError(
          "That doesn't look like a key we can read. Paste an armored PGP key block or an SSH public key line, or browse for a key file.",
        );
        return;
      }

      const worthImporting = importable(prepared.keys);

      // Several SSH public keys that do not agree on a name. They may be
      // one person's three machines or three different people, and
      // nothing in the text says which -- so the preview asks, instead
      // of the bulk import below quietly filing three contacts the user
      // then cannot label or merge.
      if (prepared.groupProposal) {
        setGroupSeparates(worthImporting);
        setGroupName("");
        setIncoming(prepared.groupProposal);
        setStep("preview");
        return;
      }

      // A bundle of public keys: import the lot. Previewing five certs
      // one at a time would be worse than the summary toast.
      if (
        worthImporting.length > 1 &&
        worthImporting.every((k) => isPublicKind(k.kind))
      ) {
        await importPublicKeys(worthImporting);
        return;
      }

      const key = worthImporting[0] ?? prepared.keys[0];
      if (isSecretKind(key.kind)) {
        const secret = prepared.secrets.get(key.keyId);
        if (!secret) {
          setError("Could not read that private key.");
          return;
        }
        secretArmorRef.current = secret;
        // Only OpenPGP secrets are probed. A CRX PEM the user can hand
        // us is one we can already read, and an OpenSSH container is
        // deliberately NOT probed: the engine already answers "is this
        // passphrase-protected" as part of importing it, so probing here
        // would mean parsing the key twice to ask the same question --
        // and would show a passphrase field to the majority of users
        // whose key has none. The import is attempted optimistically and
        // the field appears only if the engine asks for it (see
        // handleImportSsh).
        setSecretEncrypted(
          key.kind === "pgp-private" ? await isSecretProtected(secret) : false,
        );
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

  /**
   * Look up a GitHub user's published SSH keys and preview them.
   *
   * Lands in the SAME preview as every other kind: the fetch produces one
   * IncomingKey (a group -- see ContactGroup), so there is no second
   * import flow to keep in step with this one, and no new tab.
   *
   * The fetch itself happens in the background worker, which owns the
   * only `fetch` and the only api.github.com literal in the app; what
   * comes back is a tagged code or a list of unvalidated strings, and
   * `prepareGithubImport` is what decides any of them is a key.
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
      // The worker died or no listener answered: nothing came back at
      // all, which is not one of the tagged codes.
      setError("Couldn't reach the extension's background worker.");
      return;
    }
    if (!response.ok) {
      // Inline copy in the slot that is already there, never a toast:
      // every one of these tells the user something to do next, and a
      // toast takes that away after four seconds.
      const copy = githubFailureCopy(
        response.error,
        username,
        response.resetAt,
      );
      if (copy.tone === "notice") setNotice(copy.message);
      else setError(copy.message);
      return;
    }

    const prepared = await prepareGithubImport(
      // The worker's echoed username, not the typed one: it is the
      // name the request was actually made for.
      response.username,
      response.lines,
      { contacts: existingContacts },
      // Keys the worker's caps held back. Passed through so the
      // preview can say the list is partial instead of asserting
      // "every key listed above" over a truncated one.
      { omitted: response.omitted },
    );
    setIncoming(prepared.keys[0]);
    setStep("preview");
  };

  /**
   * Look up a certificate on keys.openpgp.org and preview it.
   *
   * Thinner than the GitHub path on purpose: what comes back is armor,
   * which is what this panel already knows how to classify, so
   * `prepareKeyserverImport` hands it to the very same `prepareImport`
   * a paste goes through and only stamps the provenance on the result.
   * The worker owns the only `fetch` and the only keys.openpgp.org
   * literal; the armor it forwards is untrusted text until the engine
   * behind that call says otherwise.
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
      setError("Couldn't reach the extension's background worker.");
      return;
    }
    if (!response.ok) {
      const copy = keyserverFailureCopy(
        response.error,
        query,
        response.retryAt,
      );
      if (copy.tone === "notice") setNotice(copy.message);
      else setError(copy.message);
      return;
    }

    const prepared = await prepareKeyserverImport(
      // The worker's echoed query, not the typed one: it is what the
      // request was actually made for, and what the contact's source
      // will record.
      response.query,
      response.armored,
      storedForImport(),
    );

    if (prepared.unparseable || prepared.keys.length === 0) {
      // The worker checked the content type and the armor markers; it
      // deliberately did not check that the bytes between them are a
      // certificate, because that is the engine's call and this is
      // where the engine gets made. So this branch is reachable.
      setError(
        `${KEYSERVER_HOST} answered, but what it sent isn't a key we can read.`,
      );
      return;
    }
    if ((response.omitted ?? 0) > 0) {
      // The endpoint returns exactly one key by construction, so this
      // says the response was not the one we asked for. Shown rather
      // than swallowed: importing the first of several blocks silently
      // is how you end up encrypting to a key nobody chose.
      //
      // A TOAST, not the `notice` callout: this call ends on the preview
      // step, and the callout lives on the source step -- setting it here
      // would put the warning on a screen the user has just left. Same
      // stable-id discipline as the security warning below.
      toast.warning(
        `${KEYSERVER_HOST} returned more than one key for this lookup. Only the first is shown - check the fingerprint before importing it.`,
        { id: "keyserver-multiple-keys" },
      );
    }

    const key = prepared.keys[0];
    if (key.securityWarning) {
      // Stable id: re-running the same lookup must not stack duplicates.
      toast.warning(key.securityWarning, { id: "import-key-warning" });
    }
    setIncoming(key);
    setStep("preview");
  };

  /**
   * Run whichever lookup the typed text names.
   *
   * The routing rule lives in `classifyLookup`, not here: it is the part
   * of this feature a user can be surprised by (a 40-character hex
   * string is a valid GitHub username AND a fingerprint), so it is pure
   * and tested rather than inline in a handler.
   */
  const runLookup = async () => {
    setError(null);
    setNotice(null);
    // Same guard as the paste path, and deliberately the same ref: a
    // double-click on Look up (or Enter racing the click) would otherwise
    // start a second lookup whose response overwrites the first's.
    if (parsingRef.current) return;

    const routed = classifyLookup(lookupInput);
    if (!routed) {
      setError(
        "That isn't a GitHub username, an email address or a key fingerprint. Try “octocat”, “alice@example.com”, or the full 40-character fingerprint.",
      );
      return;
    }

    setParsing(true);
    parsingRef.current = true;
    try {
      if (routed.target === "github") {
        await lookupGithubUser(routed.username);
      } else {
        await lookupKeyserverKey(routed.query);
      }
    } catch (e) {
      setError(errorMessage(e, "Lookup failed"));
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
      // A paste into the lookup field is a USERNAME, an address or a
      // fingerprint, not armor. Without this the document listener
      // claims it, calls preventDefault, and hands "octocat" to the key
      // parser -- which reports that it doesn't look like a key, while
      // the field the user pasted into stays empty. The step's "paste
      // anywhere" rule holds for everywhere else on it.
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
  }, [step]);

  const handleConfirm = () => {
    if (!incoming) return;
    // The grouping offer. A blank name is a real answer, not a skipped
    // step: it means today's behaviour, one contact per key.
    if (groupSeparates) {
      const name = groupName.trim();
      if (!name || !incoming.group) {
        void importPublicKeys(groupSeparates);
        return;
      }
      // The user's name replaces the preview's placeholder on the way to
      // the ONE constructor every multi-key contact goes through
      // (`groupContact`), so a hand-grouped contact and a fetched one are
      // the same record.
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
    setStep("protect");
  };

  const handleBack = () => {
    if (importing || parsing) return;
    setError(null);
    setNotice(null);
    if (step === "protect") {
      setStep("preview");
    } else if (step === "preview") {
      // Opened with a key already in hand (a drop, or the workspace
      // banner): there is no source step behind this one, so Back means
      // "leave" -- not "here's an empty drop zone you never used".
      if (openedWithKey.current) {
        resetAndClose();
        return;
      }
      secretArmorRef.current = null;
      // Back to the source step drops the key, so the passphrase that
      // was for THAT key file goes with it -- leaving it would also
      // pre-fill it against whatever key is picked next.
      setSourcePassphrase("");
      setIncoming(null);
      setGroupSeparates(null);
      setGroupName("");
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
    const pem = secretArmorRef.current;
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

  /**
   * Import an OpenSSH private key under the chosen protection.
   *
   * The key file crosses into wasm as BYTES (`importSshIdentity`
   * zeroizes them), so the string is encoded here, at the call site,
   * and a fresh copy is made per attempt -- the previous copy is already
   * wiped by the time we could retry.
   *
   * The source passphrase is never probed for. Most SSH keys have none,
   * so the import is attempted optimistically and the field appears only
   * when the engine says it needs one; the user then retries on this
   * same step rather than being sent back through the preview.
   */
  const handleImportSsh = async () => {
    setError(null);
    if (method === "password") {
      const pwError = validatePassword(password, confirmPassword);
      if (pwError) {
        setError(pwError);
        return;
      }
    }
    if (secretEncrypted && !sourcePassphrase) {
      setError("Enter the key's passphrase.");
      return;
    }
    const keyText = secretArmorRef.current;
    if (!incoming || !keyText) {
      setError("No key to import.");
      return;
    }

    setImporting(true);
    try {
      const { blob } = await importSshIdentity(
        new TextEncoder().encode(keyText),
        sourcePassphrase || null,
        method === "password"
          ? { method: "password", password }
          : {
              method: "passkey",
              reusePasskeyCredentialId: reusePasskey
                ? reusePasskeyCredentialId
                : undefined,
            },
        { userIdHint: incoming.userIds[0] ?? "Imported SSH key" },
      );
      await onImportPrivate(blob);
      // Success: drop the key text now rather than waiting for the
      // panel's close, so it isn't held across the slide-out.
      secretArmorRef.current = null;
      finish([blob.keyId]);
    } catch (e) {
      const message = errorMessage(e, "Import failed");
      // Revealing the field IS the retry affordance -- the key text is
      // still in the ref, so the next attempt runs from this same step.
      // Keyed on the tagged code, never on the engine's wording: a prose
      // match here fails silently when the message is reworded, and the
      // symptom is that passphrase-protected keys stop being importable
      // at all. `lib/age/protect-flow` does the translation once.
      if (e instanceof AppError && e.code === "ssh-passphrase-required") {
        setSecretEncrypted(true);
      }
      setError(message);
    } finally {
      setImporting(false);
    }
  };

  /**
   * The protect step's one submit. Every engine that carries secret
   * material lands here and is routed by kind, so a new engine adds a
   * branch rather than another `isX ? ... : ...` at the call site (which
   * is what the CRX flag had already grown into).
   */
  const handleProtectSubmit = () => {
    switch (incoming?.kind) {
      case "crx":
        void handleImportCrx();
        return;
      case "ssh-private":
        void handleImportSsh();
        return;
      default:
        void handleImportPrivate();
    }
  };

  const isCrx = incoming?.kind === "crx";

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
              {/* A row on the SAME step, not a tab of its own: "get me a
                  key" is one question, and a lookup is just another
                  place a key comes from. It lands in the same preview.
                  ONE field for both services, routed by what is typed
                  (see classifyLookup) -- two labelled boxes would make
                  the user answer a question about our plumbing before
                  they could ask theirs. Absent entirely when key
                  discovery is off: a disabled control that explains
                  itself is still an invitation to turn it on, and the
                  strictest preset means it. */}
              {keyDiscoveryEnabled && (
                <div className="space-y-1">
                  <label
                    htmlFor="key-lookup"
                    className="text-muted-foreground block text-xs"
                  >
                    Or look someone up
                  </label>
                  <div className="flex gap-2">
                    <input
                      id="key-lookup"
                      ref={lookupInputRef}
                      type="text"
                      spellCheck={false}
                      autoComplete="off"
                      autoCapitalize="off"
                      placeholder="GitHub username, email, or fingerprint"
                      value={lookupInput}
                      disabled={parsing}
                      onChange={(e) => setLookupInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key !== "Enter") return;
                        e.preventDefault();
                        void runLookup();
                      }}
                      className={INPUT_CLASS}
                    />
                    <Button
                      variant="outline"
                      onClick={() => void runLookup()}
                      disabled={parsing || !lookupInput.trim()}
                    >
                      Look up
                    </Button>
                  </div>
                  {notice && (
                    /* A CALLOUT, not another muted line. What reaches
                       here is "this account has no SSH keys" or "the
                       keyserver has no key for that address" -- a real
                       answer to the lookup the user just ran, and set in
                       the same muted style as the standing help text
                       below it read as more boilerplate and got missed.
                       Amber, bordered and attached to the field it
                       answers, so it is legible as a RESULT;
                       deliberately not `text-destructive`, because
                       nothing failed and nothing needs fixing (see
                       githubFailureCopy / keyserverFailureCopy).
                       `status`, not `alert`: announced without
                       interrupting. */
                    <div
                      role="status"
                      className="mt-2 flex items-start gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-300"
                    >
                      <InfoIcon className="mt-px h-3.5 w-3.5 shrink-0" />
                      <span>{notice}</span>
                    </div>
                  )}
                </div>
              )}
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
            grouping={
              groupSeparates
                ? {
                    name: groupName,
                    onNameChange: setGroupName,
                    separateCount: groupSeparates.length,
                  }
                : undefined
            }
          />
        )}

        {step === "protect" && (
          <div className="flex-1 space-y-3 overflow-y-auto p-3">
            {isCrx && (
              // What the key IS was already said on the preview step; the
              // only thing left to ask is what to call it, since a CRX key
              // has no user ID to name itself with.
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
              onSubmit={handleProtectSubmit}
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
