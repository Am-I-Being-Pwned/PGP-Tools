import { useCallback, useEffect, useRef, useState } from "react";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { PresentedError } from "../../lib/errors/present";
import type { WorkspaceAction } from "../../lib/messages";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { FileResult } from "../../lib/utils/download";
import type {
  WorkspaceDraft,
  WorkspaceDraftSource,
} from "../../lib/workspace-draft";
import { looksLikePrivateKey } from "../../lib/drop-routing";
import { resolveSelfKey } from "../../lib/encrypt-recipients";
import { getPreferences } from "../../lib/storage/preferences";
import { zipHasManifest } from "../../lib/utils/zip";
import { decryptWorkspaceDraft } from "../../lib/workspace-draft";

type Mode = WorkspaceAction;

/** A drop routed to the workspace from the global dropzone. `nonce`
 *  changes on every drop so the same files/text re-trigger intake. */
export interface WorkspaceIntake {
  files: File[];
  text: string;
  nonce: number;
}

/** What the double-Escape / "Clear text" undo affordances restore. */
interface ClearUndoSnapshot {
  input: string;
  files: File[];
}

export interface WorkspaceState {
  mode: Mode;
  setMode: (m: Mode) => void;
  /** The message textarea's DOM node. It is UNCONTROLLED — the composed
   *  plaintext lives in a ref and in the DOM, never in render state (see
   *  `getInput`). `WorkspaceInput` attaches this via a callback ref that
   *  also re-seeds the node from the ref on every (re)mount. */
  inputElRef: React.MutableRefObject<HTMLTextAreaElement | null>;
  /** Read the composed message. Always call this at the point of use;
   *  never hoist the result into state or into a long-lived closure. */
  getInput: () => string;
  /** Replace the message programmatically (ref + DOM node + derived flags). */
  setInput: (s: string) => void;
  /** Derived, non-sensitive: the box has at least one character. */
  hasInput: boolean;
  /** Derived, non-sensitive: the box has at least one non-whitespace char. */
  hasTrimmedInput: boolean;
  /** Bumped on every input change. Use as an effect dependency for work
   *  that must react to the content without capturing it. */
  inputVersion: number;
  /** Drop every plaintext copy this hook owns: the input ref, the
   *  textarea's DOM value, and the clear-undo buffer. Called by the App
   *  at master lock, after the draft has been encrypted. */
  wipeInput: () => void;
  /** Capture input+files so the next clear is undoable. */
  stashClearUndo: () => void;
  /** Put back what `stashClearUndo` captured (single-shot). */
  restoreClearUndo: () => void;
  /** Whether a stashed clear is still undoable. */
  clearUndoAvailable: boolean;
  output: string;
  setOutput: (s: string) => void;
  operationDone: boolean;
  setOperationDone: (b: boolean) => void;
  statusText: string | null;
  setStatusText: (s: string | null) => void;
  verifiedSigner: PublicContactKey | ProtectedKeyBlob | null;
  setVerifiedSigner: (s: PublicContactKey | ProtectedKeyBlob | null) => void;
  signatureTone: "success" | "warning";
  setSignatureTone: (t: "success" | "warning") => void;
  binaryOutput: Uint8Array | undefined;
  setBinaryOutput: (b: Uint8Array | undefined) => void;
  fileResults: FileResult[];
  setFileResults: (r: FileResult[]) => void;
  /** Recipient key ids for encrypt mode, in selection (chip) order. */
  selectedRecipientIds: string[];
  setSelectedRecipientIds: (ids: string[]) => void;
  /** Recently used recipient fingerprints, most recent first
   *  (preference-backed; updated after each successful encrypt). */
  recentRecipients: string[];
  setRecentRecipients: (ids: string[]) => void;
  selectedKeyId: string | null;
  setSelectedKeyId: (s: string | null) => void;
  selectedCrxKeyId: string | null;
  setSelectedCrxKeyId: (s: string | null) => void;
  pendingCrxSign: boolean;
  setPendingCrxSign: (b: boolean) => void;
  /** True when the input is a single .zip containing a manifest.json. */
  isExtensionZip: boolean;
  /** Which signature the sign flow produces: an OpenPGP signature or a
   *  signed CRX package. Defaults to `crx` when an extension zip is the
   *  input (and CRX signing is available), `pgp` otherwise. */
  signKind: "pgp" | "crx";
  setSignKind: (k: "pgp" | "crx") => void;
  crxKeys: CrxSigningKeyBlob[];
  crxSigningEnabled: boolean;
  error: PresentedError | null;
  setError: (e: PresentedError | null) => void;
  loading: boolean;
  setLoading: (b: boolean) => void;
  files: File[];
  setFiles: (f: File[]) => void;
  alsoSign: boolean;
  setAlsoSign: (b: boolean) => void;
  /** Also encrypt to one of the user's own keys (preference-backed). */
  encryptToSelf: boolean;
  setEncryptToSelf: (b: boolean) => void;
  saveToHistory: boolean;
  setSaveToHistory: (b: boolean) => void;
  zipFiles: boolean;
  setZipFiles: (b: boolean) => void;
  needsPassword: boolean;
  setNeedsPassword: (b: boolean) => void;
  passwordInput: string;
  setPasswordInput: (s: string) => void;
  passwordError: string | null;
  setPasswordError: (s: string | null) => void;
  publicKeyDetected: boolean;
  setPublicKeyDetected: (b: boolean) => void;
  privateKeyDetected: boolean;
  setPrivateKeyDetected: (b: boolean) => void;
  handleInputChange: (text: string) => void;
  handleFileDrop: (newFiles: File[]) => void;
  removeFile: (index: number) => void;
  clearFiles: () => void;
  resetOutput: () => void;
  resetAll: () => void;
}

export function useWorkspaceState(opts: {
  myKeys: ProtectedKeyBlob[];
  crxKeys?: CrxSigningKeyBlob[];
  crxSigningEnabled?: boolean;
  pendingAction?: { action: WorkspaceAction; text: string } | null;
  onClearPending?: () => void;
  allPublicKeys?: { keyId: string }[];
  encryptToKeyId?: string | null;
  onClearEncryptTo?: () => void;
  /** Encrypted draft to restore on mount (from a prior auto-lock).
   *  Once consumed, `onDraftRestored` fires so the parent can clear it. */
  restoreDraft?: Uint8Array | null;
  onDraftRestored?: () => void;
  /** Hands the parent a pull-model draft source (see `WorkspaceDraftSource`).
   *  The parent calls `getDraft()` once, at lock time, then `wipe()`. */
  onRegisterDraftSource?: (src: WorkspaceDraftSource | null) => void;
  /** A drop routed here by the global dropzone. Applied once per nonce. */
  intake?: WorkspaceIntake | null;
  onIntakeConsumed?: () => void;
  /** The user's configured default key: preferred over the first key
   *  when auto-selecting a private key for sign/decrypt. */
  defaultKeyId?: string | null;
  /** Bumped when preference-backed fields (signWhenEncrypting,
   *  encryptToSelf, historyEnabled) change outside this view -- e.g. a
   *  security preset applied in Settings while the workspace stays
   *  mounted. Triggers a re-read so toggles never go stale. */
  prefsVersion?: number;
}): WorkspaceState {
  const [mode, setMode] = useState<Mode>("encrypt");

  // ---------------------------------------------------------------------
  // The composed message.
  //
  // It lives in a ref + the uncontrolled textarea's DOM node, NOT in
  // useState. A controlled `value={input}` puts the user's plaintext into
  // render state, and React snapshots hook state onto `fiber.alternate`
  // (its double buffer) and keeps effect closures hanging off it alive
  // well past unmount — so an in-app master lock that unmounts the
  // workspace still left the whole plaintext reachable from a GC root via
  // `alternate -> updateQueue.lastEffect.create -> context`. A ref is one
  // mutable slot shared by both fiber copies, so clearing it in
  // `wipeInput` really does drop the last reference. Same reasoning, and
  // the same shape, as the paste box in `ImportKeyPage`.
  //
  // Only non-sensitive *derived* facts are allowed into state: how long
  // the text is, and a version counter for effects that must react to it.
  const inputRef = useRef("");
  const inputElRef = useRef<HTMLTextAreaElement | null>(null);
  const [inputInfo, setInputInfo] = useState({
    len: 0,
    nonBlank: false,
    version: 0,
  });
  const getInput = useCallback(() => inputRef.current, []);

  // Record a new value in the ref and refresh the derived state. `\S`
  // rather than `.trim()` on purpose: trim() would materialise a second
  // copy of the plaintext just to ask a yes/no question.
  const syncInput = useCallback((text: string) => {
    inputRef.current = text;
    setInputInfo((prev) => ({
      len: text.length,
      nonBlank: /\S/.test(text),
      version: prev.version + 1,
    }));
  }, []);

  // Programmatic writes (draft restore, drops, clears, undo) must also
  // push into the uncontrolled DOM node. When the textarea isn't mounted
  // (files staged, or the full-output view is up) the callback ref
  // re-seeds it from `inputRef` as soon as it comes back.
  // The `!== text` guard is load-bearing, not an optimisation: this also
  // runs on the textarea's own onChange, and assigning to `.value` moves
  // the caret to the end of the box. Skipping the write when the node
  // already agrees keeps typing in the middle of a message working.
  const setInput = useCallback(
    (text: string) => {
      const el = inputElRef.current;
      if (el && el.value !== text) el.value = text;
      syncInput(text);
    },
    [syncInput],
  );

  const clearUndoRef = useRef<ClearUndoSnapshot | null>(null);
  const [clearUndoAvailable, setClearUndoAvailable] = useState(false);

  // Deliberately does NOT setState: it runs inside `doMasterLock`, one
  // statement before the unmount, and a re-render here would only build
  // a fresh set of closures for React to retain. Dropping the references
  // is the whole job.
  const wipeInput = useCallback(() => {
    inputRef.current = "";
    if (inputElRef.current) inputElRef.current.value = "";
    clearUndoRef.current = null;
  }, []);

  const [output, setOutput] = useState("");
  const [operationDone, setOperationDone] = useState(false);
  const [statusText, setStatusText] = useState<string | null>(null);
  const [verifiedSigner, setVerifiedSigner] = useState<
    PublicContactKey | ProtectedKeyBlob | null
  >(null);
  const [signatureTone, setSignatureTone] = useState<"success" | "warning">(
    "success",
  );
  const [binaryOutput, setBinaryOutput] = useState<Uint8Array | undefined>();
  const [fileResults, setFileResults] = useState<FileResult[]>([]);
  const [selectedRecipientIds, setSelectedRecipientIds] = useState<string[]>(
    [],
  );
  const [recentRecipients, setRecentRecipients] = useState<string[]>([]);
  const [selectedKeyId, setSelectedKeyId] = useState<string | null>(null);
  const [selectedCrxKeyId, setSelectedCrxKeyId] = useState<string | null>(null);
  const [pendingCrxSign, setPendingCrxSign] = useState(false);
  const [isExtensionZip, setIsExtensionZip] = useState(false);
  const [signKind, setSignKind] = useState<"pgp" | "crx">("pgp");
  const [error, setError] = useState<PresentedError | null>(null);
  const [loading, setLoading] = useState(false);
  const [files, setFiles] = useState<File[]>([]);
  const [alsoSign, setAlsoSign] = useState(false);
  const [encryptToSelf, setEncryptToSelf] = useState(true);
  const [saveToHistory, setSaveToHistory] = useState(false);
  const [zipFiles, setZipFiles] = useState(true);
  const [needsPassword, setNeedsPassword] = useState(false);
  const [passwordInput, setPasswordInput] = useState("");
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [publicKeyDetected, setPublicKeyDetected] = useState(false);
  const [privateKeyDetected, setPrivateKeyDetected] = useState(false);
  const resetOutput = useCallback(() => {
    setOutput("");
    setBinaryOutput(undefined);
    setFileResults([]);
    setError(null);
    setOperationDone(false);
    setStatusText(null);
    setVerifiedSigner(null);
    setSignatureTone("success");
    setNeedsPassword(false);
    setPendingCrxSign(false);
  }, []);

  const resetAll = useCallback(() => {
    setInput("");
    setFiles([]);
    setPublicKeyDetected(false);
    setPrivateKeyDetected(false);
    resetOutput();
  }, [resetOutput, setInput]);

  // Public/private-key detection (and the armor-driven mode nudge) for a
  // new box value. Split out of `handleInputChange` so the clear-undo path
  // can re-arm the private-key warning + mask: undoing a clear must not
  // silently drop the "don't paste private keys here" banner.
  const applyDetection = useCallback((text: string) => {
    setPublicKeyDetected(false);
    setPrivateKeyDetected(false);
    if (looksLikePrivateKey(text)) {
      // Flag first; the draft snapshot is refused while this is true so the
      // armor never reaches the encrypted draft blob. Covers every armored
      // private-key flavour (PGP + any raw PEM), not just PGP, so a pasted
      // OpenSSH/EC/etc. key can't leak into the draft either.
      setPrivateKeyDetected(true);
    } else if (text.includes("-----BEGIN PGP MESSAGE-----")) {
      setMode("decrypt");
    } else if (text.includes("-----BEGIN PGP SIGNED MESSAGE-----")) {
      setMode("verify");
    } else if (text.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
      setPublicKeyDetected(true);
    }
  }, []);

  const stashClearUndo = useCallback(() => {
    clearUndoRef.current = { input: inputRef.current, files };
    setClearUndoAvailable(true);
  }, [files]);

  const restoreClearUndo = useCallback(() => {
    const snap = clearUndoRef.current;
    clearUndoRef.current = null;
    setClearUndoAvailable(false);
    if (!snap) return;
    setInput(snap.input);
    setFiles(snap.files);
    applyDetection(snap.input);
  }, [setInput, applyDetection]);

  useEffect(() => {
    void getPreferences().then((p) => {
      setAlsoSign(p.signWhenEncrypting);
      setEncryptToSelf(p.encryptToSelf);
      setSaveToHistory(p.historyEnabled);
      setRecentRecipients(p.recentRecipients);
    });
    // Re-read on mount and whenever the parent signals an external
    // preference change (e.g. a preset applied in Settings).
  }, [opts.prefsVersion]);

  // Restore an encrypted draft (if any) on mount. Single-shot: the
  // parent clears the ciphertext via `onDraftRestored` so re-renders
  // don't keep re-applying it and clobbering subsequent edits.
  const restoreCt = opts.restoreDraft;
  const onRestored = opts.onDraftRestored;
  const restoredRef = useRef(false);
  useEffect(() => {
    if (restoredRef.current || !restoreCt) return;
    restoredRef.current = true;
    void (async () => {
      const draft = await decryptWorkspaceDraft(restoreCt);
      if (draft) {
        setMode(draft.mode);
        // Writes the ref + the (already mounted) textarea's DOM value.
        setInput(draft.input);
        setOutput(draft.output);
        setSelectedRecipientIds(draft.selectedRecipientIds);
        setSelectedKeyId(draft.selectedKeyId);
      }
      onRestored?.();
    })();
  }, [restoreCt, onRestored, setInput]);

  // Expose the draft to the parent as a PULL, not a push. The old push
  // contract fired an effect on every keystroke whose closure captured the
  // plaintext, and React retains such closures on the previous fiber
  // (`alternate`) after unmount -- which is precisely how the composed
  // message survived a master lock. A stable getter reads `inputRef` at
  // call time instead, so nothing durable ever closes over the string.
  const draftFieldsRef = useRef({
    mode,
    output,
    selectedRecipientIds,
    selectedKeyId,
    privateKeyDetected,
  });
  useEffect(() => {
    draftFieldsRef.current = {
      mode,
      output,
      selectedRecipientIds,
      selectedKeyId,
      privateKeyDetected,
    };
  });

  const getDraft = useCallback((): WorkspaceDraft | null => {
    const f = draftFieldsRef.current;
    // Refuse to snapshot armored private-key material into the draft.
    // The draft is encrypted at rest, but the plaintext armor still
    // exists in JS heap while the draft serializer runs and during
    // any future restore. Pasting a private key here is almost always
    // a user error (they meant to use the Import flow), so dropping
    // the snapshot is safer than persisting it.
    if (f.privateKeyDetected) return null;
    return {
      mode: f.mode,
      input: inputRef.current,
      output: f.output,
      selectedRecipientIds: f.selectedRecipientIds,
      selectedKeyId: f.selectedKeyId,
    };
  }, []);

  const onRegisterDraftSource = opts.onRegisterDraftSource;
  useEffect(() => {
    if (!onRegisterDraftSource) return;
    onRegisterDraftSource({ getDraft, wipe: wipeInput });
    return () => onRegisterDraftSource(null);
  }, [onRegisterDraftSource, getDraft, wipeInput]);

  // Default-select a private key for sign/decrypt when the user hasn't
  // picked one: the configured default key, else the first key.
  // `autoPickedRef` remembers that the current selection came from THIS
  // effect, so a default key arriving after the keys load (prefs decrypt
  // asynchronously) can still upgrade the auto-pick -- while an explicit
  // user pick, a restored draft, or the decrypt auto-selection (which all
  // set a different key id) is never overridden.
  const autoPickedRef = useRef<string | null>(null);
  useEffect(() => {
    if (opts.myKeys.length === 0) return;
    if (selectedKeyId !== null && selectedKeyId !== autoPickedRef.current) {
      return;
    }
    const resolved = resolveSelfKey(opts.myKeys, opts.defaultKeyId ?? null);
    if (resolved && resolved.keyId !== selectedKeyId) {
      autoPickedRef.current = resolved.keyId;
      setSelectedKeyId(resolved.keyId);
    }
  }, [opts.myKeys, opts.defaultKeyId, selectedKeyId]);

  // Keep the CRX key selection pointing at a key that actually exists —
  // when the selected key is deleted, fall to the first remaining one
  // HERE (visibly, the Select updates) rather than silently at sign time.
  const crxKeys = opts.crxKeys;
  useEffect(() => {
    if (!crxKeys || crxKeys.length === 0) {
      if (selectedCrxKeyId) setSelectedCrxKeyId(null);
      return;
    }
    if (!crxKeys.some((k) => k.extensionId === selectedCrxKeyId)) {
      setSelectedCrxKeyId(crxKeys[0].extensionId);
    }
  }, [crxKeys, selectedCrxKeyId]);

  // Detect whether the input is a single .zip that looks like a packed
  // Chrome extension (has a manifest.json), and when it is, nudge the mode
  // to sign so the "Sign for Web Store" action is right there.
  //
  // The nudge only fires from encrypt/decrypt — the same guard the .gpg/.asc
  // auto-switch-to-decrypt uses in handleFileDrop — so it never clobbers an
  // explicit sign/verify choice. The `cancelled` flag + functional setMode
  // mean a stale detection (file already replaced) can't flip the mode late.
  const crxSigningEnabled = opts.crxSigningEnabled;
  const haveCrxKey = (crxKeys?.length ?? 0) > 0;
  useEffect(() => {
    if (files.length !== 1 || !/\.zip$/i.test(files[0].name)) {
      setIsExtensionZip(false);
      return;
    }
    const run = { cancelled: false };
    void files[0].arrayBuffer().then((buf) => {
      if (run.cancelled) return;
      const isExtension = zipHasManifest(new Uint8Array(buf));
      setIsExtensionZip(isExtension);
      if (isExtension && crxSigningEnabled && haveCrxKey) {
        setMode((current) =>
          current === "encrypt" || current === "decrypt" ? "sign" : current,
        );
      }
    });
    return () => {
      run.cancelled = true;
    };
  }, [files, crxSigningEnabled, haveCrxKey]);

  // An extension zip defaults the sign flow to CRX (that's overwhelmingly
  // the intent); anything else resets to PGP. The user can still flip the
  // "Sign as" toggle in the view — this only sets the starting point.
  useEffect(() => {
    setSignKind(
      isExtensionZip && opts.crxSigningEnabled && (crxKeys?.length ?? 0) > 0
        ? "crx"
        : "pgp",
    );
  }, [isExtensionZip, opts.crxSigningEnabled, crxKeys]);

  // Recipients start EMPTY on purpose: encrypting is addressed to
  // someone, and pre-seeding the user's own key made "encrypted to
  // myself by accident" the default failure mode. (Encrypt-to-self is
  // its own checkbox and adds the self key at encrypt time.)

  const { pendingAction, onClearPending, encryptToKeyId, onClearEncryptTo } =
    opts;

  useEffect(() => {
    if (pendingAction) {
      setMode(pendingAction.action);
      // Keyboard mode commands deliver an empty-text op: switch the
      // mode but leave whatever the user already has in the workspace.
      if (pendingAction.text) {
        setInput(pendingAction.text);
        setFiles([]);
        resetOutput();
      }
      onClearPending?.();
    }
  }, [pendingAction, onClearPending, resetOutput, setInput]);

  useEffect(() => {
    if (!encryptToKeyId) return;
    setMode("encrypt");
    setSelectedRecipientIds([encryptToKeyId]);
    onClearEncryptTo?.();
  }, [encryptToKeyId, onClearEncryptTo]);

  // Serves both the textarea's own onChange and programmatic writes
  // (drops, intake, the clear buttons); `setInput` handles the difference.
  const handleInputChange = useCallback(
    (text: string) => {
      setInput(text);
      setFiles([]);
      resetOutput();
      applyDetection(text);
    },
    [resetOutput, setInput, applyDetection],
  );

  const handleFileDrop = useCallback(
    (newFiles: File[]) => {
      setFiles((prev) => {
        const existing = new Set(prev.map((f) => f.name));
        const deduped = newFiles.filter((f) => !existing.has(f.name));
        return [...prev, ...deduped];
      });
      setInput("");
      setMode((current) => {
        if (current !== "encrypt" && current !== "decrypt") return current;
        if (newFiles.some((f) => /\.(gpg|pgp|asc)$/i.test(f.name))) {
          return "decrypt";
        }
        return current;
      });
      resetOutput();
    },
    [resetOutput, setInput],
  );

  const removeFile = useCallback((index: number) => {
    setFiles((prev) => prev.filter((_, i) => i !== index));
  }, []);

  const clearFiles = useCallback(() => {
    setFiles([]);
    setInput("");
    resetOutput();
  }, [resetOutput, setInput]);

  // Apply a drop routed here by the global dropzone. Reuses the same
  // file/text handlers as an in-panel drop (so mode auto-detection still
  // fires), then clears the intake so it isn't re-applied on re-render.
  const { intake, onIntakeConsumed } = opts;
  useEffect(() => {
    if (!intake) return;
    if (intake.files.length > 0) {
      handleFileDrop(intake.files);
    } else if (intake.text.trim()) {
      handleInputChange(intake.text);
    }
    onIntakeConsumed?.();
  }, [intake, onIntakeConsumed, handleFileDrop, handleInputChange]);

  return {
    mode,
    setMode,
    inputElRef,
    getInput,
    setInput,
    hasInput: inputInfo.len > 0,
    hasTrimmedInput: inputInfo.nonBlank,
    inputVersion: inputInfo.version,
    wipeInput,
    stashClearUndo,
    restoreClearUndo,
    clearUndoAvailable,
    output,
    setOutput,
    operationDone,
    setOperationDone,
    statusText,
    setStatusText,
    verifiedSigner,
    setVerifiedSigner,
    signatureTone,
    setSignatureTone,
    binaryOutput,
    setBinaryOutput,
    fileResults,
    setFileResults,
    selectedRecipientIds,
    setSelectedRecipientIds,
    recentRecipients,
    setRecentRecipients,
    selectedKeyId,
    setSelectedKeyId,
    selectedCrxKeyId,
    setSelectedCrxKeyId,
    pendingCrxSign,
    setPendingCrxSign,
    isExtensionZip,
    signKind,
    setSignKind,
    crxKeys: opts.crxKeys ?? [],
    crxSigningEnabled: opts.crxSigningEnabled ?? false,
    error,
    setError,
    loading,
    setLoading,
    files,
    setFiles,
    alsoSign,
    setAlsoSign,
    encryptToSelf,
    setEncryptToSelf,
    saveToHistory,
    setSaveToHistory,
    zipFiles,
    setZipFiles,
    needsPassword,
    setNeedsPassword,
    passwordInput,
    setPasswordInput,
    passwordError,
    setPasswordError,
    publicKeyDetected,
    setPublicKeyDetected,
    privateKeyDetected,
    setPrivateKeyDetected,
    handleInputChange,
    handleFileDrop,
    removeFile,
    clearFiles,
    resetOutput,
    resetAll,
  };
}
