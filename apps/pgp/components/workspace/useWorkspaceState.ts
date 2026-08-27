import { useCallback, useEffect, useRef, useState } from "react";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { PresentedError } from "../../lib/errors/present";
import type { WorkspaceAction } from "../../lib/messages";
import type { MessageEncryption } from "../../lib/pgp/wasm-public";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { FileResult } from "../../lib/utils/download";
import type {
  WorkspaceDraft,
  WorkspaceDraftSource,
} from "../../lib/workspace-draft";
import { looksLikeAgeMessage } from "../../lib/armor-blocks";
import { recoverArmorIfNeeded } from "../../lib/armor-recovery";
import { looksLikePrivateKey } from "../../lib/drop-routing";
import { resolveSelfKey } from "../../lib/encrypt-recipients";
import { isPgpRecord, isSshRecord } from "../../lib/storage/key-kind";
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

/**
 * Overwrite the bytes of a binary result and of every multi-file result
 * with zeroes, in place.
 *
 * Dropping the reference is NOT enough for these two. Unlike the text
 * output (a ref + the display node) they are ordinary React render state,
 * and React double-buffers hook state onto `fiber.alternate`: at master
 * lock the workspace unmounts in the SAME synchronous run, so a
 * `setBinaryOutput(undefined)` scheduled a statement earlier is batched
 * with the unmount and never commits -- the previous fiber's
 * `lastRenderedState` goes on holding the old `Uint8Array`, which is the
 * exact retainer chain T-OUTPUT-HEAP-RESIDUE describes. Zeroing the
 * buffer works regardless of who is still holding it.
 *
 * Detached buffers (transferred to a worker) throw on write; they carry no
 * readable bytes any more, so skipping them is correct rather than lossy.
 */
export function zeroizeResultBytes(
  binary: Uint8Array | undefined,
  results: readonly FileResult[],
): void {
  const wipe = (buf: Uint8Array | undefined) => {
    if (!buf || buf.byteLength === 0) return;
    try {
      buf.fill(0);
    } catch {
      /* detached ArrayBuffer -- nothing readable left to wipe */
    }
  };
  wipe(binary);
  for (const r of results) wipe(r.data);
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
  /** Derived, non-sensitive: the staged input is an age message (armored
   *  or binary), or the dropped files are `.age`. A boolean, derived from
   *  `inputVersion` / `files` -- the text it was derived FROM never
   *  enters state (see the input block below). */
  inputIsAge: boolean;
  /** Drop every plaintext copy this hook owns: the input ref, the
   *  textarea's DOM value, the clear-undo buffer, the output ref and the
   *  output node's text -- and zeroize the decrypted bytes behind
   *  `binaryOutput` / `fileResults`. Called by the App at master lock,
   *  after the draft has been encrypted. */
  wipePlaintext: () => void;
  /** Capture input+files so the next clear is undoable. */
  stashClearUndo: () => void;
  /** Put back what `stashClearUndo` captured (single-shot). */
  restoreClearUndo: () => void;
  /** Whether a stashed clear is still undoable. */
  clearUndoAvailable: boolean;
  /** The `<pre>` that displays a decrypted result. Like the input box it
   *  is UNCONTROLLED — the plaintext is written to the node's
   *  `textContent` imperatively and never appears in render state, so a
   *  master lock can actually release it. `OutputArea` attaches this via
   *  a callback ref that re-seeds the node from the ref on every
   *  (re)mount. */
  outputElRef: React.MutableRefObject<HTMLPreElement | null>;
  /** Read the operation result. Always call this at the point of use
   *  (copy, download, draft); never hoist it into state or into a
   *  long-lived closure. */
  getOutput: () => string;
  /** Replace the result programmatically (ref + DOM node + derived flags). */
  setOutput: (s: string) => void;
  /** Derived, non-sensitive: there is a textual result. */
  hasOutput: boolean;
  /** The result contains an armored public key block -- e.g. a
   *  correspondent sent their key inside a message. */
  outputPublicKeyDetected: boolean;
  /** Bumps on every output change, so a second result re-runs anything
   *  derived from the output text. */
  outputVersion: number;
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
  /** The password prompt is asking for the MESSAGE's password (a
   *  `gpg --symmetric` message), not for a key's. Same row, same field,
   *  different question -- and different code on submit, so the two must
   *  not be confusable by anything downstream. */
  pendingPasswordDecrypt: boolean;
  setPendingPasswordDecrypt: (v: boolean) => void;
  /** What the staged message says about how it can be opened, or null
   *  before the async scan has answered (or for input that is not a
   *  readable message). Purely for the UI -- `executeDecrypt` re-derives
   *  it rather than racing this. */
  messageEncryption: MessageEncryption | null;
  setMessageEncryption: (v: MessageEncryption | null) => void;
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
  /** Text that arrived wholesale (paste / text drop) rather than being
   *  typed. Repairs mangled armor; `handleInputChange` never does. */
  handleTextArrival: (text: string) => void;
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
  // ---------------------------------------------------------------------
  // The operation result (decrypted plaintext, or armored ciphertext).
  //
  // Held exactly like the input, and for the same reason: a decrypted
  // message in `useState` is retained past unmount via `fiber.alternate`,
  // so an in-app master lock left the plaintext reachable from a GC root
  // (T-OUTPUT-HEAP-RESIDUE). It lives in a ref and, when it is on screen,
  // in the display node's text — never in render state.
  //
  // The display node is a `<pre>` written through `textContent` rather
  // than a React child. Rendering `{output}` as JSX would put the string
  // back into the fiber's element tree, which is the very thing being
  // avoided; an imperative write keeps React from ever seeing it while
  // leaving the markup, styling and select-all behaviour untouched.
  const outputRef = useRef("");
  const outputElRef = useRef<HTMLPreElement | null>(null);
  // `publicKey` is the same substring probe `applyDetection` runs on the
  // input, done here because the output never enters render state: a
  // correspondent's key arrives inside a decrypted message far more often
  // than it gets pasted into the box.
  const [outputInfo, setOutputInfo] = useState({
    len: 0,
    publicKey: false,
    version: 0,
  });
  const getOutput = useCallback(() => outputRef.current, []);

  const setOutput = useCallback((text: string) => {
    outputRef.current = text;
    const el = outputElRef.current;
    // The `!== text` guard keeps an unchanged re-render from blowing away
    // the user's selection inside the result box.
    if (el && el.textContent !== text) el.textContent = text;
    setOutputInfo((prev) =>
      prev.len === text.length
        ? prev
        : {
            len: text.length,
            publicKey: text.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----"),
            version: prev.version + 1,
          },
    );
  }, []);

  // The decrypted bytes of a binary or multi-file result. These are the
  // one part of the operation result that CANNOT live in a ref alone: the
  // results card renders a row per file, so the values have to reach
  // render state. The refs below mirror the current state values purely so
  // `wipePlaintext` can reach the buffers at lock time -- see
  // `zeroizeResultBytes` for why clearing the state instead does not
  // release them.
  const binaryOutputRef = useRef<Uint8Array | undefined>(undefined);
  const fileResultsRef = useRef<FileResult[]>([]);

  const wipePlaintext = useCallback(() => {
    inputRef.current = "";
    if (inputElRef.current) inputElRef.current.value = "";
    clearUndoRef.current = null;
    outputRef.current = "";
    if (outputElRef.current) outputElRef.current.textContent = "";
    // Binary / multi-file results hold DECRYPTED MESSAGE BYTES just as
    // `outputRef` holds decrypted text (executeDecrypt's file branches,
    // and executeDecryptAge, both land here). `resetOutput()` clears them
    // the ordinary way, but it is a `setState` pair and so is useless on
    // this path: the caller flips `masterUnlocked` in the same
    // synchronous run and the update is batched away with the unmount.
    // Overwriting the buffers is what actually removes the plaintext.
    zeroizeResultBytes(binaryOutputRef.current, fileResultsRef.current);
    binaryOutputRef.current = undefined;
    fileResultsRef.current = [];
  }, []);

  const [operationDone, setOperationDone] = useState(false);
  const [statusText, setStatusText] = useState<string | null>(null);
  const [verifiedSigner, setVerifiedSigner] = useState<
    PublicContactKey | ProtectedKeyBlob | null
  >(null);
  const [signatureTone, setSignatureTone] = useState<"success" | "warning">(
    "success",
  );
  const [binaryOutput, setBinaryOutputState] = useState<
    Uint8Array | undefined
  >();
  const [fileResults, setFileResultsState] = useState<FileResult[]>([]);
  // Every write goes through these so the mirror refs stay in step with
  // render state and `wipePlaintext` can never miss a live buffer.
  const setBinaryOutput = useCallback((b: Uint8Array | undefined) => {
    binaryOutputRef.current = b;
    setBinaryOutputState(b);
  }, []);
  const setFileResults = useCallback((r: FileResult[]) => {
    fileResultsRef.current = r;
    setFileResultsState(r);
  }, []);
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
  const [pendingPasswordDecrypt, setPendingPasswordDecrypt] = useState(false);
  const [messageEncryption, setMessageEncryption] =
    useState<MessageEncryption | null>(null);
  const [passwordInput, setPasswordInput] = useState("");
  const [passwordError, setPasswordError] = useState<string | null>(null);
  // Which engine the staged input is in, as a BOOLEAN derived from the
  // text at the moment it was set -- the text itself never enters state
  // (see the input block above). Split from the file half so a drop and
  // a paste each own their answer.
  const [inputIsAgeText, setInputIsAgeText] = useState(false);
  const [publicKeyDetected, setPublicKeyDetected] = useState(false);
  const [privateKeyDetected, setPrivateKeyDetected] = useState(false);
  // The one derived answer both the effect below and consumers read.
  const inputIsAge =
    inputIsAgeText || files.some((f) => /\.age$/i.test(f.name));

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
    setPendingPasswordDecrypt(false);
    setPendingCrxSign(false);
  }, [setOutput, setBinaryOutput, setFileResults]);

  const resetAll = useCallback(() => {
    setInput("");
    setFiles([]);
    setPublicKeyDetected(false);
    setPrivateKeyDetected(false);
    setInputIsAgeText(false);
    setMessageEncryption(null);
    resetOutput();
  }, [resetOutput, setInput]);

  // Public/private-key detection (and the armor-driven mode nudge) for a
  // new box value. Split out of `handleInputChange` so the clear-undo path
  // can re-arm the private-key warning + mask: undoing a clear must not
  // silently drop the "don't paste private keys here" banner.
  const applyDetection = useCallback((text: string) => {
    setPublicKeyDetected(false);
    setPrivateKeyDetected(false);
    setInputIsAgeText(looksLikeAgeMessage(text));
    // Stale the moment the text changes: keeping the previous message's
    // answer would hide the key picker for a message that needs one (or
    // show it for one that does not) until the async scan catches up.
    setMessageEncryption(null);
    if (looksLikePrivateKey(text)) {
      // Flag first; the draft snapshot is refused while this is true so the
      // armor never reaches the encrypted draft blob. Covers every armored
      // private-key flavour (PGP + any raw PEM), not just PGP, so a pasted
      // OpenSSH/EC/etc. key can't leak into the draft either.
      setPrivateKeyDetected(true);
    } else if (
      text.includes("-----BEGIN PGP MESSAGE-----") ||
      looksLikeAgeMessage(text)
    ) {
      // Both engines' ciphertext means the same thing to the user: this
      // is something to decrypt.
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
        // Writes the ref; the `<pre>` re-seeds from it if/when it mounts.
        setOutput(draft.output);
        setSelectedRecipientIds(draft.selectedRecipientIds);
        setSelectedKeyId(draft.selectedKeyId);
      }
      onRestored?.();
    })();
  }, [restoreCt, onRestored, setInput, setOutput]);

  // Expose the draft to the parent as a PULL, not a push. The old push
  // contract fired an effect on every keystroke whose closure captured the
  // plaintext, and React retains such closures on the previous fiber
  // (`alternate`) after unmount -- which is precisely how the composed
  // message survived a master lock. A stable getter reads `inputRef` at
  // call time instead, so nothing durable ever closes over the string.
  const draftFieldsRef = useRef({
    mode,
    selectedRecipientIds,
    selectedKeyId,
    privateKeyDetected,
  });
  useEffect(() => {
    draftFieldsRef.current = {
      mode,
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
      output: outputRef.current,
      selectedRecipientIds: f.selectedRecipientIds,
      selectedKeyId: f.selectedKeyId,
    };
  }, []);

  const onRegisterDraftSource = opts.onRegisterDraftSource;
  useEffect(() => {
    if (!onRegisterDraftSource) return;
    onRegisterDraftSource({ getDraft, wipe: wipePlaintext });
    return () => onRegisterDraftSource(null);
  }, [onRegisterDraftSource, getDraft, wipePlaintext]);

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

  // An age message can only be decrypted by an SSH identity, so a PGP
  // key left selected from a moment ago is the one key that definitely
  // cannot read it. Drop that stale cross-engine selection and, in the
  // overwhelmingly common single-SSH-key case, land on the only answer.
  // (Which of SEVERAL SSH keys it is gets refined in
  // `useWorkspaceOperations`, which can ask the engine.)
  const myKeysForAge = opts.myKeys;
  useEffect(() => {
    if (mode !== "decrypt" || !inputIsAge) return;
    const sshKeys = myKeysForAge.filter(isSshRecord);
    const selected = sshKeys.some((k) => k.keyId === selectedKeyId);
    if (selected) return;
    setSelectedKeyId(sshKeys.length > 0 ? sshKeys[0].keyId : null);
  }, [mode, inputIsAge, myKeysForAge, selectedKeyId]);

  // Signing is OpenPGP-only, so an SSH identity left selected from the
  // decrypt tab (or auto-picked as the default key) is never a valid
  // answer to "sign with". Same shape as the age rule above, mirrored.
  const myKeysForSign = opts.myKeys;
  useEffect(() => {
    if (mode !== "sign") return;
    const pgpKeys = myKeysForSign.filter(isPgpRecord);
    if (pgpKeys.some((k) => k.keyId === selectedKeyId)) return;
    setSelectedKeyId(pgpKeys.length > 0 ? pgpKeys[0].keyId : null);
  }, [mode, myKeysForSign, selectedKeyId]);

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
  /**
   * The box's own `onChange`: every keystroke, and nothing is repaired.
   *
   * DELIBERATELY NOT the repair path. This handler fires while someone
   * is TYPING, and armor repair has no business running then -- it is
   * for content that ARRIVES (a paste, a drop), which is the only way a
   * mangled key or message can get here. Someone writing prose that
   * happens to quote a `\n` deserves to be left alone, and rewriting the
   * box mid-sentence would move their caret to do it.
   */
  const handleInputChange = useCallback(
    (text: string) => {
      setInput(text);
      setFiles([]);
      resetOutput();
      applyDetection(text);
    },
    [resetOutput, setInput, applyDetection],
  );

  /**
   * Text that ARRIVED rather than being typed -- a paste, or a dropped
   * text selection. This is the only path that repairs armor.
   *
   * Detection runs on the REPAIRED text on purpose: an escaped private
   * key must still trip `looksLikePrivateKey`, or it reaches the draft
   * sealer as unrecognised prose with the mask off.
   */
  const handleTextArrival = useCallback(
    (text: string) => {
      handleInputChange(recoverArmorIfNeeded(text));
    },
    [handleInputChange],
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
        if (newFiles.some((f) => /\.(gpg|pgp|asc|age)$/i.test(f.name))) {
          return "decrypt";
        }
        return current;
      });
      // Cleared wherever the STAGED MESSAGE changes -- here, in
      // `applyDetection` for text, and in `resetAll` -- but deliberately
      // NOT in `resetOutput`, which also runs at the START of an
      // operation: clearing it there would bring the key picker back
      // while the password prompt for this very message is still up.
      setMessageEncryption(null);
      resetOutput();
    },
    [resetOutput, setInput],
  );

  const removeFile = useCallback((index: number) => {
    setFiles((prev) => prev.filter((_, i) => i !== index));
    setMessageEncryption(null);
  }, []);

  const clearFiles = useCallback(() => {
    setFiles([]);
    setInput("");
    setMessageEncryption(null);
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
      handleTextArrival(intake.text);
    }
    onIntakeConsumed?.();
  }, [intake, onIntakeConsumed, handleFileDrop, handleTextArrival]);

  return {
    mode,
    setMode,
    inputElRef,
    getInput,
    setInput,
    hasInput: inputInfo.len > 0,
    hasTrimmedInput: inputInfo.nonBlank,
    inputVersion: inputInfo.version,
    inputIsAge,
    wipePlaintext,
    stashClearUndo,
    restoreClearUndo,
    clearUndoAvailable,
    outputElRef,
    getOutput,
    setOutput,
    hasOutput: outputInfo.len > 0,
    outputPublicKeyDetected: outputInfo.publicKey,
    outputVersion: outputInfo.version,
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
    pendingPasswordDecrypt,
    setPendingPasswordDecrypt,
    messageEncryption,
    setMessageEncryption,
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
    handleTextArrival,
    handleFileDrop,
    removeFile,
    clearFiles,
    resetOutput,
    resetAll,
  };
}
