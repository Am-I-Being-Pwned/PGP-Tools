import { useCallback, useEffect, useRef, useState } from "react";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { PresentedError } from "../../lib/errors/present";
import type { WorkspaceAction } from "../../lib/messages";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { FileResult } from "../../lib/utils/download";
import type { WorkspaceDraft } from "../../lib/workspace-draft";
import { looksLikePrivateKey } from "../../lib/drop-routing";
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

export interface WorkspaceState {
  mode: Mode;
  setMode: (m: Mode) => void;
  input: string;
  setInput: (s: string) => void;
  output: string;
  setOutput: (s: string) => void;
  operationDone: boolean;
  setOperationDone: (b: boolean) => void;
  /** True once any operation has produced output this session, and stays
   *  true across a `resetOutput` (only `resetAll` clears it). Lets the view
   *  reserve the output slot so a later clear -- e.g. changing the recipient
   *  key -- doesn't collapse the layout and jump the controls around. */
  hasProducedOutput: boolean;
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
  selectedRecipientId: string | null;
  setSelectedRecipientId: (s: string | null) => void;
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
  /** Fires whenever the salient draft state changes. The parent stores
   *  the snapshot in a ref so it can encrypt on auto-lock. */
  onDraftChange?: (draft: WorkspaceDraft | null) => void;
  /** A drop routed here by the global dropzone. Applied once per nonce. */
  intake?: WorkspaceIntake | null;
  onIntakeConsumed?: () => void;
}): WorkspaceState {
  const [mode, setMode] = useState<Mode>("encrypt");
  const [input, setInput] = useState("");
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
  const [selectedRecipientId, setSelectedRecipientId] = useState<string | null>(
    null,
  );
  const [selectedKeyId, setSelectedKeyId] = useState<string | null>(null);
  const [selectedCrxKeyId, setSelectedCrxKeyId] = useState<string | null>(null);
  const [pendingCrxSign, setPendingCrxSign] = useState(false);
  const [isExtensionZip, setIsExtensionZip] = useState(false);
  const [signKind, setSignKind] = useState<"pgp" | "crx">("pgp");
  const [error, setError] = useState<PresentedError | null>(null);
  const [loading, setLoading] = useState(false);
  const [files, setFiles] = useState<File[]>([]);
  const [alsoSign, setAlsoSign] = useState(false);
  const [zipFiles, setZipFiles] = useState(true);
  const [needsPassword, setNeedsPassword] = useState(false);
  const [passwordInput, setPasswordInput] = useState("");
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [publicKeyDetected, setPublicKeyDetected] = useState(false);
  const [privateKeyDetected, setPrivateKeyDetected] = useState(false);
  const [hasProducedOutput, setHasProducedOutput] = useState(false);

  // Latch: once an operation completes, remember it so the view can keep the
  // output slot reserved. `resetOutput` deliberately doesn't clear this (a
  // recipient change shouldn't release the space); only `resetAll` does.
  useEffect(() => {
    if (operationDone) setHasProducedOutput(true);
  }, [operationDone]);

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
    setHasProducedOutput(false);
    resetOutput();
  }, [resetOutput]);

  useEffect(() => {
    void getPreferences().then((p) => setAlsoSign(p.signWhenEncrypting));
  }, []);

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
        setInput(draft.input);
        setOutput(draft.output);
        setSelectedRecipientId(draft.selectedRecipientId);
        setSelectedKeyId(draft.selectedKeyId);
      }
      onRestored?.();
    })();
  }, [restoreCt, onRestored]);

  // Mirror salient draft state to the parent on every change. The
  // parent stores the latest snapshot in a ref and encrypts it
  // synchronously when an auto-lock fires.
  const onDraftChange = opts.onDraftChange;
  useEffect(() => {
    if (!onDraftChange) return;
    // Refuse to snapshot armored private-key material into the draft.
    // The draft is encrypted at rest, but the plaintext armor still
    // exists in JS heap while the draft serializer runs and during
    // any future restore. Pasting a private key here is almost always
    // a user error (they meant to use the Import flow), so dropping
    // the snapshot is safer than persisting it.
    if (privateKeyDetected) {
      onDraftChange(null);
      return;
    }
    onDraftChange({
      mode,
      input,
      output,
      selectedRecipientId,
      selectedKeyId,
    });
  }, [
    mode,
    input,
    output,
    selectedRecipientId,
    selectedKeyId,
    privateKeyDetected,
    onDraftChange,
  ]);

  useEffect(() => {
    if (opts.myKeys.length > 0 && !selectedKeyId) {
      setSelectedKeyId(opts.myKeys[0].keyId);
    }
  }, [opts.myKeys, selectedKeyId]);

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

  const allRecipientKeys = opts.allPublicKeys;
  useEffect(() => {
    if (
      allRecipientKeys &&
      allRecipientKeys.length > 0 &&
      !selectedRecipientId
    ) {
      setSelectedRecipientId(allRecipientKeys[0].keyId);
    }
  }, [allRecipientKeys, selectedRecipientId]);

  const { pendingAction, onClearPending, encryptToKeyId, onClearEncryptTo } =
    opts;

  useEffect(() => {
    if (pendingAction) {
      setMode(pendingAction.action);
      setInput(pendingAction.text);
      setFiles([]);
      resetOutput();
      onClearPending?.();
    }
  }, [pendingAction, onClearPending, resetOutput]);

  useEffect(() => {
    if (!encryptToKeyId) return;
    setMode("encrypt");
    setSelectedRecipientId(encryptToKeyId);
    onClearEncryptTo?.();
  }, [encryptToKeyId, onClearEncryptTo]);

  const handleInputChange = useCallback(
    (text: string) => {
      setInput(text);
      setFiles([]);
      resetOutput();
      setPublicKeyDetected(false);
      setPrivateKeyDetected(false);
      if (looksLikePrivateKey(text)) {
        // Flag first; the drafting effect skips snapshots while this is true
        // so the armor doesn't end up in the encrypted draft blob. Covers
        // every armored private-key flavour (PGP + any raw PEM), not just
        // PGP, so a pasted OpenSSH/EC/etc. key can't leak into the draft.
        setPrivateKeyDetected(true);
      } else if (text.includes("-----BEGIN PGP MESSAGE-----")) {
        setMode("decrypt");
      } else if (text.includes("-----BEGIN PGP SIGNED MESSAGE-----")) {
        setMode("verify");
      } else if (text.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
        setPublicKeyDetected(true);
      }
    },
    [resetOutput],
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
    [resetOutput],
  );

  const removeFile = useCallback((index: number) => {
    setFiles((prev) => prev.filter((_, i) => i !== index));
  }, []);

  const clearFiles = useCallback(() => {
    setFiles([]);
    setInput("");
    resetOutput();
  }, [resetOutput]);

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
    input,
    setInput,
    output,
    setOutput,
    operationDone,
    setOperationDone,
    hasProducedOutput,
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
    selectedRecipientId,
    setSelectedRecipientId,
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
