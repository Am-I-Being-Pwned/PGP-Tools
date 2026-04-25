import { useCallback, useEffect, useRef, useState } from "react";

import type { OperationAction } from "../../lib/messages";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { getPreferences } from "../../lib/storage/preferences";
import type { WorkspaceDraft } from "../../lib/workspace-draft";
import { decryptWorkspaceDraft } from "../../lib/workspace-draft";

type Mode = "encrypt" | "decrypt" | "sign" | "verify";

export interface WorkspaceState {
  mode: Mode;
  setMode: (m: Mode) => void;
  input: string;
  setInput: (s: string) => void;
  output: string;
  setOutput: (s: string) => void;
  operationDone: boolean;
  setOperationDone: (b: boolean) => void;
  statusText: string | null;
  setStatusText: (s: string | null) => void;
  verifiedSigner: PublicContactKey | ProtectedKeyBlob | null;
  setVerifiedSigner: (s: PublicContactKey | ProtectedKeyBlob | null) => void;
  binaryOutput: Uint8Array | undefined;
  setBinaryOutput: (b: Uint8Array | undefined) => void;
  fileResults: { name: string; data: Uint8Array }[];
  setFileResults: (r: { name: string; data: Uint8Array }[]) => void;
  selectedRecipientId: string | null;
  setSelectedRecipientId: (s: string | null) => void;
  selectedKeyId: string | null;
  setSelectedKeyId: (s: string | null) => void;
  error: string | null;
  setError: (s: string | null) => void;
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
  handleInputChange: (text: string) => void;
  handleFileDrop: (newFiles: File[]) => void;
  removeFile: (index: number) => void;
  clearFiles: () => void;
  resetOutput: () => void;
  resetAll: () => void;
}

export function useWorkspaceState(opts: {
  myKeys: ProtectedKeyBlob[];
  pendingAction?: { action: OperationAction; text: string } | null;
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
}): WorkspaceState {
  const [mode, setMode] = useState<Mode>("encrypt");
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [operationDone, setOperationDone] = useState(false);
  const [statusText, setStatusText] = useState<string | null>(null);
  const [verifiedSigner, setVerifiedSigner] = useState<
    PublicContactKey | ProtectedKeyBlob | null
  >(null);
  const [binaryOutput, setBinaryOutput] = useState<Uint8Array | undefined>();
  const [fileResults, setFileResults] = useState<
    { name: string; data: Uint8Array }[]
  >([]);
  const [selectedRecipientId, setSelectedRecipientId] = useState<string | null>(
    null,
  );
  const [selectedKeyId, setSelectedKeyId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [files, setFiles] = useState<File[]>([]);
  const [alsoSign, setAlsoSign] = useState(false);
  const [zipFiles, setZipFiles] = useState(true);
  const [needsPassword, setNeedsPassword] = useState(false);
  const [passwordInput, setPasswordInput] = useState("");
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [publicKeyDetected, setPublicKeyDetected] = useState(false);

  const resetOutput = useCallback(() => {
    setOutput("");
    setBinaryOutput(undefined);
    setFileResults([]);
    setError(null);
    setOperationDone(false);
    setStatusText(null);
    setVerifiedSigner(null);
    setNeedsPassword(false);
  }, []);

  const resetAll = useCallback(() => {
    setInput("");
    setFiles([]);
    setPublicKeyDetected(false);
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
    onDraftChange,
  ]);

  useEffect(() => {
    if (opts.myKeys.length > 0 && !selectedKeyId) {
      setSelectedKeyId(opts.myKeys[0].keyId);
    }
  }, [opts.myKeys, selectedKeyId]);

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
      setOutput("");
      setBinaryOutput(undefined);
      setError(null);
      setOperationDone(false);
      setStatusText(null);
      setVerifiedSigner(null);
      onClearPending?.();
    }
  }, [pendingAction, onClearPending]);

  useEffect(() => {
    if (!encryptToKeyId) return;
    setMode("encrypt");
    setSelectedRecipientId(encryptToKeyId);
    onClearEncryptTo?.();
  }, [encryptToKeyId, onClearEncryptTo]);

  const handleInputChange = useCallback((text: string) => {
    setInput(text);
    setFiles([]);
    setOutput("");
    setBinaryOutput(undefined);
    setFileResults([]);
    setError(null);
    setOperationDone(false);
    setStatusText(null);
    setVerifiedSigner(null);
    setNeedsPassword(false);
    setPublicKeyDetected(false);
    if (text.includes("-----BEGIN PGP MESSAGE-----")) {
      setMode("decrypt");
    } else if (text.includes("-----BEGIN PGP SIGNED MESSAGE-----")) {
      setMode("verify");
    } else if (text.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
      setPublicKeyDetected(true);
    }
  }, []);

  const handleFileDrop = useCallback((newFiles: File[]) => {
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
    setOutput("");
    setBinaryOutput(undefined);
    setError(null);
    setOperationDone(false);
    setStatusText(null);
  }, []);

  const removeFile = useCallback((index: number) => {
    setFiles((prev) => prev.filter((_, i) => i !== index));
  }, []);

  const clearFiles = useCallback(() => {
    setFiles([]);
    setInput("");
    setOutput("");
    setBinaryOutput(undefined);
    setError(null);
    setOperationDone(false);
    setStatusText(null);
  }, []);

  return {
    mode,
    setMode,
    input,
    setInput,
    output,
    setOutput,
    operationDone,
    setOperationDone,
    statusText,
    setStatusText,
    verifiedSigner,
    setVerifiedSigner,
    binaryOutput,
    setBinaryOutput,
    fileResults,
    setFileResults,
    selectedRecipientId,
    setSelectedRecipientId,
    selectedKeyId,
    setSelectedKeyId,
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
    handleInputChange,
    handleFileDrop,
    removeFile,
    clearFiles,
    resetOutput,
    resetAll,
  };
}
