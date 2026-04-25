import { DownloadIcon, RotateCcwIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";
import { Checkbox } from "@amibeingpwned/ui/checkbox";

import type { OperationAction } from "../../lib/messages";
import type { EncryptInput } from "../../lib/pgp/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { WorkspaceDraft } from "../../lib/workspace-draft";
import * as pgpOps from "../../lib/pgp/operations";
import { savePreferences } from "../../lib/storage/preferences";
import { INPUT_CLASS } from "../../lib/utils/styles";
import {
  isZipArchive,
  zipFiles as zipFilesToArchive,
} from "../../lib/utils/zip";
import { KeySelector } from "./KeySelector";
import { useWorkspaceState } from "./useWorkspaceState";
import { WorkspaceInput } from "./WorkspaceInput";
import { WorkspaceResults } from "./WorkspaceResults";

interface WorkspaceViewProps {
  myKeys: ProtectedKeyBlob[];
  contacts: PublicContactKey[];
  getKeyHandle: (keyId: string) => number | null;
  onUnlockWithPassword: (
    blob: ProtectedKeyBlob,
    password: string,
  ) => Promise<boolean>;
  onUnlockWithPasskey: (blob: ProtectedKeyBlob) => Promise<boolean | "cancelled">;
  pendingAction?: { action: OperationAction; text: string } | null;
  onClearPending?: () => void;
  encryptToKeyId?: string | null;
  onClearEncryptTo?: () => void;
  onNavigateToKeys?: () => void;
  autoDownloadFiles?: boolean;
  autoDownloadText?: boolean;
  onOperationComplete?: () => void;
  /** Encrypted workspace draft to rehydrate on mount (from a prior auto-lock). */
  restoreDraft?: Uint8Array | null;
  /** Fired once the draft has been decrypted + applied. */
  onDraftRestored?: () => void;
  /** Fired on every salient state change so the parent can stash a snapshot. */
  onDraftChange?: (draft: WorkspaceDraft | null) => void;
}

export function WorkspaceView({
  myKeys,
  contacts,
  getKeyHandle,
  onUnlockWithPassword,
  onUnlockWithPasskey,
  pendingAction,
  onClearPending,
  encryptToKeyId,
  onClearEncryptTo,
  onNavigateToKeys,
  autoDownloadFiles,
  autoDownloadText,
  onOperationComplete,
  restoreDraft,
  onDraftRestored,
  onDraftChange,
}: WorkspaceViewProps) {
  const allPublicKeys: (ProtectedKeyBlob | PublicContactKey)[] = [
    ...myKeys,
    ...contacts,
  ];

  const s = useWorkspaceState({
    myKeys,
    pendingAction,
    onClearPending,
    allPublicKeys,
    encryptToKeyId,
    onClearEncryptTo,
    restoreDraft,
    onDraftRestored,
    onDraftChange,
  });

  function findSigner(signerKeyId: string | null) {
    if (!signerKeyId) return null;
    const hex = signerKeyId.toUpperCase();
    return (
      contacts.find((c) => c.keyId.toUpperCase().endsWith(hex)) ??
      myKeys.find((k) => k.keyId.toUpperCase().endsWith(hex)) ??
      null
    );
  }

  function formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  function outputFileName(): string {
    if (s.files.length === 0) return "output.gpg";
    if (s.files.length === 1 || !s.zipFiles) {
      const name = s.files[0].name;
      if (s.mode === "encrypt") return `${name}.gpg`;
      if (s.mode === "sign") return `${name}.asc`;
      return name.replace(/\.(gpg|pgp|asc)$/i, "") || name;
    }
    if (s.mode === "encrypt") return "encrypted-files.zip.gpg";
    return "decrypted-files.zip";
  }

  async function ensureUnlocked(keyId: string): Promise<number | null> {
    const cached = getKeyHandle(keyId);
    if (cached !== null) return cached;

    const blob = myKeys.find((k) => k.keyId === keyId);
    if (!blob) return null;

    if (blob.protection.method === "passkey") {
      const result = await onUnlockWithPasskey(blob);
      if (result === "cancelled") return null;
      if (!result) throw new Error("Passkey authentication failed.");
      return getKeyHandle(keyId);
    }

    s.setNeedsPassword(true);
    s.setPasswordInput("");
    s.setPasswordError(null);
    return null;
  }

  async function resolveFileBytes(): Promise<Uint8Array> {
    if (s.files.length > 1 && s.zipFiles) {
      return zipFilesToArchive(s.files);
    }
    return new Uint8Array(await s.files[0].arrayBuffer());
  }

  function downloadBlob(blob: Blob, name: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  }

  function triggerDownload() {
    if (s.fileResults.length > 0) {
      for (const r of s.fileResults) {
        downloadBlob(
          new Blob([r.data.slice()], { type: "application/octet-stream" }),
          r.name,
        );
      }
      return;
    }
    const blob = s.binaryOutput
      ? new Blob([s.binaryOutput.slice()], { type: "application/octet-stream" })
      : new Blob([s.output], { type: "text/plain" });
    downloadBlob(blob, outputFileName());
  }

  function triggerDownloadResults(
    results: { name: string; data: Uint8Array }[],
  ) {
    for (const r of results) {
      downloadBlob(
        new Blob([r.data.slice()], { type: "application/octet-stream" }),
        r.name,
      );
    }
  }

  function maybeAutoDownload(
    isFileInput: boolean,
    data?:
      | { text?: string; binary?: Uint8Array }
      | { results: { name: string; data: Uint8Array }[] },
  ) {
    if (!(isFileInput ? autoDownloadFiles : autoDownloadText)) return;
    if (data && "results" in data) {
      triggerDownloadResults(data.results);
    } else if (data) {
      const blob = data.binary
        ? new Blob([data.binary.slice()], { type: "application/octet-stream" })
        : new Blob([data.text ?? ""], { type: "text/plain" });
      downloadBlob(blob, outputFileName());
    } else {
      triggerDownload();
    }
  }

  const execute = async () => {
    s.setError(null);
    s.setOutput("");
    s.setBinaryOutput(undefined);
    s.setFileResults([]);
    s.setOperationDone(false);
    s.setStatusText(null);
    s.setVerifiedSigner(null);
    s.setNeedsPassword(false);
    s.setLoading(true);

    try {
      switch (s.mode) {
        case "encrypt":
          await executeEncrypt();
          break;
        case "decrypt":
          await executeDecrypt();
          break;
        case "sign":
          await executeSign();
          break;
        case "verify":
          await executeVerify();
          break;
      }
    } catch (e) {
      s.setError(e instanceof Error ? e.message : String(e));
    } finally {
      s.setLoading(false);
      onOperationComplete?.();
    }
  };

  async function executeEncrypt() {
    const recipient = allPublicKeys.find(
      (k) => k.keyId === s.selectedRecipientId,
    );
    if (!recipient) {
      s.setError("Select a recipient key.");
      return;
    }
    const recipientArmored =
      "armoredPublicKey" in recipient
        ? recipient.armoredPublicKey
        : recipient.publicKeyArmored;

    let signingHandle: number | null = null;
    if (s.alsoSign && s.selectedKeyId) {
      const handle = await ensureUnlocked(s.selectedKeyId);
      if (handle === null) return;
      signingHandle = handle;
    }

    const doEncrypt = async (input: EncryptInput) => {
      if (signingHandle !== null) {
        return pgpOps.encryptWithSigningHandle({
          input,
          recipientPublicKeys: [recipientArmored],
          signingKeyHandle: signingHandle,
        });
      }
      return pgpOps.encrypt({
        input,
        recipientPublicKeys: [recipientArmored],
      });
    };

    const isFileInput = s.files.length > 0;

    if (isFileInput && s.files.length > 1 && !s.zipFiles) {
      const results: { name: string; data: Uint8Array }[] = [];
      for (const file of s.files) {
        const bytes = new Uint8Array(await file.arrayBuffer());
        const result = await doEncrypt({
          kind: "binary",
          binary: bytes,
          armor: false,
        });
        const data =
          typeof result === "string"
            ? new TextEncoder().encode(result)
            : result;
        results.push({ name: `${file.name}.gpg`, data });
      }
      s.setFileResults(results);
      const totalSize = results.reduce((sum, r) => sum + r.data.length, 0);
      s.setStatusText(
        `${results.length} files encrypted (${formatSize(totalSize)} total)`,
      );
      s.setOperationDone(true);
      maybeAutoDownload(true, { results });
    } else if (isFileInput) {
      const bytes = await resolveFileBytes();
      const result = await doEncrypt({
        kind: "binary",
        binary: bytes,
        armor: false,
      });
      if (typeof result === "string") {
        s.setOutput(result);
      } else {
        s.setBinaryOutput(result);
      }
      if (s.files.length > 1 && s.zipFiles) {
        s.setStatusText(`${s.files.length} files zipped and encrypted`);
      }
      s.setOperationDone(true);
      maybeAutoDownload(true, {
        text: typeof result === "string" ? result : undefined,
        binary: typeof result !== "string" ? result : undefined,
      });
    } else {
      const result = await doEncrypt({ kind: "text", text: s.input });
      if (typeof result === "string") {
        s.setOutput(result);
      } else {
        s.setBinaryOutput(result);
      }
      s.setOperationDone(true);
      maybeAutoDownload(false, {
        text: typeof result === "string" ? result : undefined,
        binary: typeof result !== "string" ? result : undefined,
      });
    }
  }

  async function executeDecrypt() {
    if (!s.selectedKeyId) {
      s.setError("Select a decryption key.");
      return;
    }
    const keyHandle = await ensureUnlocked(s.selectedKeyId);
    if (keyHandle === null) return;

    const allPubArmored = [
      ...myKeys.map((k) => k.publicKeyArmored),
      ...contacts.map((c) => c.armoredPublicKey),
    ];

    const handleSig = (result: {
      signatureValid: boolean | null;
      signerKeyId: string | null;
    }) => {
      if (result.signatureValid === true) {
        s.setStatusText("Signature verified");
        const signer = findSigner(result.signerKeyId);
        if (signer) s.setVerifiedSigner(signer);
      } else if (result.signatureValid === false) {
        throw new Error(
          "Signature verification FAILED - this message may have been tampered with",
        );
      }
    };

    const isFileInput = s.files.length > 0;

    try {
      if (isFileInput && s.files.length > 1) {
        const results: { name: string; data: Uint8Array }[] = [];
        for (const file of s.files) {
          const bytes = new Uint8Array(await file.arrayBuffer());
          const result = await pgpOps.decryptWithHandle({
            input: { kind: "binary", binaryMessage: bytes },
            keyHandle,
            verificationPublicKeys: allPubArmored,
          });
          const data =
            result.data instanceof Uint8Array
              ? result.data
              : new TextEncoder().encode(result.data);
          const outName =
            file.name.replace(/\.(gpg|pgp|asc)$/i, "") || file.name;
          results.push({ name: outName, data });
          handleSig(result);
        }
        s.setFileResults(results);
        const totalSize = results.reduce((sum, r) => sum + r.data.length, 0);
        s.setStatusText(
          `${results.length} files decrypted (${formatSize(totalSize)} total)`,
        );
        s.setOperationDone(true);
        maybeAutoDownload(true, { results });
      } else if (isFileInput) {
        const bytes = new Uint8Array(await s.files[0].arrayBuffer());
        const result = await pgpOps.decryptWithHandle({
          input: { kind: "binary", binaryMessage: bytes },
          keyHandle,
          verificationPublicKeys: allPubArmored,
        });
        if (result.data instanceof Uint8Array) {
          if (isZipArchive(result.data)) {
            s.setBinaryOutput(result.data);
            s.setStatusText("Decrypted archive containing multiple files");
          } else {
            try {
              const decoded = new TextDecoder("utf-8", {
                fatal: true,
              }).decode(result.data);
              s.setOutput(decoded);
            } catch {
              s.setBinaryOutput(result.data);
            }
          }
        } else {
          s.setOutput(result.data);
        }
        handleSig(result);
        s.setOperationDone(true);
        maybeAutoDownload(true, {
          text: typeof result.data === "string" ? result.data : undefined,
          binary: result.data instanceof Uint8Array ? result.data : undefined,
        });
      } else {
        const result = await pgpOps.decryptWithHandle({
          input: { kind: "armored", armoredMessage: s.input },
          keyHandle,
          verificationPublicKeys: allPubArmored,
        });
        if (typeof result.data === "string") {
          s.setOutput(result.data);
        } else {
          s.setBinaryOutput(result.data);
        }
        handleSig(result);
        s.setOperationDone(true);
        maybeAutoDownload(false, {
          text: typeof result.data === "string" ? result.data : undefined,
          binary: result.data instanceof Uint8Array ? result.data : undefined,
        });
      }
    } catch {
      s.setError(
        "Decryption failed. The message may be corrupted or the wrong key was selected.",
      );
      return;
    }
  }

  async function executeSign() {
    const signKeyId = s.selectedKeyId ?? myKeys[0]?.keyId;
    if (!signKeyId) {
      s.setError("No signing key available.");
      return;
    }
    const keyHandle = await ensureUnlocked(signKeyId);
    if (keyHandle === null) return;

    if (s.files.length > 1) {
      const results: { name: string; data: Uint8Array }[] = [];
      for (const file of s.files) {
        const text = await file.text();
        const signed = await pgpOps.signWithHandle(text, keyHandle);
        results.push({
          name: `${file.name}.asc`,
          data: new TextEncoder().encode(signed),
        });
      }
      s.setFileResults(results);
      s.setStatusText(`${results.length} files signed`);
      s.setOperationDone(true);
      maybeAutoDownload(true, { results });
    } else if (s.files.length === 1) {
      const text = await s.files[0].text();
      const signed = await pgpOps.signWithHandle(text, keyHandle);
      s.setFileResults([
        {
          name: `${s.files[0].name}.asc`,
          data: new TextEncoder().encode(signed),
        },
      ]);
      s.setOperationDone(true);
      maybeAutoDownload(true, {
        results: [
          {
            name: `${s.files[0].name}.asc`,
            data: new TextEncoder().encode(signed),
          },
        ],
      });
    } else {
      const signed = await pgpOps.signWithHandle(s.input, keyHandle);
      s.setOutput(signed);
      s.setOperationDone(true);
      maybeAutoDownload(false, { text: signed });
    }
  }

  async function executeVerify() {
    if (contacts.length === 0 && myKeys.length === 0) {
      s.setError("No public keys available for verification.");
      return;
    }
    const allPubArmored = [
      ...myKeys.map((k) => k.publicKeyArmored),
      ...contacts.map((c) => c.armoredPublicKey),
    ];

    try {
      const messageText =
        s.files.length > 0 ? await s.files[0].text() : s.input;
      const result = await pgpOps.verify({
        signedMessage: messageText,
        verificationPublicKeys: allPubArmored,
      });
      if (result.signatureValid) {
        const isFileInput = s.files.length > 0;
        s.setOperationDone(true);
        s.setStatusText("Signature verified");
        const signer = findSigner(result.signerKeyId);
        if (signer) s.setVerifiedSigner(signer);
        maybeAutoDownload(isFileInput, { text: result.text });
      } else {
        s.setError(
          "Verification failed. The signature may be invalid or the signer's key is not in your contacts.",
        );
      }
    } catch {
      s.setError(
        "Verification failed. The signature may be invalid or the signer's key is not in your contacts.",
      );
    }
  }

  const handlePasswordSubmit = async () => {
    const keyId = s.selectedKeyId ?? myKeys[0]?.keyId;
    if (!keyId) return;
    const blob = myKeys.find((k) => k.keyId === keyId);
    if (!blob) return;

    s.setLoading(true);
    s.setPasswordError(null);

    try {
      const ok = await onUnlockWithPassword(blob, s.passwordInput);
      if (!ok) {
        s.setPasswordError("Wrong password.");
        s.setLoading(false);
        return;
      }
      s.setNeedsPassword(false);
      s.setPasswordInput("");
      await execute();
    } catch {
      s.setPasswordError("Unlock failed.");
      s.setLoading(false);
    }
  };

  const needsRecipient = s.mode === "encrypt";
  const needsPrivateKey = s.mode === "decrypt" || s.mode === "sign";
  const hasInput = s.files.length > 0 || s.input.length > 0;

  return (
    <div className="flex h-full flex-col gap-3">
      <WorkspaceInput
        mode={s.mode}
        onModeChange={s.setMode}
        input={s.input}
        onInputChange={s.handleInputChange}
        files={s.files}
        onFileDrop={s.handleFileDrop}
        onRemoveFile={s.removeFile}
        onClearFiles={s.clearFiles}
        publicKeyDetected={s.publicKeyDetected}
        onNavigateToKeys={onNavigateToKeys}
        operationDone={s.operationDone}
        onReset={s.resetAll}
        onResetOutput={s.resetOutput}
      />

      <div className="space-y-3">
        {needsRecipient && (
          <KeySelector
            label="Key for recipient"
            contacts={contacts}
            myKeys={myKeys}
            selectedKeyId={s.selectedRecipientId}
            onSelect={s.setSelectedRecipientId}
            emptyText="No contacts yet."
            emptyAction={onNavigateToKeys}
            emptyActionLabel="Add a contact"
          />
        )}

        {needsPrivateKey && (
          <KeySelector
            label={s.mode === "sign" ? "Sign with" : "Decrypt with"}
            keys={myKeys}
            selectedKeyId={s.selectedKeyId}
            onSelect={s.setSelectedKeyId}
            emptyText="No keys yet."
            emptyAction={onNavigateToKeys}
            emptyActionLabel="Create one"
          />
        )}

        {s.mode === "encrypt" && (
          <div className="space-y-2">
            <div className="flex items-center gap-4">
              {myKeys.length > 0 && (
                <label className="flex items-center gap-2">
                  <Checkbox
                    checked={s.alsoSign}
                    onCheckedChange={(v) => {
                      const checked = v === true;
                      s.setAlsoSign(checked);
                      s.resetOutput();
                      void savePreferences({ signWhenEncrypting: checked });
                    }}
                  />
                  <span className="text-sm">Sign</span>
                </label>
              )}
              {s.files.length > 1 && (
                <label className="flex items-center gap-2">
                  <Checkbox
                    checked={s.zipFiles}
                    onCheckedChange={(v) => {
                      s.setZipFiles(v === true);
                      s.resetOutput();
                    }}
                  />
                  <span className="text-sm">Zip files</span>
                </label>
              )}
            </div>
            {s.alsoSign && myKeys.length > 1 && (
              <KeySelector
                label="Sign with"
                keys={myKeys}
                selectedKeyId={s.selectedKeyId}
                onSelect={s.setSelectedKeyId}
              />
            )}
          </div>
        )}


        {s.needsPassword && (
          <div className="flex items-stretch gap-2">
            <input
              type="password"
              placeholder="Enter key password"
              value={s.passwordInput}
              onChange={(e) => s.setPasswordInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void handlePasswordSubmit();
              }}
              className={`${INPUT_CLASS} h-9 flex-1 py-0`}
              autoFocus
            />
            <Button
              size="sm"
              className="h-9 shrink-0"
              onClick={handlePasswordSubmit}
              disabled={s.loading}
            >
              {s.loading
                ? "..."
                : s.mode === "decrypt"
                  ? "Decrypt"
                  : s.mode === "sign"
                    ? "Sign"
                    : "Go"}
            </Button>
          </div>
        )}
        {s.passwordError && (
          <p className="text-destructive text-xs">{s.passwordError}</p>
        )}

        <WorkspaceResults
          error={s.error}
          output={s.output}
          binaryOutput={s.binaryOutput}
          fileResults={s.fileResults}
          fileName={outputFileName()}
          operationDone={s.operationDone}
          statusText={s.statusText ?? undefined}
          verifiedSigner={s.verifiedSigner}
        />

        {!s.needsPassword && (
          <div className="flex gap-2">
            <Button
              className="flex-1 capitalize"
              onClick={
                s.operationDone
                  ? s.mode === "verify"
                    ? s.resetAll
                    : () => triggerDownload()
                  : execute
              }
              disabled={s.loading || !hasInput}
            >
              {s.loading ? (
                "Processing..."
              ) : s.operationDone ? (
                s.mode === "verify" ? (
                  "Reset"
                ) : (
                  <span className="flex items-center gap-2">
                    <DownloadIcon className="h-4 w-4" />
                    Download
                  </span>
                )
              ) : (
                s.mode
              )}
            </Button>
            {s.operationDone && s.mode !== "verify" && (
              <Button
                variant="outline"
                size="icon"
                onClick={s.resetAll}
                title="Clear input and output"
                aria-label="Clear input and output"
              >
                <RotateCcwIcon className="h-4 w-4" />
              </Button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
