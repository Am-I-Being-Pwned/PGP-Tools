import { ArrowLeftIcon, DownloadIcon, RotateCcwIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";
import { Checkbox } from "@amibeingpwned/ui/checkbox";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { WorkspaceAction } from "../../lib/messages";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { WorkspaceDraft } from "../../lib/workspace-draft";
import { savePreferences } from "../../lib/storage/preferences";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { KeySelector } from "./KeySelector";
import { useWorkspaceOperations } from "./useWorkspaceOperations";
import { useWorkspaceState } from "./useWorkspaceState";
import { WorkspaceInput } from "./WorkspaceInput";
import { WorkspaceResults } from "./WorkspaceResults";

interface WorkspaceViewProps {
  myKeys: ProtectedKeyBlob[];
  contacts: PublicContactKey[];
  crxSigningEnabled?: boolean;
  crxKeys?: CrxSigningKeyBlob[];
  getKeyHandle: (keyId: string) => number | null;
  onUnlockWithPassword: (
    blob: ProtectedKeyBlob,
    password: string,
  ) => Promise<boolean>;
  onUnlockWithPasskey: (
    blob: ProtectedKeyBlob,
  ) => Promise<boolean | "cancelled">;
  pendingAction?: { action: WorkspaceAction; text: string } | null;
  onClearPending?: () => void;
  encryptToKeyId?: string | null;
  onClearEncryptTo?: () => void;
  onNavigateToKeys?: (importPrefill?: string) => void;
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
  crxSigningEnabled,
  crxKeys,
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
    crxKeys,
    crxSigningEnabled,
    pendingAction,
    onClearPending,
    allPublicKeys,
    encryptToKeyId,
    onClearEncryptTo,
    restoreDraft,
    onDraftRestored,
    onDraftChange,
  });

  const ops = useWorkspaceOperations({
    s,
    myKeys,
    contacts,
    crxKeys,
    crxSigningEnabled,
    allPublicKeys,
    getKeyHandle,
    onUnlockWithPassword,
    onUnlockWithPasskey,
    autoDownloadFiles,
    autoDownloadText,
    onOperationComplete,
  });

  const needsRecipient = s.mode === "encrypt";
  const needsPrivateKey = s.mode === "decrypt" || s.mode === "sign";
  const hasInput = s.files.length > 0 || s.input.length > 0;
  const canCrxSign = !!crxSigningEnabled && (crxKeys?.length ?? 0) > 0;
  const singleCrxFile =
    s.files.length === 1 && /\.crx$/i.test(s.files[0].name);
  // CRX signs a packed extension: only offer it for a .zip (or multiple
  // files we'll zip), never a random dropped file.
  const zipLikeSignInput =
    s.mode === "sign" &&
    (s.files.length > 1 ||
      (s.files.length === 1 && /\.zip$/i.test(s.files[0].name)));
  const showCrxSign = canCrxSign && zipLikeSignInput && !s.operationDone;
  // A dropped .crx: verifying its signature is the only sensible action, so
  // it becomes the primary button (no confusing encrypt/sign button).
  const showCrxVerify = !!crxSigningEnabled && singleCrxFile;

  // After decrypting to readable text, give the plaintext the whole panel with
  // a Back button, instead of cramming it into a small fixed-height preview.
  const showFullOutput =
    s.operationDone && s.mode === "decrypt" && s.output.length > 0;

  if (showFullOutput) {
    return (
      <div className="flex h-full flex-col gap-3">
        <div className="flex items-center">
          <Button
            variant="ghost"
            size="sm"
            className="text-muted-foreground hover:text-foreground -ml-2 h-8 gap-1 px-2"
            onClick={s.resetOutput}
          >
            <ArrowLeftIcon className="h-4 w-4" />
            Back
          </Button>
        </div>
        <WorkspaceResults
          error={s.error}
          output={s.output}
          binaryOutput={s.binaryOutput}
          fileResults={s.fileResults}
          fileName={ops.outputFileName()}
          operationDone={s.operationDone}
          statusText={s.statusText ?? undefined}
          verifiedSigner={s.verifiedSigner}
          signatureTone={s.signatureTone}
          fullHeight
        />
        <div className="flex gap-2">
          <Button
            className="flex-1"
            onClick={() => ops.triggerDownload()}
            disabled={s.loading}
          >
            <span className="flex items-center gap-2">
              <DownloadIcon className="h-4 w-4" />
              Download
            </span>
          </Button>
          <Button
            variant="outline"
            size="icon"
            onClick={s.resetAll}
            title="Clear input and output"
            aria-label="Clear input and output"
          >
            <RotateCcwIcon className="h-4 w-4" />
          </Button>
        </div>
      </div>
    );
  }

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
        privateKeyDetected={s.privateKeyDetected}
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
            onSelect={ops.selectPrivateKey}
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
                onSelect={ops.selectPrivateKey}
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
                if (e.key === "Enter") void ops.handlePasswordSubmit();
              }}
              className={`${INPUT_CLASS} h-9 flex-1 py-0`}
              autoFocus
            />
            <Button
              size="sm"
              className="h-9 shrink-0"
              onClick={ops.handlePasswordSubmit}
              disabled={s.loading}
            >
              {s.loading
                ? "..."
                : s.pendingCrxSign
                  ? "Sign"
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
          fileName={ops.outputFileName()}
          operationDone={s.operationDone}
          statusText={s.statusText ?? undefined}
          verifiedSigner={s.verifiedSigner}
          signatureTone={s.signatureTone}
        />

        {!s.needsPassword && (
          <div className="space-y-2">
            {showCrxSign && crxKeys && crxKeys.length > 1 && (
              <div>
                <label
                  htmlFor="crx-signing-key"
                  className="text-muted-foreground mb-1 block text-xs font-medium"
                >
                  CRX signing key
                </label>
                <select
                  id="crx-signing-key"
                  value={s.selectedCrxKeyId ?? ""}
                  onChange={(e) => s.setSelectedCrxKeyId(e.target.value)}
                  className="border-border bg-background focus:ring-ring w-full rounded-md border px-2 py-1.5 text-sm focus:ring-2 focus:outline-none"
                >
                  {crxKeys.map((k) => (
                    <option key={k.extensionId} value={k.extensionId}>
                      {k.label ?? k.extensionId}
                    </option>
                  ))}
                </select>
              </div>
            )}

            {showCrxVerify ? (
              <Button
                className="w-full"
                variant={s.operationDone ? "outline" : "default"}
                onClick={s.operationDone ? s.resetAll : ops.verifyCrxInput}
                disabled={s.loading}
              >
                {s.loading
                  ? "Verifying..."
                  : s.operationDone
                    ? "Reset"
                    : "Verify signature"}
              </Button>
            ) : showCrxSign ? (
              <div className="flex gap-2">
                <Button
                  className="flex-1"
                  onClick={ops.execute}
                  disabled={s.loading}
                >
                  {s.loading ? "Processing..." : "Sign (PGP)"}
                </Button>
                <Button
                  className="flex-1"
                  onClick={ops.executeCrxSign}
                  disabled={s.loading}
                >
                  {s.loading ? "Processing..." : "Sign for Web Store"}
                </Button>
              </div>
            ) : (
              <div className="flex gap-2">
                <Button
                  className="flex-1 capitalize"
                  onClick={
                    s.operationDone
                      ? s.mode === "verify"
                        ? s.resetAll
                        : () => ops.triggerDownload()
                      : ops.execute
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
        )}
      </div>
    </div>
  );
}
