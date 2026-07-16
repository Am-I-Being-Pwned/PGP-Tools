import { useEffect, useRef, useState } from "react";
import {
  ArrowLeftIcon,
  CheckIcon,
  ClipboardIcon,
  DownloadIcon,
  RotateCcwIcon,
  TriangleAlertIcon,
} from "lucide-react";

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";
import { Alert, AlertDescription } from "@amibeingpwned/ui/alert";
import { Button } from "@amibeingpwned/ui/button";
import { Checkbox } from "@amibeingpwned/ui/checkbox";
import {
  ariaKeyShortcuts,
  formatShortcutTitle,
  isMacPlatform,
} from "@amibeingpwned/ui/kbd-helpers";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@amibeingpwned/ui/select";

import type { WorkspaceOpsBridge } from "../../hooks/useActionContext";
import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { WorkspaceAction } from "../../lib/messages";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { WorkspaceDraft } from "../../lib/workspace-draft";
import type { WorkspaceIntake } from "./useWorkspaceState";
import { requestUnlimitedHistoryStorage } from "../../lib/storage/history";
import { savePreferences } from "../../lib/storage/preferences";
import { saveCrxViaPrompt } from "../../lib/utils/download";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { HistoryButton } from "./HistoryPage";
import { KeySelector } from "./KeySelector";
import { useWorkspaceOperations } from "./useWorkspaceOperations";
import { useWorkspaceState } from "./useWorkspaceState";
import { WorkspaceInput } from "./WorkspaceInput";
import { WorkspaceResults } from "./WorkspaceResults";

/** mod+Enter mirrors the main action button (Encrypt/Decrypt/Sign/...). */
const RUN_SHORTCUT: ShortcutSpec = { mod: true, key: "Enter" };
/** mod+shift+C copies completed text output. */
const COPY_SHORTCUT: ShortcutSpec = { mod: true, shift: true, key: "c" };

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
  /** A drop routed to the workspace by the global dropzone. */
  intake?: WorkspaceIntake | null;
  onIntakeConsumed?: () => void;
  /** Pushes the palette-facing state/ops slice up on every change. */
  onPaletteOps?: (bridge: WorkspaceOpsBridge | null) => void;
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
  intake,
  onIntakeConsumed,
  onPaletteOps,
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
    intake,
    onIntakeConsumed,
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

  // Copy the armored output straight from the bottom action bar (the compact
  // preview no longer carries its own copy button). Binary/file output has no
  // text to copy, so the Copy half is only shown when `s.output` is present.
  const [copied, setCopied] = useState(false);
  const copyTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(s.output);
      setCopied(true);
      clearTimeout(copyTimer.current);
      copyTimer.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard may reject if the panel isn't focused
    }
  };
  const canCrxSign = !!crxSigningEnabled && (crxKeys?.length ?? 0) > 0;
  const singleCrxFile = s.files.length === 1 && /\.crx$/i.test(s.files[0].name);
  // CRX signs a packed extension: offer it only for a single .zip that
  // actually contains a manifest.json (verified async in state), never for
  // arbitrary files. PGP signing stays available via the "Sign as" toggle.
  const crxSignAvailable =
    canCrxSign && s.mode === "sign" && s.isExtensionZip && !s.operationDone;
  const showCrxSign = crxSignAvailable && s.signKind === "crx";
  // A dropped .crx in verify mode: CRX signature verification replaces the
  // (useless there) PGP verify. Other modes keep their normal actions — a
  // .crx can still be encrypted or PGP-signed like any other file.
  const showCrxVerify =
    !!crxSigningEnabled && s.mode === "verify" && singleCrxFile;
  // A completed CRX sign is the only op that yields a single `.crx` file
  // result; it auto-saves via the Save-As prompt (with a manual Save button
  // as a fallback) instead of the usual anchor download.
  const crxResult =
    s.operationDone &&
    s.fileResults.length === 1 &&
    /\.crx$/i.test(s.fileResults[0].name)
      ? s.fileResults[0]
      : null;
  const crxFilename = crxResult?.name ?? "";

  // Save the signed CRX under its real `.crx` name via a "Save As" download.
  // A Save-As download sets Chrome's TARGET_DISPOSITION_PROMPT, the one case
  // where Chrome does NOT route a CRX (identified by its Cr24 magic) to the
  // extension installer -- so it lands on disk as a plain file, no rename, no
  // install. See saveCrxViaPrompt for the source-level reasoning.
  const handleSaveCrx = async () => {
    if (!crxResult) return;
    const result = await saveCrxViaPrompt(crxResult.data, crxFilename);
    if (result === "saved") {
      s.setStatusText(`Saved ${crxFilename}.`);
    } else if (result === "cancelled") {
      s.setStatusText(null);
    } else {
      // Permission refused / unsupported / write blocked. The Save button
      // stays on screen so the user can retry from a fresh user gesture (the
      // first-time `downloads` permission grant needs one).
      s.setStatusText("Couldn't save automatically - hit Save to try again.");
    }
  };

  // Auto-save the moment a signed CRX is ready, so the user doesn't have to
  // hit Save. Keyed on the result's identity via a ref so it fires exactly
  // once per sign (not on every re-render). If the first-ever save needs the
  // `downloads` permission it may require a user gesture the async sign has
  // already spent -- the Save button below covers that.
  const autoSavedRef = useRef<Uint8Array | null>(null);
  useEffect(() => {
    if (!crxResult) {
      autoSavedRef.current = null;
      return;
    }
    if (autoSavedRef.current === crxResult.data) return;
    autoSavedRef.current = crxResult.data;
    void handleSaveCrx();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [crxResult]);

  // After decrypting to readable text, give the plaintext the whole panel with
  // a Back button, instead of cramming it into a small fixed-height preview.
  const showFullOutput =
    s.operationDone && s.mode === "decrypt" && s.output.length > 0;

  // Whether the main action button is rendered (the trailing branch of
  // the action bar). The Run action only fires while it would be
  // enabled; in verify-done state it resets, like the button.
  const mainActionShown =
    !showFullOutput &&
    !s.needsPassword &&
    !crxResult &&
    !showCrxVerify &&
    !showCrxSign &&
    !(s.operationDone && s.mode !== "verify");

  // mod+Enter (run) and mod+shift+C (copy) are dispatched through the
  // action registry (lib/actions), which reads the state slice pushed
  // up here. Ops close over fresh state via a ref; the snapshot effect
  // below re-pushes only when a palette-readable value changes.
  const hasOutput = s.operationDone && s.output.length > 0 && !s.loading;
  const canRun = mainActionShown && !s.loading;
  const paletteRef = useRef({ s, canRun, hasOutput, handleCopy, ops });
  useEffect(() => {
    paletteRef.current = { s, canRun, hasOutput, handleCopy, ops };
  });
  useEffect(() => {
    onPaletteOps?.({
      mode: s.mode,
      hasInput,
      hasOutput,
      historyEnabled: s.saveToHistory,
      // Mirrors the mode Select: a completed operation resets fully,
      // otherwise only the (now stale) output is cleared.
      setMode: (m) => {
        const p = paletteRef.current;
        p.s.setMode(m);
        if (p.s.operationDone) p.s.resetAll();
        else p.s.resetOutput();
      },
      // In verify-done state Run resets, like the button it mirrors.
      execute: () => {
        const p = paletteRef.current;
        if (!p.canRun) return;
        if (p.s.operationDone && p.s.mode === "verify") p.s.resetAll();
        else void p.ops.execute();
      },
      clearInput: () => paletteRef.current.s.resetAll(),
      copyOutput: () => {
        if (paletteRef.current.hasOutput) void paletteRef.current.handleCopy();
      },
    });
  }, [onPaletteOps, s.mode, hasInput, hasOutput, s.saveToHistory]);
  useEffect(() => () => onPaletteOps?.(null), [onPaletteOps]);

  const copyTitle = `Copy (${formatShortcutTitle(COPY_SHORTCUT, isMacPlatform())})`;
  const copyAria = ariaKeyShortcuts(COPY_SHORTCUT, isMacPlatform());

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
          <div className="flex flex-1 gap-2">
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
              className="flex-1"
              onClick={handleCopy}
              disabled={s.loading}
              title={copyTitle}
              aria-keyshortcuts={copyAria}
            >
              <span className="flex items-center gap-2">
                {copied ? (
                  <CheckIcon className="h-4 w-4 text-green-400" />
                ) : (
                  <ClipboardIcon className="h-4 w-4" />
                )}
                {copied ? "Copied" : "Copy"}
              </span>
            </Button>
          </div>
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
            // Only offer contacts you can actually encrypt to. Sign-only
            // keys are valid contacts (for verification) but have no
            // encryption key. Legacy records (undefined) are assumed
            // encryptable until the contacts backfill fills the flag in.
            contacts={contacts.filter((c) => c.usableForEncryption !== false)}
            myKeys={myKeys}
            selectedKeyId={s.selectedRecipientId}
            // Changing the recipient invalidates any completed ciphertext —
            // clear it so the user can re-encrypt to the new key rather than
            // being stuck downloading output encrypted to the wrong one.
            onSelect={(id) => {
              if (id === s.selectedRecipientId) return;
              s.setSelectedRecipientId(id);
              s.resetOutput();
            }}
            emptyText="No contacts yet."
            emptyAction={onNavigateToKeys}
            emptyActionLabel="Add a contact"
          />
        )}

        {needsRecipient && myKeys.length > 0 && (
          <label className="flex items-center gap-2">
            <Checkbox
              checked={s.encryptToSelf}
              onCheckedChange={(v) => {
                const checked = v === true;
                s.setEncryptToSelf(checked);
                s.resetOutput();
                void savePreferences({ encryptToSelf: checked });
              }}
            />
            <span className="text-sm">Also encrypt to me</span>
          </label>
        )}

        {/* An extension zip can carry two signature kinds; let the user pick
            (defaults to CRX, the overwhelmingly likely intent) instead of
            hijacking the PGP sign flow. */}
        {crxSignAvailable && (
          <div className="flex gap-2">
            <Button
              variant={s.signKind === "crx" ? "default" : "outline"}
              size="sm"
              className="flex-1"
              onClick={() => s.setSignKind("crx")}
            >
              Chrome extension (.crx)
            </Button>
            <Button
              variant={s.signKind === "pgp" ? "default" : "outline"}
              size="sm"
              className="flex-1"
              onClick={() => s.setSignKind("pgp")}
            >
              PGP signature
            </Button>
          </div>
        )}

        {needsPrivateKey && !showCrxSign && (
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

        {/* Signing an extension package: pick a CRX key, not a PGP key. */}
        {showCrxSign && crxKeys && crxKeys.length > 0 && (
          <div>
            <label className="text-muted-foreground mb-1 block text-xs font-medium">
              Sign with
            </label>
            <Select
              value={s.selectedCrxKeyId ?? ""}
              onValueChange={(v) => s.setSelectedCrxKeyId(v)}
            >
              <SelectTrigger className="w-full">
                <SelectValue placeholder="Select a signing key" />
              </SelectTrigger>
              <SelectContent>
                {crxKeys.map((k) => (
                  <SelectItem key={k.extensionId} value={k.extensionId}>
                    {k.label ?? k.extensionId}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
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
              <label className="flex items-center gap-2">
                <Checkbox
                  checked={s.saveToHistory}
                  onCheckedChange={(v) => {
                    const checked = v === true;
                    s.setSaveToHistory(checked);
                    void savePreferences({ historyEnabled: checked });
                    // Enabling is a user gesture: ask for unlimitedStorage
                    // so history gets the generous budget. A denial is fine
                    // -- history still works within the default budget.
                    if (checked) void requestUnlimitedHistoryStorage();
                  }}
                />
                <span className="text-sm">Save to history</span>
              </label>
              <HistoryButton enabled={s.saveToHistory} />
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

        {s.selfDecryptWarning && (
          <Alert className="border-amber-500/40 bg-amber-500/10 text-amber-400">
            <TriangleAlertIcon className="h-4 w-4" />
            <AlertDescription className="text-xs text-amber-400/90">
              {s.selfDecryptWarning}
            </AlertDescription>
          </Alert>
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
          // Once an encrypt/sign has produced output, hold the slot open so
          // clearing it (e.g. on a recipient change) doesn't jump the layout.
          reserve={
            s.hasProducedOutput && (s.mode === "encrypt" || s.mode === "sign")
          }
        />

        {!s.needsPassword && (
          <div className="space-y-2">
            {crxResult ? (
              <div className="flex gap-2">
                <Button className="flex-1" onClick={() => void handleSaveCrx()}>
                  <span className="flex items-center gap-2">
                    <DownloadIcon className="h-4 w-4" />
                    Save {crxFilename}
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
            ) : showCrxVerify ? (
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
              <Button
                className="w-full"
                onClick={ops.executeCrxSign}
                disabled={s.loading}
              >
                {s.loading ? "Processing..." : "Sign for Web Store"}
              </Button>
            ) : (
              <div className="flex gap-2">
                {s.operationDone && s.mode !== "verify" ? (
                  // Completed encrypt/sign: the result is ready to take away.
                  // Download is primary; Copy rides alongside for text output.
                  <div className="flex flex-1 gap-2">
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
                    {s.output && (
                      <Button
                        variant="outline"
                        className="flex-1"
                        onClick={handleCopy}
                        disabled={s.loading}
                        title={copyTitle}
                        aria-keyshortcuts={copyAria}
                      >
                        <span className="flex items-center gap-2">
                          {copied ? (
                            <CheckIcon className="h-4 w-4 text-green-400" />
                          ) : (
                            <ClipboardIcon className="h-4 w-4" />
                          )}
                          {copied ? "Copied" : "Copy"}
                        </span>
                      </Button>
                    )}
                  </div>
                ) : (
                  <Button
                    className="flex-1 capitalize"
                    onClick={
                      s.operationDone && s.mode === "verify"
                        ? s.resetAll
                        : ops.execute
                    }
                    disabled={s.loading || !hasInput}
                    shortcut={RUN_SHORTCUT}
                  >
                    {s.loading
                      ? "Processing..."
                      : s.operationDone && s.mode === "verify"
                        ? "Reset"
                        : s.mode}
                  </Button>
                )}
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
