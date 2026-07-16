import { useEffect, useRef, useState } from "react";
import {
  ArrowLeftIcon,
  CheckIcon,
  ClipboardIcon,
  DownloadIcon,
  RotateCcwIcon,
} from "lucide-react";

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";
import { Button } from "@amibeingpwned/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@amibeingpwned/ui/select";

import type { WorkspaceOpsBridge } from "../../hooks/useActionContext";
import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { RemedyAction } from "../../lib/errors/present";
import type { WorkspaceAction } from "../../lib/messages";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { WorkspaceDraft } from "../../lib/workspace-draft";
import type { WorkspaceIntake } from "./useWorkspaceState";
import { useCopyToClipboard } from "../../hooks/useCopyToClipboard";
import { useDelayedFlag } from "../../hooks/useDelayedFlag";
import { useShortcut } from "../../hooks/useShortcut";
import {
  COPY_SHORTCUT,
  DOWNLOAD_SHORTCUT,
} from "../../lib/actions/definitions";
import { requestUnlimitedHistoryStorage } from "../../lib/storage/history";
import { savePreferences } from "../../lib/storage/preferences";
import { toast } from "../../lib/toast";
import { saveCrxViaPrompt } from "../../lib/utils/download";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { hasOpenSlideOver } from "../shared/SlideOver";
import { ToggleBadge } from "../shared/ToggleBadge";
import { HistoryButton } from "./HistoryPage";
import { KeySelector } from "./KeySelector";
import { RecipientPicker } from "./RecipientPicker";
import { useWorkspaceOperations } from "./useWorkspaceOperations";
import { useWorkspaceState } from "./useWorkspaceState";
import { WorkspaceInput } from "./WorkspaceInput";
import { WorkspaceResults } from "./WorkspaceResults";

/** mod+Enter mirrors the main action button (Encrypt/Decrypt/Sign/...). */
const RUN_SHORTCUT: ShortcutSpec = { mod: true, key: "Enter" };

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
  /** Bumped when preference-backed toggles change outside this view
   *  (e.g. a security preset applied in Settings); re-reads prefs. */
  prefsVersion?: number;
  /** The user's configured default key: preferred when auto-selecting
   *  a private key and as the encrypt-to-self key. */
  defaultKeyId?: string | null;
  /** When true (never-cache mode), history is disabled and wiped, so
   *  the "Save to history" checkbox and History button are hidden. */
  neverCacheKeys?: boolean;
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
  prefsVersion,
  defaultKeyId,
  neverCacheKeys,
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
    prefsVersion,
    defaultKeyId,
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
    defaultKeyId,
  });

  // Deferred loading labels: buttons disable immediately off s.loading,
  // but the label swap waits so sub-150ms crypto ops never flash
  // "Processing..." for operations that finish near-instantly.
  const showLoadingLabel = useDelayedFlag(s.loading);

  const needsRecipient = s.mode === "encrypt";
  const needsPrivateKey = s.mode === "decrypt" || s.mode === "sign";
  const hasInput = s.files.length > 0 || s.input.length > 0;

  // Warn BEFORE encrypting when the user won't be able to decrypt the
  // result: encrypt-to-self is off and no selected recipient is one of
  // their own keys (mirrors buildEncryptRecipients' selfExcluded).
  const selfDecryptRisk =
    s.mode === "encrypt" &&
    myKeys.length > 0 &&
    !s.encryptToSelf &&
    s.selectedRecipientIds.length > 0 &&
    !s.selectedRecipientIds.some((id) => myKeys.some((k) => k.keyId === id));

  // Copy the armored output straight from the bottom action bar (the compact
  // preview no longer carries its own copy button). Binary/file output has no
  // text to copy, so the Copy half is only shown when `s.output` is present.
  const [copied, setCopied] = useState(false);
  const copyTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const { copy } = useCopyToClipboard();
  const handleCopy = async () => {
    // No label: the button's own 2s check is the success feedback. A
    // rejected write (panel not focused) surfaces as an error toast.
    if (!(await copy(s.output))) return;
    setCopied(true);
    clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopied(false), 2000);
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

  // Snapshot of the box at the moment a double-Escape cleared it, so the
  // clear is undoable (toast Undo, or mod+z while the box is still empty
  // -- once the user types again, native undo owns mod+z).
  const [clearSnapshot, setClearSnapshot] = useState<{
    input: string;
    files: File[];
  } | null>(null);
  const lastEscapeAt = useRef(0);

  const restoreCleared = () => {
    setClearSnapshot((snap) => {
      if (snap) {
        s.setInput(snap.input);
        s.setFiles(snap.files);
      }
      return null;
    });
  };
  const clearBoxUndoable = () => {
    if (s.input.length === 0 && s.files.length === 0) return;
    setClearSnapshot({ input: s.input, files: s.files });
    s.resetAll();
    toast.message("Workspace cleared", {
      id: "workspace-text-cleared",
      duration: 4000,
      action: { label: "Undo", onClick: restoreCleared },
    });
    // A cleared box invites retyping: focus it (next tick -- resetAll may
    // have just remounted the textarea in place of the file list).
    setTimeout(() => document.getElementById("pgp-input")?.focus(), 0);
  };
  useShortcut({ mod: true, key: "z" }, restoreCleared, {
    enabled: clearSnapshot !== null && s.input.length === 0,
  });

  // Escape layers for the workspace itself (subpages and the palette
  // own their Escapes and never let them reach this listener): in the
  // full-output view a single press mirrors Back; in the form view a
  // quick double-tap clears the box, undoably.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key !== "Escape" || e.defaultPrevented) return;
      if (hasOpenSlideOver()) return;
      // Escapes that are closing a dropdown (mode select, pickers)
      // belong to the dropdown, not to us.
      const target = e.target as HTMLElement | null;
      if (target?.closest("[data-radix-popper-content-wrapper]")) return;
      if (showFullOutput) {
        // The back-press never counts toward the clear double-tap.
        lastEscapeAt.current = 0;
        s.resetOutput();
        return;
      }
      const now = Date.now();
      if (now - lastEscapeAt.current < 350) {
        lastEscapeAt.current = 0;
        clearBoxUndoable();
      } else {
        lastEscapeAt.current = now;
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  });

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

  // The preference checkboxes' handlers, extracted so the palette
  // toggles (via the ops bridge below) run the EXACT same code path:
  // persistence, stale-output reset, and the history storage request.
  const setEncryptToSelfPref = (checked: boolean) => {
    s.setEncryptToSelf(checked);
    s.resetOutput();
    void savePreferences({ encryptToSelf: checked });
  };
  const setAlsoSignPref = (checked: boolean) => {
    s.setAlsoSign(checked);
    s.resetOutput();
    void savePreferences({ signWhenEncrypting: checked });
  };
  const setSaveToHistoryPref = (checked: boolean) => {
    s.setSaveToHistory(checked);
    void savePreferences({ historyEnabled: checked });
    // Enabling is a user gesture: ask for unlimitedStorage so history
    // gets the generous budget. A denial is fine -- history still
    // works within the default budget.
    if (checked) void requestUnlimitedHistoryStorage();
  };

  // mod+Enter (run) and mod+shift+C (copy) are dispatched through the
  // action registry (lib/actions), which reads the state slice pushed
  // up here. Ops close over fresh state via a ref; the snapshot effect
  // below re-pushes only when a palette-readable value changes.
  const hasOutput = s.operationDone && s.output.length > 0 && !s.loading;
  // Broader than hasOutput: file/binary results have no copyable text
  // but do download. Verify is excluded -- its "result" is a verdict,
  // not an artifact (the UI shows no Download button there either).
  const hasDownload =
    s.operationDone &&
    !s.loading &&
    s.mode !== "verify" &&
    (s.fileResults.length > 0 || !!s.binaryOutput || s.output.length > 0);
  // Mirrors the main button's disabled logic, incl. the encrypt
  // needs-a-recipient gate (the palette shows the reason as a toast).
  const canRun =
    mainActionShown &&
    !s.loading &&
    !(s.mode === "encrypt" && s.selectedRecipientIds.length === 0);
  const paletteRef = useRef({
    s,
    canRun,
    hasOutput,
    hasDownload,
    handleCopy,
    ops,
    setEncryptToSelfPref,
    setAlsoSignPref,
    setSaveToHistoryPref,
  });
  useEffect(() => {
    paletteRef.current = {
      s,
      canRun,
      hasOutput,
      hasDownload,
      handleCopy,
      ops,
      setEncryptToSelfPref,
      setAlsoSignPref,
      setSaveToHistoryPref,
    };
  });
  useEffect(() => {
    onPaletteOps?.({
      mode: s.mode,
      hasInput,
      hasRecipients: s.selectedRecipientIds.length > 0,
      hasOutput,
      hasDownload,
      historyEnabled: s.saveToHistory,
      encryptToSelf: s.encryptToSelf,
      alsoSign: s.alsoSign,
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
      downloadOutput: () => {
        const p = paletteRef.current;
        if (p.hasDownload) p.ops.triggerDownload();
      },
      toggleEncryptToSelf: () => {
        const p = paletteRef.current;
        p.setEncryptToSelfPref(!p.s.encryptToSelf);
      },
      toggleAlsoSign: () => {
        const p = paletteRef.current;
        p.setAlsoSignPref(!p.s.alsoSign);
      },
      toggleSaveToHistory: () => {
        const p = paletteRef.current;
        p.setSaveToHistoryPref(!p.s.saveToHistory);
      },
    });
  }, [
    onPaletteOps,
    s.mode,
    hasInput,
    s.selectedRecipientIds,
    hasOutput,
    hasDownload,
    s.saveToHistory,
    s.encryptToSelf,
    s.alsoSign,
  ]);
  useEffect(() => () => onPaletteOps?.(null), [onPaletteOps]);

  // Remedy actions this view can actually perform, mapped to existing
  // handlers. An action with no handler here (or whose handler isn't
  // available right now) renders message-only in WorkspaceResults: no
  // dead button. "check-recipient" stays message-only because the
  // recipient picker has no cheap imperative open.
  const passwordInputRef = useRef<HTMLInputElement>(null);
  const remedyAction = s.error?.remedy?.action;
  const remedyHandled =
    remedyAction === "retry" ||
    (remedyAction === "import-key" && !!onNavigateToKeys) ||
    (remedyAction === "unlock" && s.needsPassword);
  const handleRemedy = remedyHandled
    ? (action: RemedyAction) => {
        switch (action) {
          case "import-key":
            onNavigateToKeys?.();
            break;
          case "retry":
            void ops.execute();
            break;
          case "unlock":
            passwordInputRef.current?.focus();
            break;
          case "check-recipient":
            break;
        }
      }
    : undefined;

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
            {/* Icon + keycaps only: the labels crowded the half-width
                buttons, and the icons with shortcut chips say it all.
                aria-label/title keep the names for AT and hover. */}
            <Button
              className="flex-1"
              onClick={() => ops.triggerDownload()}
              disabled={s.loading}
              shortcut={DOWNLOAD_SHORTCUT}
              aria-label="Download"
              title="Download"
            >
              <DownloadIcon className="h-4 w-4" />
            </Button>
            <Button
              variant="outline"
              className="flex-1"
              onClick={handleCopy}
              disabled={s.loading}
              shortcut={COPY_SHORTCUT}
              aria-label={copied ? "Copied" : "Copy"}
              title="Copy"
            >
              {copied ? (
                <CheckIcon className="h-4 w-4 text-green-400" />
              ) : (
                <ClipboardIcon className="h-4 w-4" />
              )}
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
          <RecipientPicker
            label="Recipients"
            // Only offer contacts you can actually encrypt to. Sign-only
            // keys are valid contacts (for verification) but have no
            // encryption key. Legacy records (undefined) are assumed
            // encryptable until the contacts backfill fills the flag in.
            contacts={contacts.filter((c) => c.usableForEncryption !== false)}
            myKeys={myKeys}
            selectedKeyIds={s.selectedRecipientIds}
            recentKeyIds={s.recentRecipients}
            // Changing the recipient set (adding OR removing) invalidates
            // any completed ciphertext — clear it so the user re-encrypts
            // to the new set rather than downloading stale output.
            onChange={(ids) => {
              s.setSelectedRecipientIds(ids);
              s.resetOutput();
            }}
            emptyText="No contacts yet"
            emptyAction={onNavigateToKeys}
            emptyActionLabel="Add a contact"
          />
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
            emptyText="No keys yet"
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
            <div className="flex flex-wrap items-center gap-2">
              {myKeys.length > 0 && (
                <ToggleBadge
                  pressed={s.encryptToSelf}
                  onPressedChange={setEncryptToSelfPref}
                >
                  Also encrypt to me
                </ToggleBadge>
              )}
              {myKeys.length > 0 && (
                <ToggleBadge
                  pressed={s.alsoSign}
                  onPressedChange={setAlsoSignPref}
                >
                  Sign
                </ToggleBadge>
              )}
              {s.files.length > 1 && (
                <ToggleBadge
                  pressed={s.zipFiles}
                  onPressedChange={(v) => {
                    s.setZipFiles(v);
                    s.resetOutput();
                  }}
                >
                  Zip files
                </ToggleBadge>
              )}
              {/* Never-cache means no history, ever: the toggle and the
                  viewer disappear rather than offering a dead switch. */}
              {!neverCacheKeys && (
                <>
                  <ToggleBadge
                    pressed={s.saveToHistory}
                    onPressedChange={setSaveToHistoryPref}
                  >
                    Save to history
                  </ToggleBadge>
                  <HistoryButton enabled={s.saveToHistory} />
                </>
              )}
            </div>
            {selfDecryptRisk && (
              <p className="text-muted-foreground text-xs">
                You won't be able to decrypt the result
              </p>
            )}
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
              ref={passwordInputRef}
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
              {showLoadingLabel
                ? "Unlocking..."
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
          onRemedy={handleRemedy}
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
                {showLoadingLabel
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
                {showLoadingLabel ? "Processing..." : "Sign for Web Store"}
              </Button>
            ) : (
              <div className="flex gap-2">
                {s.operationDone && s.mode !== "verify" ? (
                  // Completed encrypt/sign: the result is ready to take away.
                  // Download is primary; Copy rides alongside for text output.
                  <div className="flex flex-1 gap-2">
                    {/* Icon + keycaps only (labels crowded the buttons);
                        aria-label/title keep the names for AT and hover. */}
                    <Button
                      className="flex-1"
                      onClick={() => ops.triggerDownload()}
                      disabled={s.loading}
                      shortcut={DOWNLOAD_SHORTCUT}
                      aria-label="Download"
                      title="Download"
                    >
                      <DownloadIcon className="h-4 w-4" />
                    </Button>
                    {s.output && (
                      <Button
                        variant="outline"
                        className="flex-1"
                        onClick={handleCopy}
                        disabled={s.loading}
                        shortcut={COPY_SHORTCUT}
                        aria-label={copied ? "Copied" : "Copy"}
                        title="Copy"
                      >
                        {copied ? (
                          <CheckIcon className="h-4 w-4 text-green-400" />
                        ) : (
                          <ClipboardIcon className="h-4 w-4" />
                        )}
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
                    disabled={
                      s.loading ||
                      !hasInput ||
                      (s.mode === "encrypt" &&
                        s.selectedRecipientIds.length === 0)
                    }
                    title={
                      s.mode === "encrypt" &&
                      s.selectedRecipientIds.length === 0
                        ? "Select at least one recipient"
                        : undefined
                    }
                    shortcut={RUN_SHORTCUT}
                  >
                    {showLoadingLabel
                      ? "Processing..."
                      : s.operationDone && s.mode === "verify"
                        ? "Reset"
                        : s.mode}
                  </Button>
                )}
                {/* Anything clearable (pasted input lingering after a nav
                    round-trip, or a completed op) gets the clear button;
                    verify-done is excluded because its main button IS Reset. */}
                {(hasInput || s.operationDone) &&
                  !(s.operationDone && s.mode === "verify") && (
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
