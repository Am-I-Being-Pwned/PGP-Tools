import {
  use,
  useCallback,
  useEffect,
  useEffectEvent,
  useRef,
  useState,
} from "react";
import {
  ArrowLeftIcon,
  DownloadIcon,
  ReplyIcon,
  RotateCcwIcon,
} from "lucide-react";

import {
  ariaKeyShortcuts,
  Block,
  Button,
  cn,
  isMacPlatform,
  OptionBar,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  type ShortcutSpec,
} from "@amibeingpwned/ui";

import { KeyAvatar } from "~/components/shared/KeyAvatar";
import { ToggleBadge } from "~/components/shared/ToggleBadge";
import {
  WorkspaceBridgeContext,
  type WorkspaceCommands,
  type WorkspaceSnapshot,
} from "~/hooks/useActionContext";
import { useCopyToClipboard } from "~/hooks/useCopyToClipboard";
import { useDelayedFlag } from "~/hooks/useDelayedFlag";
import { useNav } from "~/hooks/useNav";
import { savePreference, usePreferences } from "~/hooks/usePreferences";
import { useShortcut } from "~/hooks/useShortcut";
import { useVault } from "~/hooks/useVault";
import { REPLY_SHORTCUT } from "~/lib/actions/definitions";
import { recoverArmorIfNeeded } from "~/lib/armor-recovery";
import {
  buildEncryptRecipients,
  resolveSelectedRecipients,
  sshPasswordReason,
  toSelectedRecipient,
} from "~/lib/encrypt-recipients";
import type { RemedyAction } from "~/lib/errors/present";
import { t } from "~/lib/i18n";
import type { WorkspaceAction } from "~/lib/messages";
import type { ReaderSigner } from "~/lib/reader-protocol";
import { requestUnlimitedHistoryStorage } from "~/lib/storage/history";
import { isPgpRecord, isSshRecord } from "~/lib/storage/key-kind";
import { toast } from "~/lib/toast";
import { saveCrxViaPrompt } from "~/lib/utils/download";
import { displayUserId, formatKeyDisplayName } from "~/lib/utils/key-naming";
import { INPUT_CLASS } from "~/lib/utils/styles";
import type { WorkspaceDraftSource } from "~/lib/workspace-draft";
import { withoutHiddenCharacters } from "./hidden-characters";
import { KeySelector } from "./KeySelector";
import { MessagePasswordPage } from "./MessagePasswordPage";
import { selectionEngine } from "./recipient-engine";
import { RecipientPicker } from "./RecipientPicker";
import { ResultActions } from "./ResultActions";
import { displayOnlySignerCard, signerCardState } from "./signer-card";
import {
  HoverLabel,
  TranslateToggle,
  TranslationNote,
} from "./TranslationPanel";
import { useAutoRun } from "./useAutoRun";
import { useWorkspace, type WorkspaceIntake } from "./useWorkspace";
import { useWorkspaceKeyboard } from "./useWorkspaceKeyboard";
import { useWorkspaceTranslation } from "./useWorkspaceTranslation";
import type { Mode } from "./workspace-state";
import { deriveWorkspaceView } from "./workspace-view";
import { modeLabel, WorkspaceInput } from "./WorkspaceInput";
import { WorkspaceResults } from "./WorkspaceResults";

const RUN_SHORTCUT: ShortcutSpec = { mod: true, key: "Enter" };

interface WorkspaceViewProps {
  pendingAction?: { action: WorkspaceAction; text: string } | null;
  onClearPending?: () => void;
  /** Stores still loading or keys still opening: an auto-run waits. */
  vaultSettling?: boolean;
  /** The first look for a context-menu op hasn't answered yet. */
  awaitingPendingOp?: boolean;
  onOpenReply?: (text: string, signer: ReaderSigner) => Promise<void>;
  restoreDraft?: Uint8Array | null;
  onDraftRestored?: () => void;
  onRegisterDraftSource?: (src: WorkspaceDraftSource | null) => void;
  intake?: WorkspaceIntake | null;
  onIntakeConsumed?: () => void;
}

export function WorkspaceView({
  pendingAction,
  onClearPending,
  vaultSettling = false,
  awaitingPendingOp = false,
  onOpenReply,
  restoreDraft,
  onDraftRestored,
  onRegisterDraftSource,
  intake,
  onIntakeConsumed,
}: WorkspaceViewProps) {
  const ws = useWorkspace({
    pendingAction,
    onClearPending,
    restoreDraft,
    onDraftRestored,
    onRegisterDraftSource,
    intake,
    onIntakeConsumed,
  });
  const { state: s, dispatch, myKeys, contacts, crxKeys } = ws;
  const { session } = useVault();
  const { openImport, showTab, revealKeys } = useNav();
  const {
    keyDiscoveryEnabled,
    crxSigningEnabled,
    defaultKeyId,
    neverCacheKeys,
    aiTranslateEnabled,
    translationTargetLanguage,
    signWhenEncrypting: alsoSign,
    encryptToSelf,
    historyEnabled: saveToHistory,
    recentRecipients,
  } = usePreferences();

  const onNavigateToKeys = useCallback(
    (prefill?: string) => (prefill ? openImport({ prefill }) : showTab("keys")),
    [openImport, showTab],
  );
  const onRevealKey = useCallback(
    (keyId: string) => revealKeys([keyId]),
    [revealKeys],
  );
  const {
    loading,
    done,
    error,
    hasOutputText,
    hasInput,
    canEncrypt,
    passwordOnlyMessage,
    unencryptedMessage,
    needsPrivateKey,
    crxSignAvailable,
    showCrxSign,
    showCrxVerify,
    crxResult,
    showFullOutput,
    replyTo,
    canReply,
    canRun,
    resultHasOutput,
    hasDownload,
  } = deriveWorkspaceView(s, {
    canCrxSign: ws.canCrxSign,
    passwordReady: ws.passwordReady,
    crxSigningEnabled,
  });
  const { prompt } = s;
  const { verdict } = s.result;
  const resetResults = () => dispatch({ type: "reset-results" });
  const resetAll = () => dispatch({ type: "reset-all" });
  const setMode = (mode: Mode) => dispatch({ type: "mode-picked", mode });

  const {
    translation,
    composeTranslation,
    setComposedText,
    composeToolsRef,
    onToolsReady,
    composeCanEdit,
    translateEnabled,
    resultCanTranslate,
  } = useWorkspaceTranslation(ws, {
    targetLanguage: translationTargetLanguage,
    aiTranslateEnabled,
    done,
    hasOutputText,
  });
  const { inputElRef, inputChanged } = ws;

  const showLoadingLabel = useDelayedFlag(loading);

  // Save-As is the one download Chrome doesn't route to the CRX installer.
  const saveCrx = async () => {
    if (!crxResult) return;
    const result = await saveCrxViaPrompt(crxResult.data, crxResult.name);
    dispatch({
      type: "status",
      text:
        result === "saved"
          ? t("workspace_crx_saved", { name: crxResult.name })
          : result === "cancelled"
            ? null
            : t("workspace_crx_save_failed"),
    });
  };
  const autoSaveCrx = useEffectEvent(() => void saveCrx());
  const crxData = crxResult?.data;
  useEffect(() => {
    if (crxData) autoSaveCrx();
  }, [crxData]);
  /** The reset wipes the output: the panel keeps no copy. */
  const openReply = () => {
    if (!replyTo || !onOpenReply) return;
    // Display-only card: no public key travels to the tab.
    const signer = displayOnlySignerCard(
      signerCardState({
        signer: replyTo.signer,
        tone: replyTo.tone,
        note: replyTo.note,
        caveat: replyTo.caveat,
        statusText: s.result.status ?? undefined,
        contacts,
        myKeys,
      }),
    );
    void onOpenReply(ws.getOutput(), signer)
      .then(() => {
        resetAll();
        dispatch({ type: "encrypt-to", keyId: signer.contact.keyId });
        requestAnimationFrame(() => {
          window.focus();
          inputElRef.current?.focus();
        });
      })
      .catch(() => toast.error(t("workspace_reply_failed")));
  };

  const selectedRecipientKeys = resolveSelectedRecipients(
    s.recipientIds,
    contacts,
    myKeys,
  );
  const encryptEngine = selectionEngine(selectedRecipientKeys);
  const signKeyChoices = myKeys.filter(isPgpRecord);
  const signerInHeader =
    s.mode === "sign" && !showCrxSign && signKeyChoices.length > 0;
  const signBlockedReason =
    encryptEngine === "ssh"
      ? t("workspace_sign_blocked_age")
      : signKeyChoices.length === 0
        ? t("workspace_sign_blocked_no_pgp_key")
        : undefined;
  const signer =
    signKeyChoices.find((k) => k.keyId === ws.selectedKeyId) ??
    signKeyChoices.at(0);
  const signerName = signer
    ? formatKeyDisplayName(displayUserId(signer))
    : { name: "", detail: "" };
  // Asked of the encrypt's own function so the preview can't disagree.
  const selfExcluded =
    s.mode === "encrypt" && s.recipientIds.length > 0
      ? buildEncryptRecipients({
          recipients: selectedRecipientKeys.map(toSelectedRecipient),
          encryptToSelf,
          ownKeys: myKeys,
          signingKeyId: alsoSign ? ws.selectedKeyId : null,
          defaultKeyId,
        }).selfExcluded
      : false;

  // The undo snapshot lives in a wipeable ref, never a toast closure: sonner
  // keeps action callbacks alive past a master lock.
  const restoreCleared = ws.restoreClearUndo;
  /** Next tick: Radix restores focus to a closing popover's anchor first. */
  const focusMessageBox = () =>
    setTimeout(() => document.getElementById("pgp-input")?.focus(), 0);
  const focusFlowStart = () => {
    setTimeout(() => {
      const input = document.getElementById("pgp-input");
      if (input) return input.focus();
      document
        .querySelector<HTMLElement>("[data-workspace-card]")
        ?.querySelector<HTMLElement>(
          [
            '[role="combobox"]',
            'input:not([type="file"]):not([disabled])',
            "textarea:not([disabled])",
            "select:not([disabled])",
            "button:not([disabled]):not([tabindex='-1'])",
          ].join(","),
        )
        ?.focus();
    }, 0);
  };
  const resetAndRefocus = () => {
    resetAll();
    focusFlowStart();
  };
  const clear = (toastMessage: string | null, textOnly = false) => {
    ws.stashClearUndo();
    if (textOnly) inputChanged("");
    else resetAll();
    if (toastMessage) {
      toast.message(toastMessage, {
        id: "workspace-text-cleared",
        duration: 4000,
        action: { label: t("workspace_undo"), onClick: restoreCleared },
      });
    }
    focusFlowStart();
  };
  const hasStaged =
    s.input.len > 0 || s.files.length > 0 || s.recipientIds.length > 0;
  const clearText = () =>
    clear(done ? null : t("workspace_text_cleared_toast"), s.files.length > 0);

  useShortcut({ mod: true, key: "z" }, restoreCleared, {
    enabled: s.clearUndo && s.input.len === 0,
  });
  useWorkspaceKeyboard({
    mode: s.mode,
    showFullOutput,
    hasStaged,
    promptOpen: prompt !== null,
    onBack: resetResults,
    onClear: () => clear(t("workspace_cleared_toast")),
    onResetMode: () => dispatch({ type: "mode-reset" }),
    focusMessageBox,
  });

  const setEncryptToSelf = (checked: boolean) => {
    resetResults();
    void savePreference({ encryptToSelf: checked });
  };
  const setAlsoSign = (checked: boolean) => {
    resetResults();
    void savePreference({ signWhenEncrypting: checked });
  };
  const setSaveToHistory = (checked: boolean) => {
    void savePreference({ historyEnabled: checked });
    if (checked) void requestUnlimitedHistoryStorage();
  };

  const [copied, setCopied] = useState(false);
  const copyTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const { copy } = useCopyToClipboard();
  const handleCopy = async () => {
    if (!(await copy(ws.getOutput()))) return;
    setCopied(true);
    clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopied(false), 2000);
  };
  const runMain = () => {
    if (done && s.mode === "verify") resetAll();
    else void ws.execute();
  };

  const hideForAutoRun = useAutoRun(ws, {
    vaultSettling,
    arriving:
      awaitingPendingOp ||
      (!!pendingAction?.text &&
        (pendingAction.action === "decrypt" ||
          pendingAction.action === "verify")),
    canRun,
  });

  // Re-verify a looked-up unknown signer once contacts change; never prompts.
  const lookedUp = useRef<{ keyId: string; contacts: unknown } | null>(null);
  const lookupSigner = keyDiscoveryEnabled
    ? (keyId: string) => {
        lookedUp.current = { keyId, contacts };
        openImport({ lookup: keyId });
      }
    : undefined;
  const recheckSigner = useEffectEvent(() => {
    const pending = lookedUp.current;
    if (!pending || pending.contacts === contacts) return;
    lookedUp.current = null;
    if (loading || verdict?.tone !== "warning") return;
    if (verdict.signer.keyId !== pending.keyId) return;
    if (s.mode === "verify") {
      void ws.execute();
    } else if (
      s.mode === "decrypt" &&
      (unencryptedMessage ||
        (!passwordOnlyMessage &&
          ws.selectedKeyId !== null &&
          session.getKeyHandle(ws.selectedKeyId) !== null))
    ) {
      void ws.executeWithoutPrompts();
    }
  });
  useEffect(() => {
    recheckSigner();
  }, [contacts]);

  const bridge = use(WorkspaceBridgeContext);
  const commands: WorkspaceCommands = {
    setMode,
    execute: () => {
      if (canRun) runMain();
    },
    clearInput: resetAll,
    copyOutput: () => {
      if (resultHasOutput) void handleCopy();
    },
    downloadOutput: () => {
      if (hasDownload) ws.triggerDownload();
    },
    reply: openReply,
    translateOutput: () => {
      if (ws.hasTranslation) {
        if (!translation.showing) translation.toggle();
      } else {
        void translation.translate();
      }
    },
    applyStyle: (style) => composeToolsRef.current?.applyStyle(style),
    openFind: () => composeToolsRef.current?.openFind(),
    translateTo: (language) => void composeTranslation.translate(language),
    toggleEncryptToSelf: () => setEncryptToSelf(!encryptToSelf),
    toggleAlsoSign: () => setAlsoSign(!alsoSign),
    toggleSaveToHistory: () => setSaveToHistory(!saveToHistory),
  };
  const snapshot: WorkspaceSnapshot = {
    mode: s.mode,
    hasInput,
    canEncrypt,
    encryptEngine,
    hasOutput: resultHasOutput,
    hasDownload,
    resultCanTranslate,
    resultCanReply: canReply,
    composeCanEdit,
    translateEnabled,
    translateTarget: composeTranslation.targetLanguage,
  };
  useEffect(() => bridge?.publish(snapshot, commands));
  useEffect(() => () => bridge?.publish(null, null), [bridge]);

  const passwordInputRef = useRef<HTMLInputElement>(null);
  const remedyAction = error?.remedy?.action;
  const handleRemedy =
    remedyAction === "retry" ||
    remedyAction === "import-key" ||
    (remedyAction === "unlock" && prompt !== null)
      ? (action: RemedyAction) => {
          if (action === "import-key") onNavigateToKeys();
          else if (action === "retry") void ws.execute();
          else if (action === "unlock") passwordInputRef.current?.focus();
        }
      : undefined;

  const decryptKeyChoices =
    s.mode === "decrypt" && ws.isAge ? myKeys.filter(isSshRecord) : myKeys;

  const resultProps = {
    error,
    outputElRef: ws.outputElRef,
    getOutput: ws.getOutput,
    hasOutput: hasOutputText,
    binaryOutput: s.result.binary,
    fileResults: s.result.files,
    fileName: ws.outputName(),
    operationDone: done,
    statusText: s.result.status ?? undefined,
    verifiedSigner: verdict?.signer ?? null,
    signatureTone: verdict?.tone,
    signatureNote: verdict?.note,
    signerCaveat: verdict?.caveat,
    contacts,
    myKeys,
    outputPublicKeyDetected: s.output.publicKey,
    outputVersion: s.output.version,
    onImportKey: onNavigateToKeys,
    onRevealKey,
    onLookupSigner: lookupSigner,
  };

  const resetButton = (onClick: () => void) => (
    <Button
      variant="outline"
      size="icon"
      onClick={onClick}
      title={t("workspace_clear_input_output")}
      aria-label={t("workspace_clear_input_output")}
    >
      <RotateCcwIcon className="h-4 w-4" />
    </Button>
  );

  if (showFullOutput) {
    return (
      <div className="flex h-full flex-col gap-3">
        <div className="flex items-center">
          <Button
            variant="ghost"
            size="sm"
            className="text-muted-foreground hover:text-foreground -ml-2 h-8 gap-1 px-2"
            onClick={resetResults}
          >
            <ArrowLeftIcon className="h-4 w-4" />
            {t("common_back")}
          </Button>
        </div>
        <WorkspaceResults
          {...resultProps}
          fullHeight
          // Built here so the translation refs stay owned by the wiping workspace.
          translationFooter={
            aiTranslateEnabled ? (
              <>
                <TranslationNote
                  status={translation.status}
                  showing={translation.showing}
                />
                <TranslateToggle
                  status={translation.status}
                  showing={translation.showing}
                  hasTranslation={ws.hasTranslation}
                  onTranslate={() => void translation.translate()}
                  onToggle={translation.toggle}
                  targetLanguage={translationTargetLanguage}
                />
              </>
            ) : null
          }
          resultCorner={
            canReply ? (
              <HoverLabel
                label={t("workspace_reply")}
                shortcut={REPLY_SHORTCUT}
              >
                <button
                  type="button"
                  aria-label={t("workspace_reply")}
                  aria-keyshortcuts={ariaKeyShortcuts(
                    REPLY_SHORTCUT,
                    isMacPlatform(),
                  )}
                  onClick={openReply}
                  className="surface-float text-muted-foreground hover:text-foreground pointer-events-auto shrink-0 rounded-lg p-2 transition-colors"
                >
                  <ReplyIcon className="h-4 w-4" />
                </button>
              </HoverLabel>
            ) : undefined
          }
          showTranslation={translation.showing}
          translationElRef={ws.translationElRef}
          getTranslation={ws.getTranslation}
        />
        <div className="flex gap-2">
          <ResultActions
            onDownload={ws.triggerDownload}
            onCopy={() => void handleCopy()}
            copied={copied}
            disabled={loading}
          />
          {resetButton(resetAndRefocus)}
        </div>
      </div>
    );
  }

  const resultsOnTop = s.mode === "verify";
  const results = <WorkspaceResults {...resultProps} onRemedy={handleRemedy} />;

  return (
    <div
      className={`flex h-full flex-col gap-3 ${hideForAutoRun ? "pointer-events-none opacity-0" : ""}`}
      aria-busy={hideForAutoRun || undefined}
    >
      <WorkspaceInput
        mode={s.mode}
        onModeChange={setMode}
        aboveCard={resultsOnTop ? results : undefined}
        inputElRef={inputElRef}
        getInput={ws.getInput}
        hasInput={s.input.len > 0}
        onInputChange={inputChanged}
        onRepairPastedText={recoverArmorIfNeeded}
        onClearText={clearText}
        files={s.files}
        onFileDrop={ws.dropFiles}
        onRemoveFile={(index) => dispatch({ type: "file-removed", index })}
        onClearFiles={() => dispatch({ type: "files-cleared" })}
        publicKeyDetected={s.input.key === "public"}
        contacts={contacts}
        inputVersion={s.input.version}
        onRevealKey={onRevealKey}
        privateKeyDetected={s.input.key === "private"}
        onNavigateToKeys={onNavigateToKeys}
        onToolsReady={onToolsReady}
        cardHeader={
          s.mode === "encrypt" ? (
            <>
              <Block className="rounded-t-xl focus-within:shadow-[inset_0_0_0_1px_rgb(79_193_133/0.35)]">
                <RecipientPicker
                  inline
                  // cmdk consumes Escape before document; hand it to the message box.
                  onEscapeExhausted={focusMessageBox}
                  passwordArmed={ws.passwordReady}
                  label={t("workspace_recipients_label")}
                  // Sign-only keys can't be encrypted to; legacy (undefined) assumed encryptable.
                  contacts={contacts.filter(
                    (c) => c.usableForEncryption !== false,
                  )}
                  myKeys={myKeys}
                  selectedKeyIds={s.recipientIds}
                  recentKeyIds={recentRecipients}
                  onChange={(ids) => dispatch({ type: "recipients", ids })}
                  emptyText={t("workspace_no_contacts_yet")}
                  emptyAction={onNavigateToKeys}
                  emptyActionLabel={t("workspace_add_a_contact")}
                />
              </Block>
              {myKeys.length > 0 && (
                <Block
                  className="flex min-h-9 items-center gap-2.5 py-1 pr-2.5 pl-3"
                  title={signBlockedReason}
                >
                  {!signBlockedReason && !alsoSign ? null : signer &&
                    !signBlockedReason &&
                    signKeyChoices.length > 1 ? (
                    <KeySelector
                      inline
                      label={t("workspace_sign_with")}
                      keys={signKeyChoices}
                      selectedKeyId={signer.keyId}
                      detailsContacts={contacts}
                      detailsOwnKeys={myKeys}
                      onSelect={ws.selectPrivateKey}
                    />
                  ) : signer && !signBlockedReason ? (
                    <>
                      <KeyAvatar fingerprint={signer.keyId} size={16} />
                      <span className="min-w-0 flex-1 truncate text-sm">
                        {signerName.name}
                        {signerName.detail && (
                          <span className="text-muted-foreground ml-1.5 text-xs">
                            {signerName.detail}
                          </span>
                        )}
                      </span>
                    </>
                  ) : (
                    <span className="text-muted-foreground min-w-0 flex-1 truncate text-xs">
                      {signBlockedReason}
                    </span>
                  )}
                  <label
                    className={cn(
                      "text-muted-foreground flex items-center gap-2 text-xs font-medium",
                      !signBlockedReason && !alsoSign
                        ? "flex-1 justify-between"
                        : "shrink-0",
                    )}
                  >
                    {t("common_sign")}
                    <Switch
                      size="sm"
                      checked={alsoSign}
                      onCheckedChange={setAlsoSign}
                      disabled={signBlockedReason !== undefined}
                    />
                  </label>
                </Block>
              )}
            </>
          ) : signerInHeader ? (
            <Block className="flex min-h-9 items-center gap-2 py-1 pr-1.5 pl-3">
              <span className="text-muted-foreground shrink-0 text-xs font-medium">
                {t("workspace_sign_with")}
              </span>
              <KeySelector
                inline
                label={t("workspace_sign_with")}
                keys={signKeyChoices}
                selectedKeyId={ws.selectedKeyId}
                detailsContacts={contacts}
                detailsOwnKeys={myKeys}
                onSelect={ws.selectPrivateKey}
              />
            </Block>
          ) : undefined
        }
        composeTranslate={
          aiTranslateEnabled
            ? {
                status: composeTranslation.status,
                targetLanguage: composeTranslation.targetLanguage,
                onTranslate: (language) =>
                  void composeTranslation.translate(language),
                onUndo: composeTranslation.undo,
                canUndo: composeTranslation.canUndo,
              }
            : undefined
        }
      />

      <div className="space-y-3">
        {s.mode === "encrypt" && encryptEngine === "ssh" && (
          <p className="text-muted-foreground pl-2 text-xs">
            {t("workspace_age_message_note")}
          </p>
        )}

        {crxSignAvailable && (
          <div className="flex gap-2">
            {(["crx", "pgp"] as const).map((kind) => (
              <Button
                key={kind}
                variant={
                  (s.signKindPick ?? "crx") === kind ? "default" : "outline"
                }
                size="sm"
                className="flex-1"
                onClick={() => dispatch({ type: "sign-kind", kind })}
              >
                {kind === "crx"
                  ? t("workspace_sign_kind_crx")
                  : t("workspace_sign_kind_pgp")}
              </Button>
            ))}
          </div>
        )}

        {needsPrivateKey && !showCrxSign && !signerInHeader && (
          <KeySelector
            label={
              s.mode === "sign"
                ? t("workspace_sign_with")
                : t("workspace_decrypt_with")
            }
            keys={s.mode === "sign" ? signKeyChoices : decryptKeyChoices}
            selectedKeyId={ws.selectedKeyId}
            detailsContacts={contacts}
            detailsOwnKeys={myKeys}
            onSelect={ws.selectPrivateKey}
            emptyText={t("workspace_no_keys_yet")}
            emptyAction={onNavigateToKeys}
            emptyActionLabel={t("workspace_create_one")}
          />
        )}

        {showCrxSign && crxKeys.length > 0 && (
          <div>
            <label className="text-muted-foreground mb-1 block text-xs font-medium">
              {t("workspace_sign_with")}
            </label>
            <Select
              value={ws.crxKeyId ?? ""}
              onValueChange={(id) => dispatch({ type: "crx-key-picked", id })}
            >
              <SelectTrigger className="w-full">
                <SelectValue placeholder={t("workspace_select_signing_key")} />
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
            <div className="flex items-center gap-2">
              <OptionBar className="flex flex-1 [&>*]:flex-auto [&>*]:px-2 [&>*]:text-xs">
                {myKeys.length > 0 && (
                  <ToggleBadge
                    pressed={encryptToSelf}
                    onPressedChange={setEncryptToSelf}
                  >
                    {t("workspace_toggle_encrypt_to_self")}
                  </ToggleBadge>
                )}
                <ToggleBadge
                  pressed={ws.passwordReady}
                  disabledReason={
                    encryptEngine === "ssh" ? sshPasswordReason() : undefined
                  }
                  onPressedChange={(v) => {
                    if (v) {
                      dispatch({ type: "password-dialog", open: true });
                      resetResults();
                    } else {
                      dispatch({ type: "password-set", password: "" });
                    }
                  }}
                >
                  {t("workspace_toggle_password")}
                </ToggleBadge>
                {s.files.length +
                  (s.files.length > 0 && s.input.nonBlank ? 1 : 0) >
                  1 && (
                  <ToggleBadge
                    pressed={s.zipFiles}
                    onPressedChange={(on) =>
                      dispatch({ type: "zip-files", on })
                    }
                  >
                    {t("workspace_toggle_zip_files")}
                  </ToggleBadge>
                )}
                {!neverCacheKeys && (
                  <ToggleBadge
                    pressed={saveToHistory}
                    onPressedChange={setSaveToHistory}
                  >
                    {t("workspace_toggle_save_to_history")}
                  </ToggleBadge>
                )}
              </OptionBar>
            </div>
            {encryptToSelf && selfExcluded && (
              <p className="text-muted-foreground pl-2 text-xs">
                {t("workspace_self_excluded_intro")}{" "}
                {encryptEngine === "ssh"
                  ? t("workspace_self_excluded_age")
                  : t("workspace_self_excluded_pgp")}{" "}
                <button
                  type="button"
                  onClick={() => onNavigateToKeys()}
                  className="text-primary underline"
                >
                  {t("workspace_import_one")}
                </button>
              </p>
            )}
          </div>
        )}

        {prompt && (
          <div className="flex items-stretch gap-2">
            <input
              ref={passwordInputRef}
              type="password"
              placeholder={
                prompt.kind === "message"
                  ? t("workspace_enter_message_password")
                  : t("workspace_enter_key_password")
              }
              value={prompt.value}
              onChange={(e) =>
                dispatch({ type: "prompt-typed", value: e.target.value })
              }
              onKeyDown={(e) => {
                if (e.key === "Enter") void ws.submitPassword();
              }}
              className={`${INPUT_CLASS} h-9 flex-1 py-0`}
              autoFocus
            />
            <Button
              size="sm"
              className="h-9 shrink-0"
              onClick={() => void ws.submitPassword()}
              disabled={loading}
            >
              {showLoadingLabel
                ? prompt.kind === "message"
                  ? t("workspace_decrypting")
                  : t("workspace_unlocking")
                : prompt.kind === "crx" || s.mode === "sign"
                  ? t("common_sign")
                  : s.mode === "decrypt"
                    ? t("common_decrypt")
                    : t("workspace_go")}
            </Button>
          </div>
        )}
        {prompt?.error && <p className="text-bad text-xs">{prompt.error}</p>}

        {!resultsOnTop && results}

        {s.run.kind === "held-back" && (
          <p
            data-testid="auto-run-held-back"
            className="text-muted-foreground text-xs"
          >
            {t("workspace_auto_run_too_large")}
          </p>
        )}

        {s.run.kind === "hidden-chars" && (
          // Hidden chars are signed as-is only on an explicit "Sign anyway".
          <div
            role="alert"
            data-testid="hidden-chars-strip"
            className="text-warn space-y-2 rounded-xl bg-[#252012] px-3 py-2.5 text-xs"
          >
            <p>
              {t("workspace_sign_hidden_chars", {
                chars:
                  s.run.chars.slice(0, 4).join(", ") +
                  (s.run.chars.length > 4 ? ` +${s.run.chars.length - 4}` : ""),
              })}
            </p>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={ws.signWithHiddenChars}
                className="bg-warn/12 hover:bg-warn/20 rounded-md px-2 py-1 font-medium transition-colors"
              >
                {t("workspace_sign_hidden_chars_anyway")}
              </button>
              <button
                type="button"
                onClick={() => {
                  setComposedText(withoutHiddenCharacters(ws.getInput()));
                  resetResults();
                }}
                className="bg-warn/12 hover:bg-warn/20 rounded-md px-2 py-1 font-medium transition-colors"
              >
                {t("workspace_sign_hidden_chars_remove")}
              </button>
            </div>
          </div>
        )}

        {!prompt && (
          <div className="space-y-2">
            {crxResult ? (
              <div className="flex gap-2">
                <Button className="flex-1" onClick={() => void saveCrx()}>
                  <span className="flex items-center gap-2">
                    <DownloadIcon className="h-4 w-4" />
                    {t("workspace_save_file", { name: crxResult.name })}
                  </span>
                </Button>
                {resetButton(resetAll)}
              </div>
            ) : showCrxVerify ? (
              <Button
                className="w-full"
                variant={done ? "outline" : "default"}
                onClick={done ? resetAll : () => void ws.verifyCrxInput()}
                disabled={loading}
              >
                {showLoadingLabel
                  ? t("workspace_verifying")
                  : done
                    ? t("workspace_reset")
                    : t("workspace_verify_signature")}
              </Button>
            ) : showCrxSign ? (
              <Button
                className="w-full"
                onClick={() => void ws.executeCrxSign()}
                disabled={loading}
              >
                {showLoadingLabel
                  ? t("workspace_processing")
                  : t("workspace_sign_for_web_store")}
              </Button>
            ) : (
              <div className="flex gap-2">
                {done && s.mode !== "verify" ? (
                  <ResultActions
                    onDownload={ws.triggerDownload}
                    onCopy={hasOutputText ? () => void handleCopy() : undefined}
                    copied={copied}
                    disabled={loading}
                  />
                ) : (
                  <Button
                    className="flex-1 capitalize"
                    onClick={runMain}
                    disabled={
                      loading ||
                      !hasInput ||
                      (s.mode === "encrypt" && !canEncrypt)
                    }
                    title={
                      s.mode === "encrypt" && !canEncrypt
                        ? t("workspace_need_recipient_or_password")
                        : undefined
                    }
                    shortcut={RUN_SHORTCUT}
                  >
                    {showLoadingLabel
                      ? t("workspace_processing")
                      : done && s.mode === "verify"
                        ? t("workspace_reset")
                        : modeLabel(s.mode)}
                  </Button>
                )}
                {(hasInput || done) &&
                  !(done && s.mode === "verify") &&
                  resetButton(resetAndRefocus)}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Mounted when open so `useSlideOver`'s Escape stack sees it. */}
      {s.passwordDialogOpen && (
        <MessagePasswordPage
          onSet={(password) => dispatch({ type: "password-set", password })}
          onCancel={() => dispatch({ type: "password-dialog", open: false })}
        />
      )}
    </div>
  );
}
