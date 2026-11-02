import {
  use,
  useCallback,
  useEffect,
  useEffectEvent,
  useRef,
  useState,
} from "react";
import { ArrowLeftIcon, ReplyIcon } from "lucide-react";

import {
  ariaKeyShortcuts,
  Block,
  Button,
  cn,
  isMacPlatform,
  Switch,
} from "@amibeingpwned/ui";

import { HoverHint } from "~/components/shared/HoverHint";
import { KeyAvatar } from "~/components/shared/KeyAvatar";
import {
  WorkspaceBridgeContext,
  type WorkspaceCommands,
  type WorkspaceSnapshot,
} from "~/hooks/useActionContext";
import { useCopyToClipboard } from "~/hooks/useCopyToClipboard";
import { useDelayedFlag } from "~/hooks/useDelayedFlag";
import { useNav } from "~/hooks/useNav";
import { usePreferences } from "~/hooks/usePreferences";
import { useShortcut } from "~/hooks/useShortcut";
import { useVault } from "~/hooks/useVault";
import { REPLY_SHORTCUT } from "~/lib/actions/definitions";
import { recoverArmorIfNeeded } from "~/lib/armor-recovery";
import {
  buildEncryptRecipients,
  resolveSelectedRecipients,
  toSelectedRecipient,
} from "~/lib/encrypt-recipients";
import type { RemedyAction } from "~/lib/errors/present";
import { t } from "~/lib/i18n";
import type { WorkspaceAction } from "~/lib/messages";
import type { ReaderSigner } from "~/lib/reader-protocol";
import { isPgpRecord, isSshRecord } from "~/lib/storage/key-kind";
import { toast } from "~/lib/toast";
import { saveCrxViaPrompt } from "~/lib/utils/download";
import { displayUserId, formatKeyDisplayName } from "~/lib/utils/key-naming";
import type { WorkspaceDraftSource } from "~/lib/workspace-draft";
import { KeySelector } from "./KeySelector";
import { MessagePasswordPage } from "./MessagePasswordPage";
import { selectionEngine } from "./recipient-engine";
import { RecipientPicker } from "./RecipientPicker";
import { ResultActions } from "./ResultActions";
import { displayOnlySignerCard, signerCardState } from "./signer-card";
import { TranslateToggle, TranslationNote } from "./TranslationPanel";
import { useAutoRun } from "./useAutoRun";
import { useWorkspace, type WorkspaceIntake } from "./useWorkspace";
import { useWorkspaceKeyboard } from "./useWorkspaceKeyboard";
import { useWorkspaceTranslation } from "./useWorkspaceTranslation";
import type { Mode } from "./workspace-state";
import { deriveWorkspaceView } from "./workspace-view";
import { WorkspaceInput } from "./WorkspaceInput";
import { WorkspaceResults } from "./WorkspaceResults";
import {
  EncryptOptions,
  MainActions,
  PasswordPrompt,
  ResetButton,
  RunNotices,
  SignKeyPickers,
  useEncryptToggles,
} from "./WorkspaceSections";

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
  const { state: s, dispatch, myKeys, contacts } = ws;
  const { session } = useVault();
  const { openImport, showTab, revealKeys } = useNav();
  const {
    keyDiscoveryEnabled,
    crxSigningEnabled,
    defaultKeyId,
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
  const v = deriveWorkspaceView(s, {
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
    done: v.done,
    hasOutputText: v.hasOutputText,
  });
  const { inputElRef, inputChanged } = ws;

  const showLoadingLabel = useDelayedFlag(v.loading);

  // Save-As is the one download Chrome doesn't route to the CRX installer.
  const saveCrx = async () => {
    if (!v.crxResult) return;
    const result = await saveCrxViaPrompt(v.crxResult.data, v.crxResult.name);
    dispatch({
      type: "status",
      text:
        result === "saved"
          ? t("workspace_crx_saved", { name: v.crxResult.name })
          : result === "cancelled"
            ? null
            : t("workspace_crx_save_failed"),
    });
  };
  const autoSaveCrx = useEffectEvent(() => void saveCrx());
  const crxData = v.crxResult?.data;
  useEffect(() => {
    if (crxData) autoSaveCrx();
  }, [crxData]);
  /** The reset wipes the output: the panel keeps no copy. */
  const openReply = () => {
    if (!v.replyTo || !onOpenReply) return;
    // Display-only card: no public key travels to the tab.
    const signer = displayOnlySignerCard(
      signerCardState({
        signer: v.replyTo.signer,
        tone: v.replyTo.tone,
        note: v.replyTo.note,
        caveat: v.replyTo.caveat,
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
    s.mode === "sign" && !v.showCrxSign && signKeyChoices.length > 0;
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
    clear(
      v.done ? null : t("workspace_text_cleared_toast"),
      s.files.length > 0,
    );

  useShortcut({ mod: true, key: "z" }, restoreCleared, {
    enabled: s.clearUndo && s.input.len === 0,
  });
  useWorkspaceKeyboard({
    mode: s.mode,
    showFullOutput: v.showFullOutput,
    hasStaged,
    promptOpen: prompt !== null,
    onBack: resetResults,
    onClear: () => clear(t("workspace_cleared_toast")),
    onResetMode: () => dispatch({ type: "mode-reset" }),
    focusMessageBox,
  });

  const { setEncryptToSelf, setAlsoSign, setSaveToHistory } =
    useEncryptToggles(ws);

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
    if (v.done && s.mode === "verify") resetAll();
    else void ws.execute();
  };

  const hideForAutoRun = useAutoRun(ws, {
    vaultSettling,
    arriving:
      awaitingPendingOp ||
      (!!pendingAction?.text &&
        (pendingAction.action === "decrypt" ||
          pendingAction.action === "verify")),
    canRun: v.canRun,
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
    if (v.loading || verdict?.tone !== "warning") return;
    if (verdict.signer.keyId !== pending.keyId) return;
    if (s.mode === "verify") {
      void ws.execute();
    } else if (
      s.mode === "decrypt" &&
      (v.unencryptedMessage ||
        (!v.passwordOnlyMessage &&
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
      if (v.canRun) runMain();
    },
    clearInput: resetAll,
    copyOutput: () => {
      if (v.resultHasOutput) void handleCopy();
    },
    downloadOutput: () => {
      if (v.hasDownload) ws.triggerDownload();
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
    hasInput: v.hasInput,
    canEncrypt: v.canEncrypt,
    encryptEngine,
    hasOutput: v.resultHasOutput,
    hasDownload: v.hasDownload,
    resultCanTranslate,
    resultCanReply: v.canReply,
    composeCanEdit,
    translateEnabled,
    translateTarget: composeTranslation.targetLanguage,
  };
  useEffect(() => bridge?.publish(snapshot, commands));
  useEffect(() => () => bridge?.publish(null, null), [bridge]);

  const passwordInputRef = useRef<HTMLInputElement>(null);
  const remedyAction = v.error?.remedy?.action;
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
    error: v.error,
    outputElRef: ws.outputElRef,
    getOutput: ws.getOutput,
    hasOutput: v.hasOutputText,
    binaryOutput: s.result.binary,
    fileResults: s.result.files,
    fileName: ws.outputName(),
    operationDone: v.done,
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

  if (v.showFullOutput) {
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
            v.canReply ? (
              <HoverHint
                align="end"
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
              </HoverHint>
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
            disabled={v.loading}
          />
          <ResetButton onClick={resetAndRefocus} />
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

        <SignKeyPickers
          ws={ws}
          v={v}
          signerInHeader={signerInHeader}
          signKeyChoices={signKeyChoices}
          decryptKeyChoices={decryptKeyChoices}
        />

        {s.mode === "encrypt" && (
          <EncryptOptions
            ws={ws}
            encryptEngine={encryptEngine}
            selfExcluded={selfExcluded}
          />
        )}

        <PasswordPrompt
          ws={ws}
          inputRef={passwordInputRef}
          busy={v.loading}
          busyLabel={showLoadingLabel}
        />

        {!resultsOnTop && results}

        <RunNotices ws={ws} setComposedText={setComposedText} />

        <MainActions
          ws={ws}
          v={v}
          busyLabel={showLoadingLabel}
          copied={copied}
          onCopy={() => void handleCopy()}
          onSaveCrx={() => void saveCrx()}
          onRun={runMain}
          onReset={resetAndRefocus}
        />
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
