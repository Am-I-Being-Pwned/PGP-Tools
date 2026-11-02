import {
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

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";
import { cn } from "@amibeingpwned/ui";
import { Block } from "@amibeingpwned/ui/block";
import { Button } from "@amibeingpwned/ui/button";
import { ariaKeyShortcuts, isMacPlatform } from "@amibeingpwned/ui/kbd-helpers";
import { OptionBar } from "@amibeingpwned/ui/option-bar";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@amibeingpwned/ui/select";
import { Switch } from "@amibeingpwned/ui/switch";

import type { WorkspaceOpsBridge } from "../../hooks/useActionContext";
import type { RemedyAction } from "../../lib/errors/present";
import type { WorkspaceAction } from "../../lib/messages";
import type { ReaderSigner } from "../../lib/reader-protocol";
import type { WorkspaceDraftSource } from "../../lib/workspace-draft";
import type { WorkspaceIntake } from "./useWorkspace";
import type { Mode } from "./workspace-state";
import type { ComposeTools } from "./WorkspaceInput";
import { useComposeTranslation } from "../../hooks/useComposeTranslation";
import { useCopyToClipboard } from "../../hooks/useCopyToClipboard";
import { useDelayedFlag } from "../../hooks/useDelayedFlag";
import { useNav } from "../../hooks/useNav";
import { savePreference, usePreferences } from "../../hooks/usePreferences";
import { useShortcut } from "../../hooks/useShortcut";
import { useTranslation } from "../../hooks/useTranslation";
import { useVault } from "../../hooks/useVault";
import { REPLY_SHORTCUT } from "../../lib/actions/definitions";
import { languageLabel } from "../../lib/ai/languages";
import { recoverArmorIfNeeded } from "../../lib/armor-recovery";
import { applyTextareaEdit } from "../../lib/compose/apply-edit";
import {
  buildEncryptRecipients,
  resolveSelectedRecipients,
  sshPasswordReason,
  toSelectedRecipient,
} from "../../lib/encrypt-recipients";
import { t } from "../../lib/i18n";
import { requestUnlimitedHistoryStorage } from "../../lib/storage/history";
import { isPgpRecord, isSshRecord } from "../../lib/storage/key-kind";
import { toast } from "../../lib/toast";
import { saveCrxViaPrompt } from "../../lib/utils/download";
import {
  displayUserId,
  formatKeyDisplayName,
} from "../../lib/utils/key-naming";
import { INPUT_CLASS } from "../../lib/utils/styles";
import { KeyAvatar } from "../shared/KeyAvatar";
import { ToggleBadge } from "../shared/ToggleBadge";
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
import { useWorkspace } from "./useWorkspace";
import { useWorkspaceKeyboard } from "./useWorkspaceKeyboard";
import { modeLabel, WorkspaceInput } from "./WorkspaceInput";
import { WorkspaceResults } from "./WorkspaceResults";

/** mod+Enter mirrors the main action button. */
const RUN_SHORTCUT: ShortcutSpec = { mod: true, key: "Enter" };

interface WorkspaceViewProps {
  pendingAction?: { action: WorkspaceAction; text: string } | null;
  onClearPending?: () => void;
  /** Stores still loading or keys still opening: an auto-run waits. */
  vaultSettling?: boolean;
  /** The first look for a context-menu op hasn't answered yet. */
  awaitingPendingOp?: boolean;
  /** Open `text` in a reader tab; absent where Reply isn't offered. */
  onOpenReply?: (text: string, signer: ReaderSigner) => Promise<void>;
  restoreDraft?: Uint8Array | null;
  onDraftRestored?: () => void;
  onRegisterDraftSource?: (src: WorkspaceDraftSource | null) => void;
  intake?: WorkspaceIntake | null;
  onIntakeConsumed?: () => void;
  onPaletteOps?: (bridge: WorkspaceOpsBridge | null) => void;
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
  onPaletteOps,
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

  const loading = s.run.kind === "running";
  const done = s.run.kind === "done";
  const error = s.run.kind === "error" ? s.run.error : null;
  const { prompt } = s;
  const { verdict } = s.result;
  const hasOutputText = s.output.len > 0;
  const hasInput = s.files.length > 0 || s.input.len > 0;
  const resetResults = () => dispatch({ type: "reset-results" });
  const resetAll = () => dispatch({ type: "reset-all" });
  const setMode = (mode: Mode) => dispatch({ type: "mode-picked", mode });

  const translation = useTranslation({
    getOutput: ws.getOutput,
    outputVersion: s.output.version,
    setTranslation: ws.setTranslation,
    targetLanguage: translationTargetLanguage,
  });

  // ── compose translation ────────────────────────────────────────────
  // Written through the textarea's own editing path when mounted, so
  // mod+Z reverts a translation like any other edit.
  const { inputElRef, inputChanged } = ws;
  const setComposedText = useCallback(
    (text: string) => {
      const el = inputElRef.current;
      if (
        el &&
        applyTextareaEdit(el, { text, start: text.length, end: text.length })
      ) {
        return;
      }
      inputChanged(text);
    },
    [inputElRef, inputChanged],
  );
  const translatedToastRef = useRef<string | number | null>(null);
  const translatedToastSeq = useRef(0);
  const composeTranslation = useComposeTranslation({
    getInput: ws.getInput,
    setInput: setComposedText,
    readingLanguage: translationTargetLanguage,
    onTranslated: (from, to) => {
      // A fresh id per translation: a toast reusing the id of one still
      // animating out is merged into it and leaves with it.
      if (translatedToastRef.current !== null) {
        toast.dismiss(translatedToastRef.current);
      }
      translatedToastRef.current = toast.message(
        t("workspace_compose_translated", {
          from: languageLabel(from),
          to: languageLabel(to),
        }),
        {
          id: `compose-translated-${++translatedToastSeq.current}`,
          duration: 6000,
          action: {
            label: t("workspace_undo"),
            onClick: () => composeTranslation.undo(),
          },
        },
      );
    },
    onStatus: (status) => {
      // The composer has no result bar: problems surface as toasts.
      if (status.kind === "same-language") {
        toast.message(
          t("workspace_compose_same_language", {
            language: languageLabel(status.language),
          }),
          { id: "compose-translate" },
        );
      } else if (status.kind === "unavailable") {
        toast.message(t("workspace_compose_translate_unavailable"), {
          id: "compose-translate",
        });
      } else if (status.kind === "error") {
        toast.error(status.message, { id: "compose-translate" });
      }
    },
  });
  // The undo original is plaintext: wiped at master lock (§8.11), dropped
  // once the user edits past it, cancelled when the box stops composing.
  const { addWiper, getInput } = ws;
  const { forget, noteInputChanged, cancel } = composeTranslation;
  useEffect(() => addWiper(forget), [addWiper, forget]);
  useEffect(() => {
    noteInputChanged(getInput());
  }, [s.input.version, noteInputChanged, getInput]);
  const composeToolsRef = useRef<ComposeTools | null>(null);
  const onToolsReady = useCallback((tools: ComposeTools | null) => {
    composeToolsRef.current = tools;
  }, []);
  // The find bar's highlight mirror holds a copy of the text.
  useEffect(
    () => addWiper(() => composeToolsRef.current?.closeFind()),
    [addWiper],
  );
  const composeCanEdit =
    (s.mode === "encrypt" || s.mode === "sign") &&
    s.files.length === 0 &&
    s.input.key !== "private";
  useEffect(() => {
    if (!composeCanEdit) cancel();
  }, [composeCanEdit, cancel]);
  const translateEnabled =
    aiTranslateEnabled && composeTranslation.status.kind !== "unavailable";
  const resultCanTranslate =
    aiTranslateEnabled &&
    done &&
    hasOutputText &&
    (s.mode === "decrypt" || s.mode === "verify") &&
    translation.status.kind !== "unavailable" &&
    translation.status.kind !== "same-language";

  const showLoadingLabel = useDelayedFlag(loading);

  // ── what applies ───────────────────────────────────────────────────
  const canEncrypt = s.recipientIds.length > 0 || ws.passwordReady;
  // A password-only or unencrypted message needs no key: offering a
  // picker of keys that are all wrong is worse than none.
  const passwordOnlyMessage =
    s.mode === "decrypt" &&
    s.messageEncryption?.password === true &&
    !s.messageEncryption.publicKey;
  const unencryptedMessage =
    s.mode === "decrypt" && s.messageEncryption?.encrypted === false;
  const needsPrivateKey =
    (s.mode === "decrypt" && !passwordOnlyMessage && !unencryptedMessage) ||
    s.mode === "sign";

  const singleCrxFile = s.files.length === 1 && /\.crx$/i.test(s.files[0].name);
  // Only for a single .zip that holds a manifest.json; PGP signing stays
  // available through the "Sign as" toggle.
  const crxSignAvailable =
    ws.canCrxSign && s.mode === "sign" && s.isExtensionZip && !done;
  const showCrxSign = crxSignAvailable && (s.signKindPick ?? "crx") === "crx";
  const showCrxVerify =
    crxSigningEnabled && s.mode === "verify" && singleCrxFile;
  const crxResult =
    done &&
    s.result.files.length === 1 &&
    /\.crx$/i.test(s.result.files[0].name)
      ? s.result.files[0]
      : null;

  // A Save-As download is the one case Chrome does not route a CRX to the
  // extension installer (see saveCrxViaPrompt).
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
  // Saved the moment it is signed; the Save button covers a first-time
  // `downloads` grant that needs a fresh gesture.
  const autoSaveCrx = useEffectEvent(() => void saveCrx());
  const crxData = crxResult?.data;
  useEffect(() => {
    if (crxData) autoSaveCrx();
  }, [crxData]);

  // A decrypted or verified text gets the whole panel, with Back.
  const showFullOutput =
    done && (s.mode === "decrypt" || s.mode === "verify") && hasOutputText;
  // Reply needs a signer whose key we hold, on a message that was
  // encrypted: an amber card is never private mail from anyone.
  const replyTo =
    showFullOutput && s.mode === "decrypt" && verdict?.tone === "success"
      ? verdict
      : null;
  const canReply = replyTo !== null;
  /** Hand the message to a reader tab and turn this workspace into the
   *  reply. The reset wipes the output: the panel keeps no copy. */
  const openReply = () => {
    if (!replyTo || !onOpenReply) return;
    // The card exactly as shown, minus anything it doesn't display: no
    // public key travels to the tab.
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
        // The new tab takes focus; hand it back for the reply. Best effort.
        requestAnimationFrame(() => {
          window.focus();
          inputElRef.current?.focus();
        });
      })
      .catch(() => toast.error(t("workspace_reply_failed")));
  };

  // ── recipients and signer ──────────────────────────────────────────
  // Own keys before contacts -- see `resolveSelectedRecipients`.
  const selectedRecipientKeys = resolveSelectedRecipients(
    s.recipientIds,
    contacts,
    myKeys,
  );
  const encryptEngine = selectionEngine(selectedRecipientKeys);
  // Only OpenPGP keys sign: SSH identities are narrowed out, not dimmed.
  const signKeyChoices = myKeys.filter(isPgpRecord);
  const signerInHeader =
    s.mode === "sign" && !showCrxSign && signKeyChoices.length > 0;
  const signBlockedReason =
    encryptEngine === "ssh"
      ? t("workspace_sign_blocked_age")
      : signKeyChoices.length === 0
        ? t("workspace_sign_blocked_no_pgp_key")
        : undefined;
  // The same pick the encrypt makes: the key in effect if it signs, else
  // the first PGP key.
  const signer =
    signKeyChoices.find((k) => k.keyId === ws.selectedKeyId) ??
    signKeyChoices.at(0);
  const signerName = signer
    ? formatKeyDisplayName(displayUserId(signer))
    : { name: "", detail: "" };
  // Asked of the function the encrypt runs through, so the preview cannot
  // disagree with what actually happens.
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

  // ── clearing ───────────────────────────────────────────────────────
  // The undo snapshot lives in the workspace's wipeable ref, never in a
  // toast closure: sonner keeps action callbacks alive for the toast's
  // lifetime, past a master lock.
  const restoreCleared = ws.restoreClearUndo;
  /** Next tick: Radix restores focus to a closing popover's anchor (the
   *  recipient box), and the clear may have just remounted the card. */
  const focusMessageBox = () =>
    setTimeout(() => document.getElementById("pgp-input")?.focus(), 0);
  /** After a clear: the message box, else the card's first control. */
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
  /** `textOnly`: empty the box as deleting its text would; attachments
   *  staged beside it stay. */
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
  // Recipients count: a message addressed but not written is staged.
  const hasStaged =
    s.input.len > 0 || s.files.length > 0 || s.recipientIds.length > 0;
  /** The in-box "Clear text": silent after a run (the result is its own
   *  feedback). Files have their own Clear all. */
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

  // ── preferences ────────────────────────────────────────────────────
  // Shared by the toggles and the palette: persistence plus the
  // stale-output reset.
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
    // A user gesture: ask for the generous budget. A denial is fine.
    if (checked) void requestUnlimitedHistoryStorage();
  };

  // ── run / copy / download ──────────────────────────────────────────
  const [copied, setCopied] = useState(false);
  const copyTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const { copy } = useCopyToClipboard();
  const handleCopy = async () => {
    // The button's check is the feedback; a refused write toasts.
    if (!(await copy(ws.getOutput()))) return;
    setCopied(true);
    clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopied(false), 2000);
  };
  const mainActionShown =
    !showFullOutput &&
    prompt === null &&
    !crxResult &&
    !showCrxVerify &&
    !showCrxSign &&
    !(done && s.mode !== "verify");
  const canRun =
    mainActionShown && !loading && !(s.mode === "encrypt" && !canEncrypt);
  const resultHasOutput = done && hasOutputText && !loading;
  // Verify yields a verdict, not an artifact.
  const hasDownload =
    done &&
    !loading &&
    s.mode !== "verify" &&
    (s.result.files.length > 0 || !!s.result.binary || hasOutputText);
  // In verify-done state Run resets, like the button.
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

  // An unknown signer the user went to look up: once contacts change,
  // check again so the amber card becomes the real verdict. Never at the
  // cost of a prompt, and not capped: the user opened this message.
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

  // ── palette bridge ─────────────────────────────────────────────────
  const commands = {
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
      // A translation already made is shown, not remade.
      if (ws.hasTranslation) {
        if (!translation.showing) translation.toggle();
      } else {
        void translation.translate();
      }
    },
    applyStyle: (style: Parameters<ComposeTools["applyStyle"]>[0]) =>
      composeToolsRef.current?.applyStyle(style),
    openFind: () => composeToolsRef.current?.openFind(),
    translateTo: (language: string) =>
      void composeTranslation.translate(language),
    toggleEncryptToSelf: () => setEncryptToSelf(!encryptToSelf),
    toggleAlsoSign: () => setAlsoSign(!alsoSign),
    toggleSaveToHistory: () => setSaveToHistory(!saveToHistory),
  };
  const commandsRef = useRef(commands);
  useEffect(() => {
    commandsRef.current = commands;
  });
  useEffect(() => {
    const c = commandsRef;
    onPaletteOps?.({
      mode: s.mode,
      hasInput,
      canEncrypt,
      encryptEngine,
      hasOutput: resultHasOutput,
      hasDownload,
      historyEnabled: saveToHistory,
      encryptToSelf,
      alsoSign,
      resultCanTranslate,
      resultCanReply: canReply,
      readingLanguage: translationTargetLanguage,
      composeCanEdit,
      translateEnabled,
      translateTarget: composeTranslation.targetLanguage,
      setMode: (m) => c.current.setMode(m),
      execute: () => c.current.execute(),
      clearInput: () => c.current.clearInput(),
      copyOutput: () => c.current.copyOutput(),
      downloadOutput: () => c.current.downloadOutput(),
      reply: () => c.current.reply(),
      translateOutput: () => c.current.translateOutput(),
      applyStyle: (style) => c.current.applyStyle(style),
      openFind: () => c.current.openFind(),
      translateTo: (language) => c.current.translateTo(language),
      toggleEncryptToSelf: () => c.current.toggleEncryptToSelf(),
      toggleAlsoSign: () => c.current.toggleAlsoSign(),
      toggleSaveToHistory: () => c.current.toggleSaveToHistory(),
    });
  }, [
    onPaletteOps,
    s.mode,
    hasInput,
    canEncrypt,
    encryptEngine,
    resultHasOutput,
    hasDownload,
    saveToHistory,
    encryptToSelf,
    alsoSign,
    resultCanTranslate,
    canReply,
    translationTargetLanguage,
    composeCanEdit,
    translateEnabled,
    composeTranslation.targetLanguage,
  ]);
  useEffect(() => () => onPaletteOps?.(null), [onPaletteOps]);

  // Remedies this view can perform; any other renders message-only.
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
          // A footer bar, permanent once translation is on, so a status
          // appearing never resizes the message above it. Built here so
          // the translation refs stay owned by the wiping workspace.
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

  // A verify verdict reads first, above the box, not under a tall message.
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
        // Recipients are the card's To row, as on an envelope.
        cardHeader={
          s.mode === "encrypt" ? (
            <>
              <Block className="rounded-t-xl focus-within:shadow-[inset_0_0_0_1px_rgb(79_193_133/0.35)]">
                <RecipientPicker
                  inline
                  // Its Escape layers spent, Escape lands in the message
                  // (cmdk consumes Escape before it reaches document).
                  onEscapeExhausted={focusMessageBox}
                  // A password rules out age: SSH rows dim with a reason.
                  passwordArmed={ws.passwordReady}
                  label={t("workspace_recipients_label")}
                  // Sign-only keys verify but cannot be encrypted to; legacy
                  // records (undefined) are assumed encryptable.
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
              {/* The From line: who signs, and whether they do. */}
              {myKeys.length > 0 && (
                <Block
                  className="flex min-h-9 items-center gap-2.5 py-1 pr-2.5 pl-3"
                  title={signBlockedReason}
                >
                  {/* Off: just the switch. On with several signing keys:
                      the name IS the picker. Blocked: the reason. */}
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
            // An age message opens only with an SSH identity: narrowed.
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
                  // A persisted preference: left pressed even when this
                  // message can't include the user; the line below says so.
                  <ToggleBadge
                    pressed={encryptToSelf}
                    onPressedChange={setEncryptToSelf}
                  >
                    {t("workspace_toggle_encrypt_to_self")}
                  </ToggleBadge>
                )}
                {/* ADDITIVE: a password the message can also be opened
                    with. Pressed means a password IS SET. Dimmed with a
                    reason for age, never hidden. */}
                <ToggleBadge
                  pressed={ws.passwordReady}
                  disabledReason={
                    encryptEngine === "ssh" ? sshPasswordReason() : undefined
                  }
                  onPressedChange={(v) => {
                    // Un-pressing drops the password rather than parking
                    // it against a message it was never meant for.
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
                {/* Counted as the encrypt will: a written message goes too. */}
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
                {/* Never-cache means no history, ever: no dead switch. */}
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
              // One password row for every question: the placeholder
              // carries the whole distinction.
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
          // Signed as they are only on an explicit "Sign anyway"; "Remove
          // them" edits the box (undoable).
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
                {/* Verify-done's main button IS Reset. */}
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
