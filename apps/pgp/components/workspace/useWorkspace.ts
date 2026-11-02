import {
  useCallback,
  useEffect,
  useEffectEvent,
  useRef,
  useState,
} from "react";

import type { WorkspaceAction } from "../../lib/messages";
import type {
  WorkspaceDraft,
  WorkspaceDraftSource,
} from "../../lib/workspace-draft";
import type { RunContext } from "./workspace-operations";
import type { Outcome, WorkspaceEvent } from "./workspace-state";
import { useContacts } from "../../hooks/useContacts";
import { useCrxKeys } from "../../hooks/useCrxKeys";
import { useKeyring } from "../../hooks/useKeyring";
import { useNav } from "../../hooks/useNav";
import { usePreferences } from "../../hooks/usePreferences";
import { useVault } from "../../hooks/useVault";
import { recoverArmorIfNeeded } from "../../lib/armor-recovery";
import { presentError } from "../../lib/errors/present";
import { t } from "../../lib/i18n";
import { oversizedFilesMessage, splitOversizedFiles } from "../../lib/limits";
import { toast } from "../../lib/toast";
import { showLoneCarriageReturns } from "../../lib/utils/line-breaks";
import { forgetLastRegExpMatch } from "../../lib/utils/regexp-residue";
import { zipHasManifest } from "../../lib/utils/zip";
import { decryptWorkspaceDraft } from "../../lib/workspace-draft";
import {
  AUTO_RUN_MAX_BYTES,
  decryptWithMessagePassword,
  download,
  matchDecryptionKey,
  outputName,
  runMode,
  scanMessageEncryption,
  signCrx,
  verifyCrx,
} from "./workspace-operations";
import {
  encryptPasswordReady,
  initialWorkspaceState,
  inputIsAge,
  resolveKeyId,
  textFacts,
  workspaceReducer,
  zeroizeResultBytes,
} from "./workspace-state";

/** A drop routed here by the global dropzone; `nonce` re-triggers intake
 *  for the same files/text. */
export interface WorkspaceIntake {
  files: File[];
  text: string;
  nonce: number;
}

const PUBLIC_KEY_HEADER = "-----BEGIN PGP PUBLIC KEY BLOCK-----";

/**
 * The workspace: one reducer for render state, refs for every copy of
 * plaintext, and the operations wired to both.
 *
 * PLAINTEXT LIVES IN REFS + UNCONTROLLED DOM NODES, never in state or a
 * long-lived closure: React retains hook state and effect closures on
 * `fiber.alternate` past unmount, so a master lock could not release it
 * (SECURITY.md §8.11). Read it with `getInput`/`getOutput` at the point
 * of use. The App pulls the draft at lock time, then calls `wipe()`.
 */
export function useWorkspace(opts: {
  pendingAction?: { action: WorkspaceAction; text: string } | null;
  onClearPending?: () => void;
  /** Encrypted draft from a prior lock, applied once. */
  restoreDraft?: Uint8Array | null;
  onDraftRestored?: () => void;
  onRegisterDraftSource?: (src: WorkspaceDraftSource | null) => void;
  intake?: WorkspaceIntake | null;
  onIntakeConsumed?: () => void;
}) {
  const { keys: myKeys } = useKeyring();
  const { contacts } = useContacts();
  const { keys: crxKeys } = useCrxKeys();
  const { session } = useVault();
  const nav = useNav();
  const prefs = usePreferences();

  const [state, setState] = useState(initialWorkspaceState);
  // Reduced eagerly so async runs and the lock-time wipe see the latest.
  const stateRef = useRef(state);

  const inputRef = useRef("");
  const inputElRef = useRef<HTMLTextAreaElement | null>(null);
  const outputRef = useRef("");
  const outputElRef = useRef<HTMLPreElement | null>(null);
  // A translation is a second readable copy of the output: held the same
  // way (T-TRANSLATION-HEAP-RESIDUE); only its length is state.
  const translationRef = useRef("");
  const translationElRef = useRef<HTMLPreElement | null>(null);
  const [translationLen, setTranslationLen] = useState(0);
  const clearUndoRef = useRef<{
    input: string;
    files: File[];
    recipientIds: string[];
  } | null>(null);
  // Other plaintext holders (translate-undo original, find-bar mirror).
  const extraWipers = useRef(new Set<() => void>());
  // "Sign anyway" applies to one exact text: the input version it was for.
  const hiddenConfirmedFor = useRef<number | null>(null);

  const getInput = useCallback(() => inputRef.current, []);
  const getOutput = useCallback(() => outputRef.current, []);
  const getTranslation = useCallback(() => translationRef.current, []);

  // The `!==` guards are load-bearing: assigning `.value` moves the caret,
  // and rewriting `textContent` drops the user's selection.
  const writeInput = useCallback((text: string) => {
    inputRef.current = text;
    const el = inputElRef.current;
    if (el && el.value !== text) el.value = text;
  }, []);

  const dispatch = useCallback((event: WorkspaceEvent) => {
    const prev = stateRef.current;
    const next = workspaceReducer(prev, event);
    if (next === prev) return;
    stateRef.current = next;
    // Every mode change (picked, nudged, opened) moves on, as a tab change
    // does: the last mode's toasts, Undo included, go.
    if (next.mode !== prev.mode) toast.dismiss();
    // The reducer says when text is gone; the refs holding it follow.
    if (next.input.len === 0 && inputRef.current !== "") {
      inputRef.current = "";
      if (inputElRef.current) inputElRef.current.value = "";
    }
    if (next.output.len === 0 && next.output !== prev.output) {
      outputRef.current = "";
      if (outputElRef.current) outputElRef.current.textContent = "";
      forgetLastRegExpMatch();
    }
    setState(next);
  }, []);

  const writeOutput = useCallback(
    (text: string) => {
      outputRef.current = text;
      // Lone CRs shown as a symbol; the ref keeps the bytes for copy and
      // download.
      const shown = showLoneCarriageReturns(text);
      const el = outputElRef.current;
      if (el && el.textContent !== shown) el.textContent = shown;
      dispatch({
        type: "output",
        len: text.length,
        publicKey: text.includes(PUBLIC_KEY_HEADER),
      });
    },
    [dispatch],
  );

  const setTranslation = useCallback((text: string) => {
    translationRef.current = text;
    const el = translationElRef.current;
    if (el && el.textContent !== text) el.textContent = text;
    setTranslationLen(text.length);
  }, []);

  const addWiper = useCallback((fn: () => void) => {
    extraWipers.current.add(fn);
    return () => {
      extraWipers.current.delete(fn);
    };
  }, []);

  /**
   * Drop every plaintext copy: input, clear-undo buffer, output,
   * translation, the registered holders -- and zeroize the result bytes,
   * which a `setState` cannot release here (it is batched away with the
   * unmount; T-OUTPUT-HEAP-RESIDUE). MUST STAY SYNCHRONOUS: `doMasterLock`
   * unmounts right after it.
   */
  const wipePlaintext = useCallback(() => {
    for (const fn of extraWipers.current) fn();
    inputRef.current = "";
    if (inputElRef.current) inputElRef.current.value = "";
    clearUndoRef.current = null;
    outputRef.current = "";
    if (outputElRef.current) outputElRef.current.textContent = "";
    translationRef.current = "";
    if (translationElRef.current) translationElRef.current.textContent = "";
    const { result } = stateRef.current;
    zeroizeResultBytes(result.binary, result.files);
    // The message password: a JS string cannot be overwritten, so
    // dropping the reference is all there is.
    dispatch({ type: "wiped" });
    // Last: V8 keeps the subject of the last regex match.
    forgetLastRegExpMatch();
  }, [dispatch]);

  // ── input ──────────────────────────────────────────────────────────

  /** The box's onChange: every keystroke. Never repairs armor -- that is
   *  for text that ARRIVES, and would move the caret mid-sentence. */
  const inputChanged = useCallback(
    (text: string) => {
      writeInput(text);
      dispatch({ type: "edited", text: textFacts(text) });
    },
    [writeInput, dispatch],
  );

  /** A paste or text drop: the only path that repairs armor. Detection
   *  runs on the REPAIRED text, so an escaped private key still trips it. */
  const textArrived = useCallback(
    (text: string) => inputChanged(recoverArmorIfNeeded(text)),
    [inputChanged],
  );

  /** Oversized files are refused HERE, before anything reads them: one
   *  big enough to exhaust wasm memory takes the engine and the unlocked
   *  keys down with it (`lib/limits.ts`). */
  const dropFiles = useCallback(
    (dropped: File[]) => {
      const { accepted, rejected } = splitOversizedFiles(dropped);
      dispatch({
        type: "dropped",
        files: accepted,
        encrypted: accepted.some((f) => /\.(gpg|pgp|asc|age)$/i.test(f.name)),
        oversized: oversizedFilesMessage(rejected),
      });
    },
    [dispatch],
  );

  const stashClearUndo = useCallback(() => {
    const { files, recipientIds } = stateRef.current;
    clearUndoRef.current = { input: inputRef.current, files, recipientIds };
    dispatch({ type: "clear-undo", available: true });
  }, [dispatch]);

  const restoreClearUndo = useCallback(() => {
    const snap = clearUndoRef.current;
    clearUndoRef.current = null;
    if (!snap) return dispatch({ type: "clear-undo", available: false });
    writeInput(snap.input);
    // Re-arms the private-key mask: an undo must not drop it.
    dispatch({
      type: "undo-restored",
      text: textFacts(snap.input),
      files: snap.files,
      recipientIds: snap.recipientIds,
    });
  }, [writeInput, dispatch]);

  // ── one-shot deliveries from the panel ─────────────────────────────

  const { pendingAction, onClearPending, intake, onIntakeConsumed } = opts;
  useEffect(() => {
    if (!pendingAction) return;
    const { action, text } = pendingAction;
    // A keyboard mode command has no text: switch, keep the workspace.
    if (text) writeInput(text);
    dispatch({
      type: "opened",
      mode: action,
      text: text ? textFacts(text) : undefined,
      // Opening a message IS the request to read it; encrypt and sign
      // wait for the user to address and send.
      autoRun:
        text && (action === "decrypt" || action === "verify") ? action : null,
    });
    onClearPending?.();
  }, [pendingAction, onClearPending, writeInput, dispatch]);

  const { encryptToKeyId, consume } = nav;
  useEffect(() => {
    if (!encryptToKeyId) return;
    dispatch({ type: "encrypt-to", keyId: encryptToKeyId });
    consume("encryptToKeyId");
  }, [encryptToKeyId, consume, dispatch]);

  useEffect(() => {
    if (!intake) return;
    if (intake.files.length > 0) dropFiles(intake.files);
    else if (intake.text.trim()) textArrived(intake.text);
    onIntakeConsumed?.();
  }, [intake, onIntakeConsumed, dropFiles, textArrived]);

  // ── draft ──────────────────────────────────────────────────────────

  const { restoreDraft, onDraftRestored, onRegisterDraftSource } = opts;
  const restoredRef = useRef(false);
  useEffect(() => {
    if (restoredRef.current || !restoreDraft) return;
    restoredRef.current = true;
    void (async () => {
      const draft = await decryptWorkspaceDraft(restoreDraft);
      if (draft) {
        writeInput(draft.input);
        dispatch({
          type: "restored",
          mode: draft.mode,
          text: textFacts(draft.input),
          recipientIds: draft.selectedRecipientIds,
          keyPick: draft.selectedKeyId,
        });
        writeOutput(draft.output);
      }
      onDraftRestored?.();
    })();
  }, [restoreDraft, onDraftRestored, writeInput, writeOutput, dispatch]);

  // A PULL, read at lock time: nothing durable closes over the text.
  const getDraft = useCallback((): WorkspaceDraft | null => {
    const s = stateRef.current;
    // Never seal pasted private-key armor into the draft.
    if (s.input.key === "private") return null;
    return {
      mode: s.mode,
      input: inputRef.current,
      output: outputRef.current,
      selectedRecipientIds: s.recipientIds,
      selectedKeyId: s.keyPick,
    };
  }, []);

  useEffect(() => {
    if (!onRegisterDraftSource) return;
    onRegisterDraftSource({ getDraft, wipe: wipePlaintext });
    return () => onRegisterDraftSource(null);
  }, [onRegisterDraftSource, getDraft, wipePlaintext]);

  // ── derived ────────────────────────────────────────────────────────

  const isAge = inputIsAge(state);
  const selectedKeyId = resolveKeyId(
    { mode: state.mode, keyPick: state.keyPick, age: isAge },
    myKeys,
    prefs.defaultKeyId,
  );
  const crxKey =
    crxKeys.find((k) => k.extensionId === state.crxKeyPick) ??
    crxKeys.at(0) ??
    null;
  const canCrxSign = prefs.crxSigningEnabled && crxKeys.length > 0;

  const selectPrivateKey = (keyId: string | null) => {
    if (keyId !== selectedKeyId) dispatch({ type: "key-picked", keyId });
  };

  const runContext = (
    how: { unattended?: boolean; cap?: number } = {},
  ): RunContext => ({
    mode: state.mode,
    files: state.files,
    getInput,
    hasText: state.input.nonBlank,
    isAge,
    zipFiles: state.zipFiles,
    recipientIds: state.recipientIds,
    keyId: selectedKeyId,
    myKeys,
    contacts,
    alsoSign: prefs.signWhenEncrypting,
    encryptToSelf: prefs.encryptToSelf,
    defaultKeyId: prefs.defaultKeyId,
    recentRecipients: prefs.recentRecipients,
    password: encryptPasswordReady(state) ? state.encryptPassword : undefined,
    autoDownloadFiles: prefs.autoDownloadFiles,
    autoDownloadText: prefs.autoDownloadText,
    getKeyHandle: session.getKeyHandle,
    unlockWithPasskey: session.unlockWithPasskey,
    unattended: how.unattended ?? false,
    cap: how.cap,
    hiddenCharsConfirmed: false,
  });

  // An extension zip (a single .zip with manifest.json) nudges to Sign.
  const { files } = state;
  useEffect(() => {
    if (files.length !== 1 || !/\.zip$/i.test(files[0].name)) {
      dispatch({ type: "extension-zip", value: false, nudge: false });
      return;
    }
    const run = { cancelled: false };
    void files[0].arrayBuffer().then((buf) => {
      if (run.cancelled) return;
      const value = zipHasManifest(new Uint8Array(buf));
      dispatch({ type: "extension-zip", value, nudge: value && canCrxSign });
    });
    return () => {
      run.cancelled = true;
    };
  }, [files, canCrxSign, dispatch]);

  // Decrypt: scan how the staged message opens (a password-only message
  // gets no key picker) and pick the key it is addressed to. A later
  // manual pick is left alone: this re-runs only when the input changes.
  const scanStaged = useEffectEvent(async (run: { cancelled: boolean }) => {
    const c = runContext();
    try {
      if (!c.isAge) {
        const encryption = await scanMessageEncryption(c);
        if (!run.cancelled) {
          dispatch({ type: "message-encryption", value: encryption });
        }
      }
      const match = await matchDecryptionKey(c);
      if (!run.cancelled && match) selectPrivateKey(match);
    } catch {
      // Not a parseable message yet (still typing/pasting).
    }
  });
  const hasStagedInput = state.files.length > 0 || state.input.nonBlank;
  useEffect(() => {
    if (state.mode !== "decrypt" || !hasStagedInput) return;
    const run = { cancelled: false };
    void scanStaged(run);
    return () => {
      run.cancelled = true;
    };
    // `input.version` stands in for the text, which nothing here holds.
  }, [
    state.mode,
    state.input.version,
    state.files,
    hasStagedInput,
    isAge,
    myKeys,
  ]);

  // ── runs ───────────────────────────────────────────────────────────

  /** Apply an outcome -- unless the staged input moved since `staged`. */
  const settle = (outcome: Outcome, staged = stateRef.current.staged) => {
    if (
      outcome.kind === "done" &&
      outcome.text !== undefined &&
      staged === stateRef.current.staged
    ) {
      writeOutput(outcome.text);
    }
    dispatch({ type: "finished", outcome, staged });
  };

  const run = async (
    start: WorkspaceEvent,
    op: () => Promise<Outcome>,
    lockAfter = true,
  ) => {
    const staged = stateRef.current.staged;
    dispatch(start);
    let outcome: Outcome;
    try {
      outcome = await op();
    } catch (e) {
      outcome = {
        kind: "error",
        error: presentError(e, t("workspace_operation_failed")),
      };
    }
    if (lockAfter) session.lockAllIfNoCache();
    settle(outcome, staged);
  };

  const execute = (how: { unattended?: boolean; cap?: number } = {}) =>
    run({ type: "started", autoRun: how.cap !== undefined }, () =>
      runMode({
        ...runContext(how),
        hiddenCharsConfirmed:
          hiddenConfirmedFor.current === state.input.version,
      }),
    );

  const submitPassword = async () => {
    const prompt = state.prompt;
    if (!prompt) return;
    if (prompt.kind === "message") {
      return run(
        { type: "submitted" },
        () => decryptWithMessagePassword(runContext(), prompt.value),
        false,
      );
    }
    if (prompt.kind === "crx") {
      if (!crxKey) return;
      return run({ type: "submitted" }, () =>
        signCrx(runContext(), crxKey, prompt.value),
      );
    }
    const keyId = prompt.keyId ?? selectedKeyId ?? myKeys.at(0)?.keyId;
    const blob = myKeys.find((k) => k.keyId === keyId);
    if (!blob) return;
    dispatch({ type: "submitted" });
    let rejected: string | null = null;
    try {
      if (!(await session.unlockWithPassword(blob, prompt.value))) {
        rejected = t("workspace_error_wrong_key_password");
      }
    } catch (e) {
      // One-row prompt: the curated sentence only, no detail line.
      rejected = presentError(e, t("workspace_error_unlock_failed")).message;
    }
    if (rejected !== null)
      return settle({ kind: "rejected", message: rejected });
    await execute();
  };

  const executeCrxSign = async () => {
    if (state.mode !== "sign" || state.files.length !== 1) return;
    if (!crxKey) {
      return settle({
        kind: "error",
        error: { message: t("workspace_error_select_crx_key") },
      });
    }
    if (crxKey.protection.method === "password") {
      return dispatch({ type: "prompted", kind: "crx" });
    }
    await run({ type: "started" }, () => signCrx(runContext(), crxKey));
  };

  const verifyCrxInput = async () => {
    if (state.files.length === 0) return;
    await run({ type: "started" }, () => verifyCrx(runContext()), false);
  };

  const binaryResult = !!state.result.binary && state.output.len === 0;

  return {
    state,
    dispatch,
    myKeys,
    contacts,
    crxKeys,
    canCrxSign,
    isAge,
    selectedKeyId,
    crxKeyId: crxKey?.extensionId ?? null,
    passwordReady: encryptPasswordReady(state),
    inputElRef,
    outputElRef,
    translationElRef,
    getInput,
    getOutput,
    getTranslation,
    setTranslation,
    hasTranslation: translationLen > 0,
    addWiper,
    inputChanged,
    textArrived,
    dropFiles,
    stashClearUndo,
    restoreClearUndo,
    selectPrivateKey,
    execute: () => execute(),
    /** A context-menu auto-run: no prompts, capped output. */
    executeUnattended: () =>
      execute({ unattended: true, cap: AUTO_RUN_MAX_BYTES }),
    /** A re-run of the user's own run: no prompts, not capped. */
    executeWithoutPrompts: () => execute({ unattended: true }),
    executeCrxSign,
    verifyCrxInput,
    submitPassword,
    /** "Sign anyway": sign this exact text as it is. */
    signWithHiddenChars: () => {
      hiddenConfirmedFor.current = state.input.version;
      void execute();
    },
    matchDecryptionKey: () => matchDecryptionKey(runContext()),
    outputName: () => outputName(runContext(), binaryResult),
    triggerDownload: () =>
      download(runContext(), {
        files: state.result.files,
        binary: state.result.binary,
        text: getOutput(),
      }),
  };
}

export type Workspace = ReturnType<typeof useWorkspace>;
