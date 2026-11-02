import type { WorkspaceState } from "./workspace-state";

const isCrx = (name: string) => /\.crx$/i.test(name);

/** What the workspace shows and allows, derived from its state alone. */
export function deriveWorkspaceView(
  s: WorkspaceState,
  {
    canCrxSign,
    passwordReady,
    crxSigningEnabled,
  }: {
    canCrxSign: boolean;
    passwordReady: boolean;
    crxSigningEnabled: boolean;
  },
) {
  const loading = s.run.kind === "running";
  const done = s.run.kind === "done";
  const error = s.run.kind === "error" ? s.run.error : null;
  const hasOutputText = s.output.len > 0;
  const hasInput = s.files.length > 0 || s.input.len > 0;
  const canEncrypt = s.recipientIds.length > 0 || passwordReady;

  // Password-only / unencrypted messages need no key: no picker of wrong keys.
  const passwordOnlyMessage =
    s.mode === "decrypt" &&
    s.messageEncryption?.password === true &&
    !s.messageEncryption.publicKey;
  const unencryptedMessage =
    s.mode === "decrypt" && s.messageEncryption?.encrypted === false;
  const needsPrivateKey =
    (s.mode === "decrypt" && !passwordOnlyMessage && !unencryptedMessage) ||
    s.mode === "sign";

  const crxSignAvailable =
    canCrxSign && s.mode === "sign" && s.isExtensionZip && !done;
  const showCrxSign = crxSignAvailable && (s.signKindPick ?? "crx") === "crx";
  const showCrxVerify =
    crxSigningEnabled &&
    s.mode === "verify" &&
    s.files.length === 1 &&
    isCrx(s.files[0].name);
  const crxResult =
    done && s.result.files.length === 1 && isCrx(s.result.files[0].name)
      ? s.result.files[0]
      : null;

  const showFullOutput =
    done && (s.mode === "decrypt" || s.mode === "verify") && hasOutputText;
  // Reply needs a known signer on an encrypted message: amber is never private mail.
  const replyTo =
    showFullOutput &&
    s.mode === "decrypt" &&
    s.result.verdict?.tone === "success"
      ? s.result.verdict
      : null;

  const mainActionShown =
    !showFullOutput &&
    s.prompt === null &&
    !crxResult &&
    !showCrxVerify &&
    !showCrxSign &&
    !(done && s.mode !== "verify");
  const canRun =
    mainActionShown && !loading && !(s.mode === "encrypt" && !canEncrypt);
  const resultHasOutput = done && hasOutputText && !loading;
  const hasDownload =
    done &&
    !loading &&
    s.mode !== "verify" &&
    (s.result.files.length > 0 || !!s.result.binary || hasOutputText);

  return {
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
    canReply: replyTo !== null,
    canRun,
    resultHasOutput,
    hasDownload,
  };
}
