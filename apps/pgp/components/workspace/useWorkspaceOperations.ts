import { useEffect, useRef } from "react";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { PresentedError } from "../../lib/errors/present";
import type {
  DecryptOptions,
  DecryptResult,
  EncryptInput,
} from "../../lib/pgp/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { NewHistoryEntry } from "../../lib/storage/history";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { FileResult } from "../../lib/utils/download";
import type { SignedResult } from "./signature-summary";
import type { WorkspaceState } from "./useWorkspaceState";
import * as ageOps from "../../lib/age/operations";
import { signZipWithCrxKey, verifyCrxFile } from "../../lib/crx/operations";
import {
  buildEncryptRecipients,
  resolveSelectedRecipients,
  sshPasswordReason,
  toSelectedRecipient,
} from "../../lib/encrypt-recipients";
import { AppError } from "../../lib/errors/app-error";
import { presentError } from "../../lib/errors/present";
import { t, tn } from "../../lib/i18n";
import { MAX_VERIFY_FILE_BYTES, MAX_VERIFY_FILE_LABEL } from "../../lib/limits";
import * as pgpOps from "../../lib/pgp/operations";
import { isWebAuthnCancel } from "../../lib/protection/webauthn-prf";
import { updateRecentRecipients } from "../../lib/recipient-ordering";
import { contactRecipients } from "../../lib/storage/contact-recipients";
import { recordHistory } from "../../lib/storage/history";
import { isPgpRecord, isSshRecord } from "../../lib/storage/key-kind";
import { savePreferences } from "../../lib/storage/preferences";
import { toast } from "../../lib/toast";
import {
  downloadBinary,
  downloadResults,
  downloadText,
} from "../../lib/utils/download";
import {
  displayFileName,
  hasHiddenCharacters,
} from "../../lib/utils/file-name";
import { formatFileSize } from "../../lib/utils/formatting";
import {
  displayUserId,
  formatKeyDisplayName,
  parseUserId,
} from "../../lib/utils/key-naming";
import {
  isZipArchive,
  zipFiles as zipFilesToArchive,
} from "../../lib/utils/zip";
import { outputFileName } from "./output-name";
import { selectionEngine } from "./recipient-engine";
import {
  mixedBatchNote,
  signatureNote,
  signedForOthers,
  summariseBatch,
} from "./signature-summary";

interface WorkspaceOperationsOptions {
  s: WorkspaceState;
  myKeys: ProtectedKeyBlob[];
  contacts: PublicContactKey[];
  crxKeys?: CrxSigningKeyBlob[];
  crxSigningEnabled?: boolean;
  allPublicKeys: (ProtectedKeyBlob | PublicContactKey)[];
  getKeyHandle: (keyId: string) => number | null;
  onUnlockWithPassword: (
    blob: ProtectedKeyBlob,
    password: string,
  ) => Promise<boolean>;
  onUnlockWithPasskey: (
    blob: ProtectedKeyBlob,
  ) => Promise<boolean | "cancelled">;
  autoDownloadFiles?: boolean;
  autoDownloadText?: boolean;
  onOperationComplete?: () => void;
  /** The user's configured default key: preferred as the
   *  encrypt-to-self key (see resolveSelfKey). */
  defaultKeyId?: string | null;
}

/**
 * The workspace's operation layer: runs encrypt/decrypt/sign/verify
 * against the state owned by `useWorkspaceState`, including key
 * unlocking, result downloads, and decryption-key auto-selection.
 * `WorkspaceView` stays a pure rendering layer on top of this.
 */
export function useWorkspaceOperations({
  s,
  myKeys,
  contacts,
  crxKeys = [],
  allPublicKeys,
  getKeyHandle,
  onUnlockWithPassword,
  onUnlockWithPasskey,
  autoDownloadFiles,
  autoDownloadText,
  onOperationComplete,
  defaultKeyId,
}: WorkspaceOperationsOptions) {
  // Change the active private key. A pending password prompt belongs to the
  // *previous* key, so drop it -- otherwise switching to a passkey-protected
  // key leaves the password dialog stuck open and blocks the passkey flow.
  function selectPrivateKey(keyId: string | null) {
    if (keyId === s.selectedKeyId) return;
    s.setSelectedKeyId(keyId);
    s.setNeedsPassword(false);
    s.setPasswordInput("");
    s.setPasswordError(null);
    // A completed sign/decrypt output belongs to the previous key; clear it
    // so switching keys lets the user re-run rather than download stale output.
    s.resetOutput();
  }

  // Default-select the private key the message is actually encrypted to, so
  // the user doesn't have to guess which of their keys decrypts it. Runs when
  // the message or key set changes; a later manual pick is left untouched.
  useEffect(() => {
    if (s.mode !== "decrypt") return;
    const hasContent = s.files.length > 0 || s.hasTrimmedInput;
    // NOT gated on `myKeys.length` any more. A password-encrypted message
    // is readable with no keys at all, and the scan below is what tells
    // the UI to stop offering a key picker for one -- so returning early
    // on an empty keyring would leave the user staring at "No keys yet"
    // for a message that never wanted a key.
    if (!hasContent) return;

    // Object guard (not a bare `let`) so a stale async run can't clobber a
    // newer selection after the effect re-runs.
    const run = { cancelled: false };
    void (async () => {
      try {
        const bytes = async () =>
          s.files.length > 0
            ? new Uint8Array(await s.files[0].arrayBuffer())
            : new TextEncoder().encode(s.getInput());

        // Two engines, two matchers. An age file has no OpenPGP packet
        // header at all, so the PGP matcher throws on it, the catch below
        // swallows that, and whatever PGP key was selected would stay
        // selected -- the one key that certainly cannot read it. Ask the
        // engine that owns the format instead.
        if (s.inputIsAge) {
          const sshKeys = myKeys.filter(isSshRecord);
          if (sshKeys.length === 0) return;
          const index = await ageOps.selectDecryptionKey(
            await bytes(),
            sshKeys.map((k) => k.publicKeyArmored),
          );
          const match = index === null ? null : sshKeys[index]?.keyId;
          if (!run.cancelled && match && match !== s.selectedKeyId) {
            selectPrivateKey(match);
          }
          return;
        }

        const input = await stagedPgpInput();

        // How this message can be opened, for the UI: a password-only
        // message gets no key picker (a picker whose every choice is
        // wrong is worse than none), and the prompt asks for the right
        // thing. `executeDecrypt` re-derives this rather than reading it
        // back, because a paste followed straight by a click would race
        // this effect.
        const encryption = await pgpOps.messageEncryption(input);
        // Guarded, not early-returned: an early return here narrows
        // `run.cancelled` to `false` for the rest of the closure, and the
        // match guard below would then be flagged as always-true even
        // though the await between them is exactly when it flips.
        if (!run.cancelled) s.setMessageEncryption(encryption);

        if (myKeys.length === 0) return;
        const match = await pgpOps.selectDecryptionKey(
          input,
          myKeys.map((k) => k.publicKeyArmored),
        );
        if (!run.cancelled && match && match !== s.selectedKeyId) {
          selectPrivateKey(match);
        }
      } catch {
        // Not a parseable message of either engine yet (still
        // typing/pasting) -- ignore.
      }
    })();
    return () => {
      run.cancelled = true;
    };
    // `inputVersion` stands in for the message text: it bumps on every
    // change so this still re-runs as the user pastes, but nothing here
    // closes over the plaintext (see the input block in useWorkspaceState).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [s.mode, s.inputVersion, s.files, s.inputIsAge, myKeys]);

  // The signer for any PGP operation: the current selection when it is
  // an OpenPGP key, else the first one. SSH identities are never
  // candidates -- age has no signing operation.
  function resolvePgpSignerId(): string | null {
    const pgpKeys = myKeys.filter(isPgpRecord);
    if (s.selectedKeyId && pgpKeys.some((k) => k.keyId === s.selectedKeyId)) {
      return s.selectedKeyId;
    }
    return pgpKeys[0]?.keyId ?? null;
  }

  function findSigner(signerKeyId: string | null) {
    if (!signerKeyId) return null;
    const hex = signerKeyId.toUpperCase();
    // Any of a contact's keys, not just its first: a signature from a
    // person's second key is still that person.
    return (
      contacts.find((c) =>
        contactRecipients(c).some((r) => r.keyId.toUpperCase().endsWith(hex)),
      ) ??
      myKeys.find((k) => k.keyId.toUpperCase().endsWith(hex)) ??
      null
    );
  }

  /** A signer as a note names them: the name part of their display
   *  name, else the 16-hex key id. */
  function signerName(keyId: string): string {
    const signer = findSigner(keyId);
    const userId = signer ? displayUserId(signer) : undefined;
    return userId ? parseUserId(userId).name : keyId.slice(-16);
  }

  /** A signer card for someone we hold no key for. */
  function placeholderSigner(
    keyId: string,
    name = t("workspace_unknown_signer"),
  ): PublicContactKey {
    return {
      keyId,
      userIds: [name],
      algorithm: "",
      armoredPublicKey: "",
      addedAt: 0,
      lastUsedAt: 0,
    };
  }

  /** The signer card for a single "valid" or "unknown_key" result.
   *  `extraNote` is appended to what the card says about it. */
  function showSignature(
    result: SignedResult,
    extraNote: string | null = null,
  ) {
    if (result.signatureStatus === "valid") {
      // A key retired since signing still verifies -- it was good when
      // the signature says it was made -- and a message signed for
      // someone else verifies too, forwarded or not. Both are amber,
      // never green.
      const forOthers = signedForOthers(
        result,
        myKeys.map((k) => k.keyId),
      );
      const caveat = forOthers
        ? t("workspace_signature_verified_not_for_you")
        : !result.signerKeyCurrent
          ? t("workspace_signature_verified_retired")
          : null;
      s.setSignatureTone(caveat ? "warning" : "success");
      s.setStatusText(t("workspace_signature_verified"));
      const signer = findSigner(result.signerKeyId);
      if (signer) {
        // The signature is good; whether the key is the person it names
        // is a separate question, and only the user can answer it (Mark
        // as verified, on the key's details). Said quietly -- most keys
        // are never marked, and the verdict itself stays green.
        const unvouched =
          "armoredPublicKey" in signer &&
          !signer.verified &&
          !myKeys.some((k) => k.keyId === signer.keyId)
            ? t("workspace_signer_not_verified")
            : null;
        s.setVerifiedSigner(signer);
        s.setSignerCaveat(caveat);
        s.setSignatureNote(
          [signatureNote(result, signerName, forOthers), unvouched, extraNote]
            .filter(Boolean)
            .join(" · ") || null,
        );
      }
    } else if (result.signatureStatus === "unknown_key") {
      // Signed, but we don't hold the signer's public key. Show the same
      // signer card as a verified signature, in an amber "can't verify"
      // tone, with the key id so the user can go and fetch the key.
      s.setSignatureTone("warning");
      s.setVerifiedSigner(placeholderSigner(result.signerKeyId ?? ""));
      s.setStatusText(t("workspace_status_signer_unknown"));
    }
  }

  /** One verdict for a batch of files -- see `summariseBatch`. */
  function showBatchSignatures(
    batch: { name: string; result: SignedResult }[],
  ) {
    const summary = summariseBatch(
      batch,
      myKeys.map((k) => k.keyId),
    );
    if (summary.kind === "unsigned") return;
    if (summary.kind === "same") {
      showSignature(summary.result);
      return;
    }
    s.setSignatureTone("warning");
    s.setVerifiedSigner(
      placeholderSigner("", t("workspace_files_mixed_signers")),
    );
    s.setStatusText(mixedBatchNote(summary.files, signerName));
  }

  /** Display names of the currently selected recipients, for encrypt
   *  download names ("report.pdf.to-alice.2026-07-16-1432.gpg"). */
  function selectedRecipientNames(): string[] {
    return s.selectedRecipientIds
      .map((id) => allPublicKeys.find((k) => k.keyId === id))
      .filter((k) => k !== undefined)
      .map((k) => {
        const uid = k.userIds[0];
        return uid ? formatKeyDisplayName(uid).name : k.keyId.slice(-8);
      });
  }

  /** The keys behind the current recipient chips. */
  function selectedRecipientKeys() {
    // Contacts before own keys -- see `resolveSelectedRecipients`. A
    // contact's keyId is its head recipient's fingerprint, so an own key
    // with that fingerprint used to win the lookup and silently drop the
    // contact's other recipients.
    return resolveSelectedRecipients(s.selectedRecipientIds, contacts, myKeys);
  }

  /** Which engine the current selection encrypts with -- and therefore
   *  which extension the ciphertext gets. Null while nothing is selected;
   *  the picker guarantees the selection is never mixed. */
  function selectedEngine() {
    return selectionEngine(selectedRecipientKeys());
  }

  function currentOutputName(): string {
    // Encrypt downloads carry who-and-when in the name, so a Downloads
    // folder of ciphertext stays identifiable weeks later.
    return outputFileName(
      s.mode,
      stagedFiles().map((f) => f.name),
      s.zipFiles,
      {
        recipients: selectedRecipientNames(),
        engine: selectedEngine(),
        binary: !!s.binaryOutput && !s.hasOutput,
      },
    );
  }

  /**
   * Return the WASM handle for `keyId`, unlocking if needed. Password
   * keys flip the inline password prompt and return null; the caller
   * retries via `handlePasswordSubmit` once the user has typed it.
   */
  async function ensureUnlocked(keyId: string): Promise<number | null> {
    const cached = getKeyHandle(keyId);
    if (cached !== null) return cached;
    // Nobody pressed anything: a key that closed since the auto-run
    // checked it stays closed rather than raising a ceremony or a prompt.
    if (unattendedRef.current) return null;

    const blob = myKeys.find((k) => k.keyId === keyId);
    if (!blob) return null;

    if (blob.protection.method === "passkey") {
      const result = await onUnlockWithPasskey(blob);
      if (result === "cancelled") return null;
      if (!result) {
        throw new AppError("passkey-failed", "Passkey authentication failed.");
      }
      return getKeyHandle(keyId);
    }

    s.setNeedsPassword(true);
    s.setPasswordInput("");
    s.setPasswordError(null);
    return null;
  }

  /**
   * What an encrypt actually takes in: the staged files, plus -- when a
   * message was written alongside them -- that message as `msg.txt`.
   * Built at the moment of the operation, never kept: the text stays in
   * the message box as the one copy, and this blob goes with the run.
   */
  function stagedFiles(): File[] {
    if (s.mode !== "encrypt" || s.files.length === 0 || !s.hasTrimmedInput) {
      return s.files;
    }
    const taken = new Set(s.files.map((f) => f.name));
    let name = "msg.txt";
    for (let n = 2; taken.has(name); n++) name = `msg-${n}.txt`;
    return [...s.files, new File([s.getInput()], name, { type: "text/plain" })];
  }

  async function resolveFileBytes(
    files: File[] = s.files,
  ): Promise<Uint8Array> {
    if (files.length > 1 && s.zipFiles) {
      return zipFilesToArchive(files);
    }
    return new Uint8Array(await files[0].arrayBuffer());
  }

  function triggerDownload() {
    if (s.fileResults.length > 0) {
      downloadResults(s.fileResults);
      return;
    }
    if (s.binaryOutput) {
      downloadBinary(s.binaryOutput, currentOutputName());
    } else {
      downloadText(s.getOutput(), currentOutputName());
    }
  }

  function maybeAutoDownload(
    isFileInput: boolean,
    data?: { text?: string; binary?: Uint8Array } | { results: FileResult[] },
  ) {
    if (!(isFileInput ? autoDownloadFiles : autoDownloadText)) return;
    // The preference is for results the user asked for. An auto-run's
    // input is whatever a web page put in the selection, so its output
    // goes to disk only when they press Download.
    if (unattendedRef.current) return;
    if (data && "results" in data) {
      downloadResults(data.results);
    } else if (data) {
      if (data.binary) {
        downloadBinary(data.binary, currentOutputName());
      } else {
        downloadText(data.text ?? "", currentOutputName());
      }
    } else {
      triggerDownload();
    }
  }

  /** File metadata for history capture -- names and sizes only. */
  function historyFileMeta(files: File[] = s.files) {
    return files.map((f) => ({ name: f.name, size: f.size }));
  }

  /** Fire-and-forget history capture: never delays the operation, but a
   *  storage failure (quota / device full) surfaces one deduped error
   *  toast -- a user who believes history is recording may delete the
   *  original message trusting the copy exists. */
  function captureHistory(entry: NewHistoryEntry): void {
    void recordHistory(entry).then((result) => {
      if (result === "failed") {
        toast.error(t("workspace_history_save_failed"), {
          id: "history-save-failed",
        });
      }
    });
  }

  /**
   * True while an operation runs without a click (a context-menu
   * auto-run). It never asks for a secret -- no ceremony, no password
   * prompt -- and never writes to disk; everything else is the same run.
   * Checked at the point of each prompt rather than decided up front,
   * because a key can close between the auto-run's check and the decrypt.
   */
  const unattendedRef = useRef(false);

  const executeUnattended = async () => {
    unattendedRef.current = true;
    try {
      await execute();
    } finally {
      unattendedRef.current = false;
    }
  };

  /**
   * Run `operation`, and keep what it wrote only if the staged input is
   * still what it read. A file dropped, removed or retyped while it ran
   * would otherwise end up listed under a verdict -- green, even -- for
   * input that was never checked. Writes and the reset land in the same
   * React batch, so the stale result is never painted.
   */
  async function forCurrentInput<T>(operation: () => Promise<T>): Promise<T> {
    const generation = s.stagedGeneration();
    try {
      return await operation();
    } finally {
      if (s.stagedGeneration() !== generation) s.resetOutput();
    }
  }

  const execute = () => forCurrentInput(executeNow);

  const executeNow = async () => {
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
      s.setError(presentError(e, t("workspace_operation_failed")));
    } finally {
      s.setLoading(false);
      onOperationComplete?.();
    }
  };

  async function executeEncrypt() {
    const recipients = selectedRecipientKeys();
    // A password is a way for the message to be openable, so it
    // satisfies this gate on its own -- that IS the `gpg -c` case, and
    // requiring a recipient for it would make password-only encryption
    // unreachable. The engine refuses "no recipients and no password"
    // independently, so a message nobody can open cannot be produced
    // even if this check is wrong.
    if (recipients.length === 0 && !s.encryptPasswordReady) {
      s.setError({ message: t("workspace_error_need_recipient_or_password") });
      return;
    }

    // Which engine this message is in, decided by the recipients. It
    // also decides what happens below: age has no signing operation, so
    // the persisted "Sign" preference must not drag the message onto the
    // PGP signing path (nor pull a PGP key in as the signer).
    const isAge = selectedEngine() === "ssh";

    // A password and an age message are mutually exclusive, and getting
    // this wrong is SILENT: the age branch below never sees
    // `messagePassword`, so without this the user gets a .age file with
    // no password on it while the Password badge sits lit above the
    // button. They would only find out when the recipient asked what the
    // password was for. The picker dims SSH recipients once a password
    // is set and the badge disables once SSH ones are picked, so this is
    // the backstop for a state the UI should not allow, not the main
    // defence.
    if (isAge && s.encryptPasswordReady) {
      s.setError({ message: sshPasswordReason() });
      return;
    }

    // With encrypt-to-self on, the user's own key rides along so they
    // can decrypt their own ciphertext later. When no own key of this
    // engine exists, `selfExcluded` comes back true -- and WorkspaceView
    // renders that same answer as a line under the toggle before the
    // user presses the button, so this path never has to explain it
    // after the fact.
    // Signing is OpenPGP-only, and `selectedKeyId` doubles as the
    // decrypt selection -- so it can point at an SSH identity, which has
    // no signature format at all. Resolve it against the PGP keys only,
    // and use the SAME answer for the recipient set and for the handle
    // below, so the key the message says signed it is the one that did.
    const signerKeyId = s.alsoSign && !isAge ? resolvePgpSignerId() : null;
    const { recipientPublicKeys, selfKeyId, engine, refusal } =
      buildEncryptRecipients({
        // One selected contact can carry several keys; the message goes
        // to all of them (see toSelectedRecipient).
        recipients: recipients.map(toSelectedRecipient),
        encryptToSelf: s.encryptToSelf,
        ownKeys: myKeys,
        signingKeyId: signerKeyId,
        defaultKeyId,
      });

    // Backstop only: the picker disables the other engine's options, so
    // a mixed set cannot normally be assembled. If one ever is, refuse
    // rather than encrypt to the subset that happens to work.
    if (refusal !== null) {
      s.setError({ message: refusal });
      return;
    }

    // `engine` is the same answer arrived at inside the recipient
    // assembly; if the two ever disagreed, the assembly's is the one the
    // ciphertext follows.
    if (engine !== null && (engine === "ssh") !== isAge) {
      s.setError({ message: t("workspace_error_engine_mismatch") });
      return;
    }

    let signingHandle: number | null = null;
    // Never take the signing path for age, even with the persisted
    // "Sign when encrypting" preference on: age has no signature format,
    // so there is nothing to sign WITH and the PGP signer would be a
    // wrong-engine key. The toggle stays visible and dimmed with that
    // reason in WorkspaceView.
    if (signerKeyId) {
      const handle = await ensureUnlocked(signerKeyId);
      if (handle === null) return;
      signingHandle = handle;
    }

    if (isAge) {
      s.setStatusText(t("workspace_status_age_encrypted"));
    }

    // The message password, when the badge is armed. `undefined` -- not
    // `""` -- when it is not: an empty string is a password, and passing
    // one would produce a message "protected" by nothing.
    //
    // NOT offered on the age path: age has no password mode, and adding
    // one would mean inventing a construction rather than using a
    // format's own. The badge is hidden for an age message in the view.
    const messagePassword = s.encryptPasswordReady
      ? s.encryptPassword
      : undefined;

    const doEncrypt = async (input: EncryptInput) => {
      if (isAge) {
        return ageOps.encryptToRecipients({
          input,
          recipients: recipientPublicKeys,
        });
      }
      if (signingHandle !== null) {
        return pgpOps.encryptWithSigningHandle({
          input,
          recipientPublicKeys,
          signingKeyHandle: signingHandle,
          password: messagePassword,
        });
      }
      return pgpOps.encrypt({
        input,
        recipientPublicKeys,
        password: messagePassword,
      });
    };

    // Attachments plus a written message: the message rides along as a
    // file of its own (`stagedFiles`).
    const files = stagedFiles();
    const isFileInput = files.length > 0;

    if (isFileInput && files.length > 1 && !s.zipFiles) {
      const results: FileResult[] = [];
      for (const file of files) {
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
        results.push({
          name: outputFileName("encrypt", [file.name], false, {
            recipients: selectedRecipientNames(),
            engine: engine,
          }),
          data,
        });
      }
      s.setFileResults(results);
      const totalSize = results.reduce((sum, r) => sum + r.data.length, 0);
      s.setStatusText(
        tn("workspace_files_encrypted", results.length, {
          size: formatFileSize(totalSize),
        }),
      );
      s.setOperationDone(true);
      maybeAutoDownload(true, { results });
    } else if (isFileInput) {
      const bytes = await resolveFileBytes(files);
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
      if (files.length > 1 && s.zipFiles) {
        s.setStatusText(tn("workspace_files_zipped_encrypted", files.length));
      }
      s.setOperationDone(true);
      maybeAutoDownload(true, {
        text: typeof result === "string" ? result : undefined,
        binary: typeof result !== "string" ? result : undefined,
      });
    } else {
      const result = await doEncrypt({ kind: "text", text: s.getInput() });
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

    // The message password was for THIS message. Holding on to it would
    // quietly arm the next one with the same secret, so it goes the
    // moment it has been used; the badge drops with it and the next
    // message asks again. (On failure it stays, so a retry needs no
    // retyping.)
    if (messagePassword !== undefined) s.setEncryptPassword("");

    // Record the FINAL recipient set: when encrypt-to-self rode the
    // user's own key along, history shows it too.
    //
    // One entry per selected CONTACT, not per key: history answers "who
    // did I send this to", and a contact holding three SSH keys is one
    // person. Expanding it to three entries would render as "To alice,
    // , " -- ContactRecipient carries no name -- and would report three
    // recipients for one reader. `k.keyId` is the contact record id,
    // which equals its first key's fingerprint, so the reference stays a
    // real fingerprint.
    const historyRecipients = recipients.map((k) => ({
      fingerprint: k.keyId,
      name: k.userIds[0] ?? "",
    }));
    const selfKey =
      selfKeyId === null ? null : myKeys.find((k) => k.keyId === selfKeyId);
    if (selfKey) {
      historyRecipients.push({
        fingerprint: selfKey.keyId,
        name: selfKey.userIds[0] ?? "",
      });
    }
    // Fire-and-forget: capture must never delay showing the result.
    captureHistory({
      op: "encrypt",
      recipients: historyRecipients,
      // age produces no signature, ever -- recorded as a fact about the
      // message rather than inferred from a handle that is null for two
      // different reasons.
      signed: !isAge && signingHandle !== null,
      ...(isFileInput
        ? { files: historyFileMeta(files) }
        : { content: s.getInput() }),
    });

    // A successful encrypt promotes its recipients in the picker's
    // recency ordering (selected ones only -- not the auto self key).
    const updatedRecents = updateRecentRecipients(
      s.recentRecipients,
      recipients.map((k) => k.keyId),
    );
    s.setRecentRecipients(updatedRecents);
    void savePreferences({ recentRecipients: updatedRecents });
  }

  /**
   * Decrypt an age message with an unlocked SSH identity.
   *
   * Deliberately not folded into the PGP path: there are no verification
   * keys to pass (age messages carry no signature), so there is no
   * signature status to report and no signer card to show -- the
   * branches would be empty rather than shared. The error hygiene IS
   * shared, and matters for the same reason it does there: a failure
   * must never leave plaintext from a previous run on screen.
   */
  async function executeDecryptAge(keyHandle: number) {
    const isFileInput = s.files.length > 0;
    try {
      if (isFileInput && s.files.length > 1) {
        const results: FileResult[] = [];
        for (const file of s.files) {
          const bytes = new Uint8Array(await file.arrayBuffer());
          const data = await ageOps.decryptWithHandle({
            input: { kind: "binary", binaryMessage: bytes },
            keyHandle,
          });
          results.push({
            name: outputFileName("decrypt", [file.name], false),
            data:
              typeof data === "string" ? new TextEncoder().encode(data) : data,
          });
        }
        s.setFileResults(results);
        const totalSize = results.reduce((sum, r) => sum + r.data.length, 0);
        s.setStatusText(
          tn("workspace_files_decrypted", results.length, {
            size: formatFileSize(totalSize),
          }),
        );
        s.setOperationDone(true);
        maybeAutoDownload(true, { results });
        return;
      }

      const data = await ageOps.decryptWithHandle({
        input: isFileInput
          ? {
              kind: "binary",
              binaryMessage: new Uint8Array(await s.files[0].arrayBuffer()),
            }
          : { kind: "armored", armoredMessage: s.getInput() },
        keyHandle,
      });
      if (typeof data === "string") {
        s.setOutput(data);
      } else if (isZipArchive(data)) {
        s.setBinaryOutput(data);
        s.setStatusText(t("workspace_status_decrypted_archive"));
      } else {
        s.setBinaryOutput(data);
      }
      s.setOperationDone(true);
      maybeAutoDownload(isFileInput, {
        text: typeof data === "string" ? data : undefined,
        binary: typeof data === "string" ? undefined : data,
      });
    } catch (err) {
      s.setOutput("");
      s.setBinaryOutput(undefined);
      s.setFileResults([]);
      s.setOperationDone(false);
      s.setVerifiedSigner(null);
      s.setError(presentError(err, t("workspace_error_decrypt_failed_ssh")));
    }
  }

  /** The staged message, in the shape the PGP ops take. */
  /**
   * The user's key the staged message is addressed to, or null when none
   * of theirs is (or it is not a message either engine can read). The
   * same question the default-selection effect above asks, for callers
   * that need the answer rather than the side effect.
   */
  async function matchDecryptionKey(): Promise<string | null> {
    if (s.inputIsAge) {
      const sshKeys = myKeys.filter(isSshRecord);
      if (sshKeys.length === 0) return null;
      const bytes =
        s.files.length > 0
          ? new Uint8Array(await s.files[0].arrayBuffer())
          : new TextEncoder().encode(s.getInput());
      const index = await ageOps.selectDecryptionKey(
        bytes,
        sshKeys.map((k) => k.publicKeyArmored),
      );
      return index === null ? null : (sshKeys[index]?.keyId ?? null);
    }
    if (myKeys.length === 0) return null;
    return pgpOps.selectDecryptionKey(
      await stagedPgpInput(),
      myKeys.map((k) => k.publicKeyArmored),
    );
  }

  async function stagedPgpInput(): Promise<DecryptOptions["input"]> {
    return s.files.length > 0
      ? {
          kind: "binary",
          binaryMessage: new Uint8Array(await s.files[0].arrayBuffer()),
        }
      : { kind: "armored", armoredMessage: s.getInput() };
  }

  /**
   * Decide how this message wants to be opened, then open it.
   *
   * THE KEY WINS WHEN ONE OF THE USER'S KEYS ACTUALLY MATCHES. A message
   * can carry both a password packet (SKESK) and recipient packets
   * (PKESK); asking which to use would put a question in front of a case
   * where the answer is obvious, and the key path is also the one that
   * verifies the signature against a recipient we know. The password is
   * the FALLBACK -- taken when the message offers one and no key of ours
   * is named by it, which is the whole `gpg -c` case.
   *
   * Detection happens here rather than being read off the effect's state
   * on purpose: that effect is async and a paste followed immediately by
   * a click would race it. It is a scan of the packet headers in front of
   * the encrypted container -- cheap enough to redo, and correctness is
   * not worth trading for it.
   */
  async function executeDecrypt() {
    if (s.inputIsAge) {
      // age has no password mode at all; it needs an SSH identity.
      if (!s.selectedKeyId) {
        s.setError({ message: t("workspace_error_select_decryption_key") });
        return;
      }
      const ageHandle = await ensureUnlocked(s.selectedKeyId);
      if (ageHandle === null) return;
      await executeDecryptAge(ageHandle);
      return;
    }

    const input = await stagedPgpInput();
    // A failure here means the input is not a message we can even read
    // the headers of. Fall through to the key path, whose errors already
    // say so properly.
    const encryption = await pgpOps.messageEncryption(input).catch(() => null);

    if (encryption?.password) {
      const keyMatch = encryption.publicKey
        ? await pgpOps
            .selectDecryptionKey(
              input,
              myKeys.map((k) => k.publicKeyArmored),
            )
            .catch(() => null)
        : null;
      if (!keyMatch) {
        if (unattendedRef.current) return;
        // Ask for the MESSAGE password. Same inline row the key-unlock
        // prompt uses -- one password affordance in this workspace, not
        // two that look alike and mean different things; the placeholder
        // is what says which is being asked for.
        s.setPendingPasswordDecrypt(true);
        s.setNeedsPassword(true);
        s.setPasswordInput("");
        s.setPasswordError(null);
        return;
      }
    }

    if (!s.selectedKeyId) {
      s.setError({ message: t("workspace_error_select_decryption_key") });
      return;
    }
    const keyHandle = await ensureUnlocked(s.selectedKeyId);
    if (keyHandle === null) return;

    const failure = await runPgpDecrypt((one) =>
      pgpOps.decryptWithHandle({
        input: one,
        keyHandle,
        verificationPublicKeys: pgpVerificationKeys(),
      }),
    );
    if (failure) s.setError(failure);
  }

  /** Every public key a signature could be checked against -- every key
   *  of every PGP contact, not only each contact's first. */
  function pgpVerificationKeys(): string[] {
    return [
      ...myKeys.filter(isPgpRecord).map((k) => k.publicKeyArmored),
      ...contacts
        .filter((c) => !isSshRecord(c))
        .flatMap((c) => contactRecipients(c).map((r) => r.armored)),
    ];
  }

  /**
   * Run a PGP decrypt and render everything that follows from it.
   *
   * `decryptOne` is the ONLY difference between opening the message with
   * a key and opening it with a password: same multi-file loop, same
   * text/binary sniffing, same signature handling, same auto-download,
   * same failure teardown. Passing the call in rather than duplicating
   * the body is what stops the password path quietly drifting -- and it
   * would drift silently, because everything below this line is the part
   * a user notices and none of it is engine-specific.
   */
  async function runPgpDecrypt(
    decryptOne: (input: DecryptOptions["input"]) => Promise<DecryptResult>,
  ): Promise<PresentedError | null> {
    /** A tampered signature anywhere fails the whole operation. */
    const refuseInvalid = (result: SignedResult) => {
      if (result.signatureStatus === "invalid") {
        throw new Error(
          "Signature verification FAILED - this message may have been tampered with",
        );
      }
    };
    const handleSig = (result: SignedResult) => {
      refuseInvalid(result);
      showSignature(result);
    };

    const isFileInput = s.files.length > 0;

    try {
      if (isFileInput && s.files.length > 1) {
        const results: FileResult[] = [];
        const signatures: { name: string; result: SignedResult }[] = [];
        for (const file of s.files) {
          const bytes = new Uint8Array(await file.arrayBuffer());
          const result = await decryptOne({
            kind: "binary",
            binaryMessage: bytes,
          });
          const data =
            result.data instanceof Uint8Array
              ? result.data
              : new TextEncoder().encode(result.data);
          // Same naming as a single file: cleaned, ciphertext extension
          // off, and never left looking like ciphertext.
          const outName = outputFileName("decrypt", [file.name], false);
          results.push({ name: outName, data });
          refuseInvalid(result);
          signatures.push({ name: file.name, result });
        }
        s.setFileResults(results);
        const totalSize = results.reduce((sum, r) => sum + r.data.length, 0);
        s.setStatusText(
          tn("workspace_files_decrypted", results.length, {
            size: formatFileSize(totalSize),
          }),
        );
        // After the size line: a mixed batch replaces it with the
        // file-by-file account of who signed what.
        showBatchSignatures(signatures);
        s.setOperationDone(true);
        maybeAutoDownload(true, { results });
      } else if (isFileInput) {
        const bytes = new Uint8Array(await s.files[0].arrayBuffer());
        const result = await decryptOne({
          kind: "binary",
          binaryMessage: bytes,
        });
        if (result.data instanceof Uint8Array) {
          if (isZipArchive(result.data)) {
            s.setBinaryOutput(result.data);
            s.setStatusText(t("workspace_status_decrypted_archive"));
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
        const result = await decryptOne({
          kind: "armored",
          armoredMessage: s.getInput(),
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
      // Decrypts are NOT captured: without content (never stored --
      // it's someone else's message) a decrypt row is just "decrypt,
      // <time>", which answers nothing. History records what YOU
      // produced (encrypt/sign), not what you read.
      return null;
    } catch (err) {
      // Never leave decrypted plaintext on screen when the operation
      // errored. The single-input branches set the output *before*
      // handleSig runs, so a bad-signature ("invalid" -> tamper) throw
      // would otherwise render the tampered plaintext next to the error.
      // Clear it so a tamper signal never shows the untrusted content.
      s.setOutput("");
      s.setBinaryOutput(undefined);
      s.setFileResults([]);
      s.setOperationDone(false);
      s.setVerifiedSigner(null);
      // Classify the underlying reason (missing key, wrong passphrase,
      // corrupted data, tampered signature, ...) into curated copy instead
      // of a one-size-fits-all message; the raw error rides along as the
      // collapsed technical detail, so failures stay diagnosable.
      //
      // RETURNED, not set: where a failure belongs depends on how the
      // message was being opened. The key path puts it in the page-level
      // error slot; the password path puts it under the prompt, which
      // stays up so the user can just retype.
      return presentError(err, t("workspace_error_decrypt_failed"));
    }
  }

  async function executeSign() {
    const signKeyId = resolvePgpSignerId();
    if (!signKeyId) {
      s.setError({
        message:
          myKeys.length > 0
            ? t("workspace_error_no_signing_key_ssh")
            : t("workspace_error_no_signing_key"),
      });
      return;
    }
    const keyHandle = await ensureUnlocked(signKeyId);
    if (keyHandle === null) return;

    if (s.files.length > 0) {
      const results: FileResult[] = [];
      for (const file of s.files) {
        const text = await file.text();
        const signed = await pgpOps.signWithHandle(text, keyHandle);
        results.push({
          name: outputFileName("sign", [file.name], false),
          data: new TextEncoder().encode(signed),
        });
      }
      s.setFileResults(results);
      if (results.length > 1) {
        s.setStatusText(tn("workspace_files_signed", results.length));
      }
      s.setOperationDone(true);
      maybeAutoDownload(true, { results });
    } else {
      const signed = await pgpOps.signWithHandle(s.getInput(), keyHandle);
      s.setOutput(signed);
      s.setOperationDone(true);
      maybeAutoDownload(false, { text: signed });
    }

    captureHistory({
      op: "sign",
      recipients: [],
      signed: true,
      ...(s.files.length > 0
        ? { files: historyFileMeta() }
        : { content: s.getInput() }),
    });
  }

  async function executeVerify() {
    const allPubArmored = pgpVerificationKeys();

    try {
      // Every staged file, not just the first: a verdict under a list of
      // two files must speak for both.
      // Size first, before any file is read: nothing past the engine's
      // input cap can verify, and reading it as text costs the panel.
      const tooLarge = s.files.find((f) => f.size > MAX_VERIFY_FILE_BYTES);
      if (tooLarge) {
        s.setError({
          message: t("workspace_error_verify_file_too_large", {
            name: displayFileName(tooLarge.name),
            limit: MAX_VERIFY_FILE_LABEL,
          }),
        });
        return;
      }
      // Decoded strictly. `File.text()` swaps invalid UTF-8 for U+FFFD,
      // so a genuine Latin-1 file read as tampered, and a crafted one
      // could verify as text it doesn't contain.
      const strictUtf8 = new TextDecoder("utf-8", { fatal: true });
      const inputs: { name: string; text: string }[] = [];
      if (s.files.length === 0) {
        inputs.push({ name: "", text: s.getInput() });
      }
      for (const f of s.files) {
        try {
          inputs.push({
            name: f.name,
            text: strictUtf8.decode(await f.arrayBuffer()),
          });
        } catch {
          s.setError({
            message: t("workspace_error_verify_not_utf8", {
              name: displayFileName(f.name),
            }),
          });
          return;
        }
      }
      const results = [];
      for (const input of inputs) {
        results.push({
          name: input.name,
          result: await pgpOps.verify({
            signedMessage: input.text,
            verificationPublicKeys: allPubArmored,
          }),
        });
      }

      const failed = results.find(
        ({ result }) =>
          result.signatureStatus === "invalid" ||
          result.signatureStatus === "unsigned",
      );
      if (failed) {
        s.setError({
          message:
            failed.result.signatureStatus === "invalid"
              ? t("workspace_error_signature_invalid")
              : t("workspace_error_not_signed"),
          ...(results.length > 1 ? { detail: failed.name } : {}),
        });
        return;
      }

      s.setOperationDone(true);
      const only = results.length === 1 ? results[0].result : null;
      if (only) {
        // What was signed may itself hold characters that reorder or hide
        // text on screen. They are the signer's, so they stay -- but the
        // card says they are there.
        showSignature(
          only,
          hasHiddenCharacters(only.text)
            ? t("workspace_signed_text_hidden_chars")
            : null,
        );
        // Show what was SIGNED -- the engine's text, not the paste. For an
        // inline-signed message or a file it is the only place the user
        // sees the content the verdict is about.
        s.setOutput(only.text);
        if (only.signatureStatus === "valid") {
          maybeAutoDownload(s.files.length > 0, { text: only.text });
        }
      } else {
        showBatchSignatures(results);
      }
      // Verify results are not captured (see the decrypt note): a
      // content-free "verify, <time>" row carries no recall value.
    } catch (e) {
      s.setError(presentError(e, t("workspace_error_verify_failed")));
    }
  }

  // ── CRX (Chrome extension) signing ────────────────────────────────

  function crxOutputName(): string {
    const base = s.files[0]?.name.replace(/\.(zip|crx)$/i, "") ?? "extension";
    return `${base}.crx`;
  }

  function pickCrxKey(): CrxSigningKeyBlob | null {
    // Exact match only. Falling back to crxKeys[0] here would silently sign
    // under a different extension identity than the one shown in the Select
    // (state keeps the selection valid, so a miss means something is off).
    return crxKeys.find((k) => k.extensionId === s.selectedCrxKeyId) ?? null;
  }

  function doCrxSign(
    crxKey: CrxSigningKeyBlob,
    password?: string,
  ): Promise<boolean> {
    return forCurrentInput(() => doCrxSignNow(crxKey, password));
  }

  async function doCrxSignNow(
    crxKey: CrxSigningKeyBlob,
    password?: string,
  ): Promise<boolean> {
    s.setLoading(true);
    s.setError(null);
    s.setOutput("");
    s.setBinaryOutput(undefined);
    s.setFileResults([]);
    try {
      // CRX signing is gated on a single manifest-bearing .zip input, so
      // sign exactly that file — never the multi-file/zip-toggle path.
      const zip = new Uint8Array(await s.files[0].arrayBuffer());
      const crx = await signZipWithCrxKey(
        crxKey,
        zip,
        password ? { password } : {},
      );
      const name = crxOutputName();
      s.setFileResults([{ name, data: crx }]);
      s.setStatusText(t("workspace_status_crx_signed", { name }));
      s.setOperationDone(true);
      // WorkspaceView auto-fires the "Save As" prompt for this result (the one
      // download path Chrome won't route to the extension installer -- see
      // saveCrxViaPrompt); the Save button is a manual fallback.
      return true;
    } catch (e) {
      // Backing out of the passkey prompt is a decision, not a failure.
      if (isWebAuthnCancel(e)) return false;
      if (password) {
        s.setPasswordError(t("workspace_error_crx_wrong_password"));
      } else {
        s.setError(presentError(e, t("workspace_error_crx_sign_failed")));
      }
      return false;
    } finally {
      s.setLoading(false);
      onOperationComplete?.();
    }
  }

  async function executeCrxSign() {
    if (s.mode !== "sign" || s.files.length !== 1) return;
    const crxKey = pickCrxKey();
    if (!crxKey) {
      s.setError({ message: t("workspace_error_select_crx_key") });
      return;
    }
    s.setError(null);
    if (crxKey.protection.method === "password") {
      s.setPendingCrxSign(true);
      s.setNeedsPassword(true);
      s.setPasswordInput("");
      s.setPasswordError(null);
      return;
    }
    await doCrxSign(crxKey);
  }

  function verifyCrxInput() {
    return forCurrentInput(verifyCrxInputNow);
  }

  async function verifyCrxInputNow() {
    if (s.files.length === 0) return;
    s.setError(null);
    s.setOperationDone(false);
    s.setLoading(true);
    try {
      const bytes = new Uint8Array(await s.files[0].arrayBuffer());
      const r = await verifyCrxFile(bytes);
      if (r.valid) {
        s.setOperationDone(true);
        s.setSignatureTone("success");
        s.setStatusText(
          t("workspace_status_crx_valid", { id: r.extensionId ?? "" }),
        );
      } else {
        s.setError(presentError(r.error, t("workspace_error_crx_invalid")));
      }
    } catch (e) {
      // verifyCrxFile reports malformed input via `valid:false`; anything
      // thrown is unexpected (e.g. the file read failed) -- still surface it.
      s.setError(presentError(e, t("workspace_error_read_file")));
    } finally {
      s.setLoading(false);
    }
  }

  /**
   * Open the staged message with the password just typed.
   *
   * The failure case is the interesting one. A wrong password is not
   * reliably detectable where the password is used -- a v4 SKESK unwraps
   * the session key with no integrity check, so a wrong one fails much
   * later as an MDC mismatch. The engine folds both into one message, and
   * this keeps the prompt UP rather than tearing it down and showing a
   * page-level error: the user's next action is to retype the password,
   * and it should be waiting where they left it.
   */
  const runPasswordDecrypt = (password: string) =>
    forCurrentInput(() => runPasswordDecryptNow(password));

  const runPasswordDecryptNow = async (password: string) => {
    s.setLoading(true);
    s.setPasswordError(null);
    try {
      const failure = await runPgpDecrypt((one) =>
        pgpOps.decryptWithPassword({
          input: one,
          password,
          verificationPublicKeys: pgpVerificationKeys(),
        }),
      );
      if (failure) {
        // Inline, under the field, with the prompt still up. The
        // detail line has nowhere to go here -- the prompt is one row --
        // so only the curated sentence is shown, the same compromise the
        // key-unlock branch below makes.
        s.setPasswordError(failure.message);
        return;
      }
      s.setPendingPasswordDecrypt(false);
      s.setNeedsPassword(false);
      s.setPasswordInput("");
    } finally {
      s.setLoading(false);
    }
  };

  const handlePasswordSubmit = async () => {
    if (s.pendingPasswordDecrypt) {
      await runPasswordDecrypt(s.passwordInput);
      return;
    }
    if (s.pendingCrxSign) {
      const crxKey = pickCrxKey();
      if (!crxKey) return;
      const ok = await doCrxSign(crxKey, s.passwordInput);
      if (ok) {
        s.setPendingCrxSign(false);
        s.setNeedsPassword(false);
        s.setPasswordInput("");
      }
      return;
    }

    const keyId = s.selectedKeyId ?? myKeys[0]?.keyId;
    if (!keyId) return;
    const blob = myKeys.find((k) => k.keyId === keyId);
    if (!blob) return;

    s.setLoading(true);
    s.setPasswordError(null);

    try {
      const ok = await onUnlockWithPassword(blob, s.passwordInput);
      if (!ok) {
        s.setPasswordError(t("workspace_error_wrong_key_password"));
        s.setLoading(false);
        return;
      }
      s.setNeedsPassword(false);
      s.setPasswordInput("");
      await execute();
    } catch (e) {
      // The prompt is a single password field, so surface just the
      // curated message inline (no room for the detail line here).
      s.setPasswordError(
        presentError(e, t("workspace_error_unlock_failed")).message,
      );
      s.setLoading(false);
    }
  };

  return {
    execute,
    executeUnattended,
    executeCrxSign,
    verifyCrxInput,
    handlePasswordSubmit,
    triggerDownload,
    selectPrivateKey,
    matchDecryptionKey,
    outputFileName: currentOutputName,
  };
}
