import { useEffect } from "react";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { EncryptInput, SignatureStatus } from "../../lib/pgp/types";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { NewHistoryEntry } from "../../lib/storage/history";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type { FileResult } from "../../lib/utils/download";
import type { WorkspaceState } from "./useWorkspaceState";
import * as ageOps from "../../lib/age/operations";
import { signZipWithCrxKey, verifyCrxFile } from "../../lib/crx/operations";
import {
  buildEncryptRecipients,
  resolveSelectedRecipients,
  toSelectedRecipient,
} from "../../lib/encrypt-recipients";
import { AppError } from "../../lib/errors/app-error";
import { presentError } from "../../lib/errors/present";
import * as pgpOps from "../../lib/pgp/operations";
import { isWebAuthnCancel } from "../../lib/protection/webauthn-prf";
import { updateRecentRecipients } from "../../lib/recipient-ordering";
import { recordHistory } from "../../lib/storage/history";
import { isPgpRecord, isSshRecord } from "../../lib/storage/key-kind";
import { savePreferences } from "../../lib/storage/preferences";
import { toast } from "../../lib/toast";
import {
  downloadBinary,
  downloadResults,
  downloadText,
} from "../../lib/utils/download";
import { formatFileSize } from "../../lib/utils/formatting";
import { formatKeyDisplayName } from "../../lib/utils/key-naming";
import {
  isZipArchive,
  zipFiles as zipFilesToArchive,
} from "../../lib/utils/zip";
import { outputFileName } from "./output-name";
import { selectionEngine } from "./recipient-engine";

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
    if (!hasContent || myKeys.length === 0) return;

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

        const input =
          s.files.length > 0
            ? {
                kind: "binary" as const,
                binaryMessage: new Uint8Array(await s.files[0].arrayBuffer()),
              }
            : { kind: "armored" as const, armoredMessage: s.getInput() };
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
    return (
      contacts.find((c) => c.keyId.toUpperCase().endsWith(hex)) ??
      myKeys.find((k) => k.keyId.toUpperCase().endsWith(hex)) ??
      null
    );
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
      s.files.map((f) => f.name),
      s.zipFiles,
      { recipients: selectedRecipientNames(), engine: selectedEngine() },
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

  async function resolveFileBytes(): Promise<Uint8Array> {
    if (s.files.length > 1 && s.zipFiles) {
      return zipFilesToArchive(s.files);
    }
    return new Uint8Array(await s.files[0].arrayBuffer());
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
  function historyFileMeta() {
    return s.files.map((f) => ({ name: f.name, size: f.size }));
  }

  /** Fire-and-forget history capture: never delays the operation, but a
   *  storage failure (quota / device full) surfaces one deduped error
   *  toast -- a user who believes history is recording may delete the
   *  original message trusting the copy exists. */
  function captureHistory(entry: NewHistoryEntry): void {
    void recordHistory(entry).then((result) => {
      if (result === "failed") {
        toast.error("Couldn't save to history - storage may be full", {
          id: "history-save-failed",
        });
      }
    });
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
      s.setError(presentError(e, "The operation failed. Try again."));
    } finally {
      s.setLoading(false);
      onOperationComplete?.();
    }
  };

  async function executeEncrypt() {
    const recipients = selectedRecipientKeys();
    if (recipients.length === 0) {
      s.setError({ message: "Select at least one recipient key." });
      return;
    }

    // Which engine this message is in, decided by the recipients. It
    // also decides what happens below: age has no signing operation, so
    // the persisted "Sign" preference must not drag the message onto the
    // PGP signing path (nor pull a PGP key in as the signer).
    const isAge = selectedEngine() === "ssh";

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
      s.setError({ message: "Couldn't work out which format to encrypt in." });
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
      s.setStatusText("age message - encrypted to SSH recipients");
    }

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
        });
      }
      return pgpOps.encrypt({
        input,
        recipientPublicKeys,
      });
    };

    const isFileInput = s.files.length > 0;

    if (isFileInput && s.files.length > 1 && !s.zipFiles) {
      const results: FileResult[] = [];
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
        `${results.length} files encrypted (${formatFileSize(totalSize)} total)`,
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
        ? { files: historyFileMeta() }
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
            name: file.name.replace(/\.age$/i, "") || file.name,
            data:
              typeof data === "string" ? new TextEncoder().encode(data) : data,
          });
        }
        s.setFileResults(results);
        const totalSize = results.reduce((sum, r) => sum + r.data.length, 0);
        s.setStatusText(
          `${results.length} files decrypted (${formatFileSize(totalSize)} total)`,
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
        s.setStatusText("Decrypted archive containing multiple files");
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
      s.setError(
        presentError(
          err,
          "Decryption failed. The message may be corrupted, or it isn't encrypted to any of your SSH keys.",
        ),
      );
    }
  }

  async function executeDecrypt() {
    if (!s.selectedKeyId) {
      s.setError({ message: "Select a decryption key." });
      return;
    }
    const keyHandle = await ensureUnlocked(s.selectedKeyId);
    if (keyHandle === null) return;

    if (s.inputIsAge) {
      await executeDecryptAge(keyHandle);
      return;
    }

    const allPubArmored = [
      ...myKeys.map((k) => k.publicKeyArmored),
      ...contacts.map((c) => c.armoredPublicKey),
    ];

    const handleSig = (result: {
      signatureStatus: SignatureStatus;
      signerKeyId: string | null;
    }) => {
      switch (result.signatureStatus) {
        case "valid": {
          s.setSignatureTone("success");
          s.setStatusText("Signature verified");
          const signer = findSigner(result.signerKeyId);
          if (signer) s.setVerifiedSigner(signer);
          break;
        }
        case "unknown_key": {
          // Signed, but we don't hold the signer's public key. Decryption
          // still succeeded -- show the same signer card as a verified
          // signature, but in an orange "can't verify" tone.
          s.setSignatureTone("warning");
          s.setVerifiedSigner({
            keyId: result.signerKeyId ?? "",
            userIds: ["Unknown signer"],
            algorithm: "",
            armoredPublicKey: "",
            addedAt: 0,
            lastUsedAt: 0,
          });
          s.setStatusText(
            "This message is signed, but the signer's public key isn't in your keys or contacts, so the signature could not be verified.",
          );
          break;
        }
        case "invalid":
          throw new Error(
            "Signature verification FAILED - this message may have been tampered with",
          );
        case "unsigned":
          break;
      }
    };

    const isFileInput = s.files.length > 0;

    try {
      if (isFileInput && s.files.length > 1) {
        const results: FileResult[] = [];
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
          `${results.length} files decrypted (${formatFileSize(totalSize)} total)`,
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
          input: { kind: "armored", armoredMessage: s.getInput() },
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
      // Decrypts are NOT captured: without content (never stored --
      // it's someone else's message) a decrypt row is just "decrypt,
      // <time>", which answers nothing. History records what YOU
      // produced (encrypt/sign), not what you read.
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
      s.setError(
        presentError(
          err,
          "Decryption failed. The message may be corrupted, or it isn't encrypted to any of your keys.",
        ),
      );
    }
  }

  async function executeSign() {
    const signKeyId = resolvePgpSignerId();
    if (!signKeyId) {
      s.setError({
        message:
          myKeys.length > 0
            ? "No signing key available. SSH keys can't sign - add an OpenPGP key first."
            : "No signing key available. Add a key first.",
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
          name: `${file.name}.asc`,
          data: new TextEncoder().encode(signed),
        });
      }
      s.setFileResults(results);
      if (results.length > 1) {
        s.setStatusText(`${results.length} files signed`);
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
    const allPubArmored = [
      ...myKeys.map((k) => k.publicKeyArmored),
      ...contacts.map((c) => c.armoredPublicKey),
    ];

    try {
      const messageText =
        s.files.length > 0 ? await s.files[0].text() : s.getInput();
      const result = await pgpOps.verify({
        signedMessage: messageText,
        verificationPublicKeys: allPubArmored,
      });
      switch (result.signatureStatus) {
        case "valid": {
          const isFileInput = s.files.length > 0;
          s.setOperationDone(true);
          s.setSignatureTone("success");
          s.setStatusText("Signature verified");
          const signer = findSigner(result.signerKeyId);
          if (signer) s.setVerifiedSigner(signer);
          maybeAutoDownload(isFileInput, { text: result.text });
          break;
        }
        case "unknown_key":
          // Signed, but we don't hold the signer's public key. That is not
          // a failed verification -- show the signer's key ID so the user
          // can go fetch the right key (a rotation notice is often signed
          // by a key you don't have yet).
          s.setOperationDone(true);
          s.setSignatureTone("warning");
          s.setVerifiedSigner({
            keyId: result.signerKeyId ?? "",
            userIds: ["Unknown signer"],
            algorithm: "",
            armoredPublicKey: "",
            addedAt: 0,
            lastUsedAt: 0,
          });
          s.setStatusText(
            "This message is signed, but the signer's public key isn't in your keys or contacts, so the signature could not be verified.",
          );
          break;
        case "invalid":
          s.setError({
            message:
              "Signature verification FAILED - this message may have been tampered with",
          });
          break;
        case "unsigned":
          s.setError({ message: "This message is not signed." });
          break;
      }
      if (
        result.signatureStatus === "valid" ||
        result.signatureStatus === "unknown_key"
      ) {
        // Verify results are not captured (see the decrypt note): a
        // content-free "verify, <time>" row carries no recall value.
      }
    } catch (e) {
      s.setError(
        presentError(
          e,
          "Verification failed. The input doesn't look like a signed PGP message.",
        ),
      );
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

  async function doCrxSign(
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
      s.setStatusText(`Signed ${name} - saving...`);
      s.setOperationDone(true);
      // WorkspaceView auto-fires the "Save As" prompt for this result (the one
      // download path Chrome won't route to the extension installer -- see
      // saveCrxViaPrompt); the Save button is a manual fallback.
      return true;
    } catch (e) {
      // Backing out of the passkey prompt is a decision, not a failure.
      if (isWebAuthnCancel(e)) return false;
      if (password) {
        s.setPasswordError("Wrong password or signing failed.");
      } else {
        s.setError(presentError(e, "CRX signing failed. Try again."));
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
      s.setError({ message: "Select a CRX signing key first." });
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

  async function verifyCrxInput() {
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
        s.setStatusText(`Valid CRX - extension ${r.extensionId}`);
      } else {
        s.setError(
          presentError(
            r.error,
            "This file's CRX signature could not be verified.",
          ),
        );
      }
    } catch (e) {
      // verifyCrxFile reports malformed input via `valid:false`; anything
      // thrown is unexpected (e.g. the file read failed) -- still surface it.
      s.setError(presentError(e, "Could not read this file. Try again."));
    } finally {
      s.setLoading(false);
    }
  }

  const handlePasswordSubmit = async () => {
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
        s.setPasswordError("Wrong password. Check it and try again.");
        s.setLoading(false);
        return;
      }
      s.setNeedsPassword(false);
      s.setPasswordInput("");
      await execute();
    } catch (e) {
      // The prompt is a single password field, so surface just the
      // curated message inline (no room for the detail line here).
      s.setPasswordError(presentError(e, "Unlock failed. Try again.").message);
      s.setLoading(false);
    }
  };

  return {
    execute,
    executeCrxSign,
    verifyCrxInput,
    handlePasswordSubmit,
    triggerDownload,
    selectPrivateKey,
    outputFileName: currentOutputName,
  };
}
