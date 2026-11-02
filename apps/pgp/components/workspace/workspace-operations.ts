import type { CrxSigningKeyBlob } from "../../lib/crx/types";
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
import type { Mode, Outcome, RunResult } from "./workspace-state";
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
import { OutputCapReached } from "../../lib/pgp/wasm-public";
import { isWebAuthnCancel } from "../../lib/protection/webauthn-prf";
import { updateRecentRecipients } from "../../lib/recipient-ordering";
import { contactRecipients } from "../../lib/storage/contact-recipients";
import { recordHistory } from "../../lib/storage/history";
import { isPgpRecord, isSshRecord } from "../../lib/storage/key-kind";
import { preferencesStore } from "../../lib/storage/preferences-store";
import { toast } from "../../lib/toast";
import {
  downloadBinary,
  downloadResults,
  downloadText,
} from "../../lib/utils/download";
import { displayFileName } from "../../lib/utils/file-name";
import { formatFileSize } from "../../lib/utils/formatting";
import {
  displayUserId,
  formatKeyDisplayName,
  parseUserId,
} from "../../lib/utils/key-naming";
import { hasLoneCarriageReturn } from "../../lib/utils/line-breaks";
import { isZipArchive, zipFiles } from "../../lib/utils/zip";
import {
  hasHiddenCharacters,
  hiddenCharactersToConfirm,
} from "./hidden-characters";
import { outputFileName, uniqueOutputNames } from "./output-name";
import { selectionEngine } from "./recipient-engine";
import {
  mixedBatchNote,
  notAddressed,
  signatureNote,
  signedForOthers,
  summariseBatch,
} from "./signature-summary";

/**
 * The workspace's operations: encrypt / decrypt / sign / verify and CRX,
 * each computing an {@link Outcome} that `useWorkspace` applies in one
 * dispatch. Nothing here touches React state.
 *
 * Plaintext is only ever read through `getInput()` at the point of use
 * and handed back as `Outcome.text`; never hoisted into anything that
 * outlives the run (SECURITY.md §8.11).
 */

/**
 * The most an UNATTENDED run (context-menu auto-decrypt) puts on screen.
 * Passed to the PGP engine as `maxOutputBytes` so it stops reading there,
 * and re-checked after every unattended run (age takes no ceiling; text
 * counts characters).
 */
export const AUTO_RUN_MAX_BYTES = 1024 * 1024;

export interface RunContext {
  mode: Mode;
  files: File[];
  /** Read the composed message at the point of use, never hoisted. */
  getInput: () => string;
  /** The box has a non-whitespace character. */
  hasText: boolean;
  isAge: boolean;
  zipFiles: boolean;
  recipientIds: string[];
  /** The private key in effect (see `resolveKeyId`). */
  keyId: string | null;
  myKeys: ProtectedKeyBlob[];
  contacts: PublicContactKey[];
  alsoSign: boolean;
  encryptToSelf: boolean;
  defaultKeyId: string | null;
  recentRecipients: string[];
  /** The message password when one is armed; `undefined`, never `""`
   *  (an empty string is a password). */
  password: string | undefined;
  autoDownloadFiles: boolean;
  autoDownloadText: boolean;
  getKeyHandle: (keyId: string) => number | null;
  unlockWithPasskey: (blob: ProtectedKeyBlob) => Promise<boolean | "cancelled">;
  /** Nobody pressed anything: never ask for a secret, never write to
   *  disk. Checked at each prompt, since a key can close mid-run. */
  unattended: boolean;
  /** Output ceiling (`AUTO_RUN_MAX_BYTES`) -- context-menu auto-run only.
   *  A prompt-free re-run of the user's own run is not capped. */
  cap: number | undefined;
  /** "Sign anyway" was pressed for this exact text. */
  hiddenCharsConfirmed: boolean;
}

const NONE: Outcome = { kind: "none" };
const fail = (message: string): Outcome => ({
  kind: "error",
  error: { message },
});

/** Abandons an unattended run over the ceiling. Never shown as an error. */
class HeldBackForSize extends Error {}

/** The engine's own over-the-ceiling stop, read as {@link HeldBackForSize}. */
async function heldBackIfCapped<T>(run: Promise<T>): Promise<T> {
  try {
    return await run;
  } catch (e) {
    if (e instanceof OutputCapReached) throw new HeldBackForSize();
    throw e;
  }
}

function withinCap<T extends { data: string | Uint8Array }>(
  c: RunContext,
  result: T,
): T {
  if (c.cap !== undefined && result.data.length > c.cap) {
    if (result.data instanceof Uint8Array) result.data.fill(0);
    throw new HeldBackForSize();
  }
  return result;
}

const fileBytes = async (f: File) => new Uint8Array(await f.arrayBuffer());
const totalSize = (results: FileResult[]) =>
  formatFileSize(results.reduce((sum, r) => sum + r.data.length, 0));

/** Rename a batch's outputs apart in place; returns the final names. */
function nameApart(results: FileResult[]): string[] {
  const names = uniqueOutputNames(results.map((r) => r.name));
  results.forEach((r, i) => (r.name = names[i]));
  return names;
}

// ── keys and signers ────────────────────────────────────────────────

/** The signer for any PGP operation: the key in effect when it is
 *  OpenPGP, else the first one. age has no signing operation. */
function pgpSignerId(c: RunContext): string | null {
  const pgpKeys = c.myKeys.filter(isPgpRecord);
  if (c.keyId && pgpKeys.some((k) => k.keyId === c.keyId)) return c.keyId;
  return pgpKeys[0]?.keyId ?? null;
}

function findSigner(c: RunContext, signerKeyId: string | null) {
  if (!signerKeyId) return null;
  const hex = signerKeyId.toUpperCase();
  // Any of a contact's keys: a signature from a person's second key is
  // still that person.
  return (
    c.contacts.find((ct) =>
      contactRecipients(ct).some((r) => r.keyId.toUpperCase().endsWith(hex)),
    ) ??
    c.myKeys.find((k) => k.keyId.toUpperCase().endsWith(hex)) ??
    null
  );
}

function signerName(c: RunContext, keyId: string): string {
  const signer = findSigner(c, keyId);
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

/** Every public key a signature could be checked against -- every key of
 *  every PGP contact, not only each contact's first. */
function verificationKeys(c: RunContext): string[] {
  return [
    ...c.myKeys.filter(isPgpRecord).map((k) => k.publicKeyArmored),
    ...c.contacts
      .filter((ct) => !isSshRecord(ct))
      .flatMap((ct) => contactRecipients(ct).map((r) => r.armored)),
  ];
}

/**
 * The verdict for a single result. Only the keys it decides are set, so
 * an unsigned result leaves the caller's status (e.g. "archive") alone.
 *
 * `text`: the signed text as shown -- hidden characters or a lone CR are
 * the signer's and stay, but the card says so. `notEncrypted`: a "PGP
 * MESSAGE" with no encryption layer is amber, never green, and gets a
 * card even unsigned.
 */
function signatureVerdict(
  c: RunContext,
  result: SignedResult,
  {
    text,
    notEncrypted = false,
    decrypted = false,
  }: { text?: string; notEncrypted?: boolean; decrypted?: boolean } = {},
): Partial<RunResult> {
  const loneCr = text !== undefined && hasLoneCarriageReturn(text);
  if (result.signatureStatus === "valid") {
    const myIds = c.myKeys.map((k) => k.keyId);
    const forOthers = signedForOthers(result, myIds);
    // Retired since signing, or signed for someone else: amber, never green.
    const caveat = notEncrypted
      ? t("workspace_not_encrypted")
      : forOthers
        ? t("workspace_signature_verified_not_for_you")
        : !result.signerKeyCurrent
          ? t("workspace_signature_verified_retired")
          : loneCr
            ? t("workspace_signature_verified_line_breaks")
            : null;
    const signer = findSigner(c, result.signerKeyId);
    if (!signer) return { status: t("workspace_signature_verified") };
    // Whether the key IS the person it names only the user can vouch for.
    const unvouched =
      "armoredPublicKey" in signer &&
      !signer.verified &&
      !myIds.includes(signer.keyId);
    const note =
      [
        notEncrypted ? t("workspace_signed_not_encrypted") : null,
        signatureNote(result, (id) => signerName(c, id), forOthers),
        unvouched ? t("workspace_signer_not_verified") : null,
        notAddressed(result, { decrypted, notEncrypted })
          ? t("workspace_signature_not_addressed")
          : null,
        text !== undefined && hasHiddenCharacters(text)
          ? t("workspace_signed_text_hidden_chars")
          : null,
        loneCr ? t("workspace_signed_text_lone_cr") : null,
      ]
        .filter(Boolean)
        .join(" · ") || null;
    return {
      status: t("workspace_signature_verified"),
      verdict: { signer, tone: caveat ? "warning" : "success", note, caveat },
    };
  }
  const amber = (signer: PublicContactKey, status: string) => ({
    status,
    verdict: { signer, tone: "warning", note: null, caveat: null } as const,
  });
  if (result.signatureStatus === "unknown_key") {
    // Same card, amber, with the key id so the user can fetch the key.
    return amber(
      placeholderSigner(result.signerKeyId ?? ""),
      notEncrypted
        ? `${t("workspace_status_signer_unknown")} ${t("workspace_status_not_encrypted")}`
        : t("workspace_status_signer_unknown"),
    );
  }
  if (notEncrypted) {
    return amber(
      placeholderSigner("", t("workspace_not_encrypted_not_signed")),
      t("workspace_status_not_encrypted"),
    );
  }
  return {};
}

/** One verdict for a batch of files -- see `summariseBatch`. */
function batchVerdict(
  c: RunContext,
  batch: { name: string; result: SignedResult }[],
  decrypted = false,
): Partial<RunResult> {
  const summary = summariseBatch(
    batch,
    c.myKeys.map((k) => k.keyId),
  );
  if (summary.kind === "unsigned") return {};
  if (summary.kind === "same") {
    return signatureVerdict(c, summary.result, { decrypted });
  }
  return {
    status: mixedBatchNote(summary.files, (id) => signerName(c, id)),
    verdict: {
      signer: placeholderSigner("", t("workspace_files_mixed_signers")),
      tone: "warning",
      note: null,
      caveat: null,
    },
  };
}

/** The key handle, unlocking if needed; otherwise what to do instead. */
async function ensureUnlocked(
  c: RunContext,
  keyId: string,
): Promise<number | Outcome> {
  const cached = c.getKeyHandle(keyId);
  if (cached !== null) return cached;
  if (c.unattended) return NONE;
  const blob = c.myKeys.find((k) => k.keyId === keyId);
  if (!blob) return NONE;
  if (blob.protection.method === "passkey") {
    const result = await c.unlockWithPasskey(blob);
    if (result === "cancelled") return NONE;
    if (!result) {
      throw new AppError("passkey-failed", "Passkey authentication failed.");
    }
    return c.getKeyHandle(keyId) ?? NONE;
  }
  return { kind: "prompt", prompt: "key" };
}

/** Signing may go ahead, or the hidden-characters strip goes up. */
function hiddenCharsHold(c: RunContext): Outcome | null {
  if (c.hiddenCharsConfirmed) return null;
  const chars = hiddenCharactersToConfirm(c.getInput());
  return chars.length > 0 ? { kind: "hidden-chars", chars } : null;
}

// ── names and downloads ─────────────────────────────────────────────

function selectedRecipientKeys(c: RunContext) {
  // Own keys win an id both hold (see `resolveSelectedRecipients`).
  return resolveSelectedRecipients(c.recipientIds, c.contacts, c.myKeys);
}

function recipientNames(c: RunContext): string[] {
  return c.recipientIds
    .map((id) => [...c.myKeys, ...c.contacts].find((k) => k.keyId === id))
    .filter((k) => k !== undefined)
    .map((k) => {
      const uid = k.userIds[0];
      return uid ? formatKeyDisplayName(uid).name : k.keyId.slice(-8);
    });
}

/**
 * What an encrypt takes in: the staged files plus, when a message was
 * written alongside them, that message as `msg.txt`. Built per run, never
 * kept: the box stays the one copy of the text.
 */
function stagedFiles(c: RunContext): File[] {
  const name = messageFileName(c);
  if (name === null) return c.files;
  return [...c.files, new File([c.getInput()], name, { type: "text/plain" })];
}

function messageFileName(c: RunContext): string | null {
  if (c.mode !== "encrypt" || c.files.length === 0 || !c.hasText) return null;
  const taken = new Set(c.files.map((f) => f.name));
  let name = "msg.txt";
  for (let n = 2; taken.has(name); n++) name = `msg-${n}.txt`;
  return name;
}

/** The download name. Encrypt names carry who-and-when, so a Downloads
 *  folder of ciphertext stays identifiable. Names only: safe in render. */
export function outputName(c: RunContext, binary: boolean): string {
  const message = messageFileName(c);
  return outputFileName(
    c.mode,
    [...c.files.map((f) => f.name), ...(message === null ? [] : [message])],
    c.zipFiles,
    {
      recipients: recipientNames(c),
      engine: selectionEngine(selectedRecipientKeys(c)),
      binary,
    },
  );
}

/** Save a result: per-file results, else the binary, else the text. */
export function download(
  c: RunContext,
  r: { files?: FileResult[]; binary?: Uint8Array; text?: string },
): void {
  if (r.files && r.files.length > 0) downloadResults(r.files);
  else if (r.binary) downloadBinary(r.binary, outputName(c, !r.text));
  else downloadText(r.text ?? "", outputName(c, false));
}

/** The auto-download preference -- for results the user asked for. An
 *  auto-run's input is whatever a web page selected, so never then. */
function autoDownload(
  c: RunContext,
  fileInput: boolean,
  r: { files?: FileResult[]; binary?: Uint8Array; text?: string },
) {
  if (c.unattended) return;
  if (fileInput ? c.autoDownloadFiles : c.autoDownloadText) download(c, r);
}

/** Fire-and-forget; a storage failure surfaces once -- a user who
 *  believes history records may delete the original trusting the copy. */
function captureHistory(entry: NewHistoryEntry): void {
  void recordHistory(entry).then((result) => {
    if (result === "failed") {
      toast.error(t("workspace_history_save_failed"), {
        id: "history-save-failed",
      });
    }
  });
}

const split = (data: string | Uint8Array) =>
  typeof data === "string" ? { text: data } : { binary: data };

// ── the operations ──────────────────────────────────────────────────

export async function runMode(c: RunContext): Promise<Outcome> {
  try {
    switch (c.mode) {
      case "encrypt":
        return await encrypt(c);
      case "decrypt":
        return await decrypt(c);
      case "sign":
        return await sign(c);
      case "verify":
        return await verify(c);
    }
  } catch (e) {
    return {
      kind: "error",
      error: presentError(e, t("workspace_operation_failed")),
    };
  }
}

async function encrypt(c: RunContext): Promise<Outcome> {
  const recipients = selectedRecipientKeys(c);
  // A password alone opens the message (`gpg -c`); the engine refuses
  // "no recipients and no password" independently.
  if (recipients.length === 0 && c.password === undefined) {
    return fail(t("workspace_error_need_recipient_or_password"));
  }
  const isAge = selectionEngine(recipients) === "ssh";
  // Backstop: the age path never sees the password, so this would be a
  // SILENT .age without one. The UI disallows the combination.
  if (isAge && c.password !== undefined) return fail(sshPasswordReason());

  // Signing is OpenPGP-only: resolved against PGP keys, and the same
  // answer for the recipient set and the handle, so the key the message
  // says signed it is the one that did.
  const signerKeyId = c.alsoSign && !isAge ? pgpSignerId(c) : null;
  const { recipientPublicKeys, selfKeyId, engine, refusal } =
    buildEncryptRecipients({
      recipients: recipients.map(toSelectedRecipient),
      encryptToSelf: c.encryptToSelf,
      ownKeys: c.myKeys,
      signingKeyId: signerKeyId,
      defaultKeyId: c.defaultKeyId,
    });
  // Backstops: the picker never assembles a mixed set.
  if (refusal !== null) return fail(refusal);
  if (engine !== null && (engine === "ssh") !== isAge) {
    return fail(t("workspace_error_engine_mismatch"));
  }

  let signingHandle: number | null = null;
  if (signerKeyId) {
    // The written message is signed along with the files (`msg.txt`).
    const hold = c.hasText ? hiddenCharsHold(c) : null;
    if (hold) return hold;
    const handle = await ensureUnlocked(c, signerKeyId);
    if (typeof handle !== "number") return handle;
    signingHandle = handle;
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
        password: c.password,
      });
    }
    return pgpOps.encrypt({ input, recipientPublicKeys, password: c.password });
  };

  const files = stagedFiles(c);
  const fileInput = files.length > 0;
  // The password was for THIS message: kept, it would quietly arm the
  // next one. (On failure it stays, so a retry needs no retyping.)
  const spentPassword = c.password !== undefined;
  let outcome: Outcome;
  if (files.length > 1 && !c.zipFiles) {
    const results: FileResult[] = [];
    for (const file of files) {
      const result = await doEncrypt({
        kind: "binary",
        binary: await fileBytes(file),
        armor: false,
      });
      results.push({
        name: outputFileName("encrypt", [file.name], false, {
          recipients: recipientNames(c),
          engine,
        }),
        data:
          typeof result === "string"
            ? new TextEncoder().encode(result)
            : result,
      });
    }
    nameApart(results);
    outcome = {
      kind: "done",
      spentPassword,
      files: results,
      status: tn("workspace_files_encrypted", results.length, {
        size: totalSize(results),
      }),
    };
    autoDownload(c, true, { files: results });
  } else {
    const result = await doEncrypt(
      fileInput
        ? {
            kind: "binary",
            binary:
              files.length > 1
                ? await zipFiles(files)
                : await fileBytes(files[0]),
            armor: false,
          }
        : { kind: "text", text: c.getInput() },
    );
    const out = split(result);
    outcome = {
      kind: "done",
      spentPassword,
      ...out,
      status:
        files.length > 1
          ? tn("workspace_files_zipped_encrypted", files.length)
          : isAge
            ? t("workspace_status_age_encrypted")
            : null,
    };
    autoDownload(c, fileInput, out);
  }
  // History answers "who did I send this to": one entry per selected
  // contact (its record id is its first key's fingerprint), plus the self
  // key when encrypt-to-self rode along.
  const historyRecipients = recipients.map((k) => ({
    fingerprint: k.keyId,
    name: k.userIds[0] ?? "",
  }));
  const selfKey =
    selfKeyId === null ? null : c.myKeys.find((k) => k.keyId === selfKeyId);
  if (selfKey) {
    historyRecipients.push({
      fingerprint: selfKey.keyId,
      name: selfKey.userIds[0] ?? "",
    });
  }
  captureHistory({
    op: "encrypt",
    recipients: historyRecipients,
    signed: !isAge && signingHandle !== null,
    ...(fileInput
      ? { files: files.map((f) => ({ name: f.name, size: f.size })) }
      : { content: c.getInput() }),
  });

  // Promote the selected recipients in the picker's recency order. A
  // failed background save only costs ordering: swallowed, since a toast
  // over a successful encrypt would read as the encrypt failing.
  void preferencesStore
    .update({
      recentRecipients: updateRecentRecipients(
        c.recentRecipients,
        recipients.map((k) => k.keyId),
      ),
    })
    .catch(() => undefined);
  return outcome;
}

/** The staged message, in the shape the PGP ops take. */
async function stagedPgpInput(c: RunContext): Promise<DecryptOptions["input"]> {
  return c.files.length > 0
    ? { kind: "binary", binaryMessage: await fileBytes(c.files[0]) }
    : { kind: "armored", armoredMessage: c.getInput() };
}

/** The user's key the staged message is addressed to, if any. */
export async function matchDecryptionKey(
  c: RunContext,
): Promise<string | null> {
  if (c.isAge) {
    // An age file has no OpenPGP header: ask the engine that owns it.
    const sshKeys = c.myKeys.filter(isSshRecord);
    if (sshKeys.length === 0) return null;
    const bytes =
      c.files.length > 0
        ? await fileBytes(c.files[0])
        : new TextEncoder().encode(c.getInput());
    const index = await ageOps.selectDecryptionKey(
      bytes,
      sshKeys.map((k) => k.publicKeyArmored),
    );
    return index === null ? null : (sshKeys[index]?.keyId ?? null);
  }
  if (c.myKeys.length === 0) return null;
  return pgpOps.selectDecryptionKey(
    await stagedPgpInput(c),
    c.myKeys.map((k) => k.publicKeyArmored),
  );
}

/** How the staged PGP message can be opened (for the UI only). */
export async function scanMessageEncryption(c: RunContext) {
  return pgpOps.messageEncryption(await stagedPgpInput(c));
}

/**
 * Decide how this message wants to be opened, then open it.
 *
 * THE KEY WINS when one of the user's keys matches; the password is the
 * fallback (`gpg -c`). Detection is redone here rather than read off the
 * scan effect: a paste followed straight by a click would race it.
 */
async function decrypt(c: RunContext): Promise<Outcome> {
  if (c.isAge) {
    // age has no password mode; it needs an SSH identity.
    if (!c.keyId) return fail(t("workspace_error_select_decryption_key"));
    const handle = await ensureUnlocked(c, c.keyId);
    if (typeof handle !== "number") return handle;
    return decryptAge(c, handle);
  }

  const input = await stagedPgpInput(c);
  // Unreadable headers fall through to the key path, whose errors say so.
  const encryption = await pgpOps.messageEncryption(input).catch(() => null);

  // A "PGP MESSAGE" with no encryption layer, asked BEFORE any key is
  // unlocked: decrypting it would dress up anything ever signed in public
  // as a private message. A batch is refused by name, file by file.
  if (c.files.length > 1) {
    for (const file of c.files) {
      const shape = await pgpOps
        .messageEncryption({
          kind: "binary",
          binaryMessage: await fileBytes(file),
        })
        .catch(() => null);
      if (shape && !shape.encrypted) {
        return fail(
          t("workspace_error_batch_not_encrypted", {
            name: displayFileName(file.name),
          }),
        );
      }
    }
  } else if (encryption && !encryption.encrypted) {
    return runPgpDecrypt(
      c,
      (one) =>
        pgpOps.openUnencrypted({
          input: one,
          verificationPublicKeys: verificationKeys(c),
          maxOutputBytes: c.cap,
        }),
      true,
    );
  }

  if (encryption?.password) {
    const keyMatch = encryption.publicKey
      ? await pgpOps
          .selectDecryptionKey(
            input,
            c.myKeys.map((k) => k.publicKeyArmored),
          )
          .catch(() => null)
      : null;
    if (!keyMatch) {
      return c.unattended ? NONE : { kind: "prompt", prompt: "message" };
    }
  }

  if (!c.keyId) return fail(t("workspace_error_select_decryption_key"));
  const keyHandle = await ensureUnlocked(c, c.keyId);
  if (typeof keyHandle !== "number") return keyHandle;
  return runPgpDecrypt(c, (one) =>
    pgpOps.decryptWithHandle({
      input: one,
      keyHandle,
      verificationPublicKeys: verificationKeys(c),
      maxOutputBytes: c.cap,
    }),
  );
}

/** Open the staged message with the password just typed. A wrong one is
 *  said under the prompt, which stays up for the retype. */
export async function decryptWithMessagePassword(
  c: RunContext,
  password: string,
): Promise<Outcome> {
  const outcome = await runPgpDecrypt(c, (one) =>
    pgpOps.decryptWithPassword({
      input: one,
      password,
      verificationPublicKeys: verificationKeys(c),
      maxOutputBytes: c.cap,
    }),
  );
  return outcome.kind === "error"
    ? { kind: "rejected", message: outcome.error.message }
    : outcome;
}

/**
 * Decrypt an age message with an unlocked SSH identity. No signatures in
 * age, so no verdict; the failure hygiene is the PGP path's.
 */
async function decryptAge(c: RunContext, keyHandle: number): Promise<Outcome> {
  try {
    if (c.files.length > 1) {
      const results: FileResult[] = [];
      for (const file of c.files) {
        const data = await ageOps.decryptWithHandle({
          input: { kind: "binary", binaryMessage: await fileBytes(file) },
          keyHandle,
        });
        results.push({
          name: outputFileName("decrypt", [file.name], false),
          data:
            typeof data === "string" ? new TextEncoder().encode(data) : data,
        });
      }
      nameApart(results);
      autoDownload(c, true, { files: results });
      return {
        kind: "done",
        files: results,
        status: tn("workspace_files_decrypted", results.length, {
          size: totalSize(results),
        }),
      };
    }
    const { data } = withinCap(c, {
      data: await ageOps.decryptWithHandle({
        input:
          c.files.length > 0
            ? { kind: "binary", binaryMessage: await fileBytes(c.files[0]) }
            : { kind: "armored", armoredMessage: c.getInput() },
        keyHandle,
      }),
    });
    const out = split(data);
    autoDownload(c, c.files.length > 0, out);
    return {
      kind: "done",
      ...out,
      status:
        out.binary && isZipArchive(out.binary)
          ? t("workspace_status_decrypted_archive")
          : null,
    };
  } catch (err) {
    if (err instanceof HeldBackForSize) return { kind: "held-back" };
    return {
      kind: "error",
      error: presentError(err, t("workspace_error_decrypt_failed_ssh")),
    };
  }
}

/**
 * Run a PGP decrypt and work out everything that follows from it.
 *
 * `decryptCall` is the ONLY difference between the key, password and
 * unencrypted paths: same batch loop, text/binary sniffing, verdict,
 * auto-download and failure handling, so the paths cannot drift.
 * A tampered signature anywhere fails the whole run, and nothing it
 * decrypted is shown next to the error.
 */
async function runPgpDecrypt(
  c: RunContext,
  decryptCall: (input: DecryptOptions["input"]) => Promise<DecryptResult>,
  notEncrypted = false,
): Promise<Outcome> {
  const refuseInvalid = (result: SignedResult) => {
    if (result.signatureStatus === "invalid") {
      throw new Error(
        "Signature verification FAILED - this message may have been tampered with",
      );
    }
  };
  const decryptOne = async (input: DecryptOptions["input"]) =>
    withinCap(c, await heldBackIfCapped(decryptCall(input)));

  try {
    if (c.files.length > 1) {
      const results: FileResult[] = [];
      const signatures: { name: string; result: SignedResult }[] = [];
      for (const file of c.files) {
        const result = await decryptOne({
          kind: "binary",
          binaryMessage: await fileBytes(file),
        });
        const name = outputFileName("decrypt", [file.name], false);
        results.push({
          name,
          data:
            result.data instanceof Uint8Array
              ? result.data
              : new TextEncoder().encode(result.data),
        });
        refuseInvalid(result);
        signatures.push({ name, result });
      }
      // The note names what the user SAVES: the de-duplicated names.
      nameApart(results).forEach((name, i) => (signatures[i].name = name));
      autoDownload(c, true, { files: results });
      return {
        kind: "done",
        files: results,
        // A mixed batch replaces the size line with who signed what.
        status: tn("workspace_files_decrypted", results.length, {
          size: totalSize(results),
        }),
        ...batchVerdict(c, signatures, true),
      };
    }

    const fileInput = c.files.length > 0;
    const result = await decryptOne(await stagedPgpInput(c));
    let text: string | undefined;
    let binary: Uint8Array | undefined;
    let status: string | null = null;
    if (typeof result.data === "string") {
      text = result.data;
    } else if (fileInput && isZipArchive(result.data)) {
      binary = result.data;
      status = t("workspace_status_decrypted_archive");
    } else if (fileInput) {
      try {
        // ignoreBOM: a leading BOM is part of the file; Copy and Download
        // must give it back.
        text = new TextDecoder("utf-8", {
          fatal: true,
          ignoreBOM: true,
        }).decode(result.data);
      } catch {
        binary = result.data;
      }
    } else {
      binary = result.data;
    }
    refuseInvalid(result);
    const verdict = signatureVerdict(c, result, {
      text,
      notEncrypted,
      decrypted: true,
    });
    autoDownload(c, fileInput, split(result.data));
    // Decrypts are not recorded in history: it records what you produced.
    return { kind: "done", text, binary, status, ...verdict };
  } catch (err) {
    if (err instanceof HeldBackForSize) return { kind: "held-back" };
    // Curated copy for the reason; the raw error rides along as detail.
    return {
      kind: "error",
      error: presentError(err, t("workspace_error_decrypt_failed")),
    };
  }
}

async function sign(c: RunContext): Promise<Outcome> {
  const keyId = pgpSignerId(c);
  if (!keyId) {
    return fail(
      c.myKeys.length > 0
        ? t("workspace_error_no_signing_key_ssh")
        : t("workspace_error_no_signing_key"),
    );
  }
  // The box's text is what gets signed when no files are staged.
  const hold = c.files.length === 0 ? hiddenCharsHold(c) : null;
  if (hold) return hold;
  const keyHandle = await ensureUnlocked(c, keyId);
  if (typeof keyHandle !== "number") return keyHandle;

  let outcome: Outcome;
  if (c.files.length > 0) {
    const results: FileResult[] = [];
    for (const file of c.files) {
      const signed = await pgpOps.signWithHandle(await file.text(), keyHandle);
      results.push({
        name: outputFileName("sign", [file.name], false),
        data: new TextEncoder().encode(signed),
      });
    }
    nameApart(results);
    autoDownload(c, true, { files: results });
    outcome = {
      kind: "done",
      files: results,
      status:
        results.length > 1
          ? tn("workspace_files_signed", results.length)
          : null,
    };
  } else {
    const signed = await pgpOps.signWithHandle(c.getInput(), keyHandle);
    autoDownload(c, false, { text: signed });
    outcome = { kind: "done", text: signed };
  }
  captureHistory({
    op: "sign",
    recipients: [],
    signed: true,
    ...(c.files.length > 0
      ? { files: c.files.map((f) => ({ name: f.name, size: f.size })) }
      : { content: c.getInput() }),
  });
  return outcome;
}

async function verify(c: RunContext): Promise<Outcome> {
  try {
    // Size first: nothing past the engine's cap can verify, and reading it
    // costs the panel.
    const tooLarge = c.files.find((f) => f.size > MAX_VERIFY_FILE_BYTES);
    if (tooLarge) {
      return fail(
        t("workspace_error_verify_file_too_large", {
          name: displayFileName(tooLarge.name),
          limit: MAX_VERIFY_FILE_LABEL,
        }),
      );
    }
    // Strict UTF-8: `File.text()` swaps invalid bytes for U+FFFD, so a
    // crafted file could verify as text it doesn't contain.
    const strictUtf8 = new TextDecoder("utf-8", { fatal: true });
    const inputs: { name: string; text: string }[] = [];
    if (c.files.length === 0) inputs.push({ name: "", text: c.getInput() });
    for (const f of c.files) {
      try {
        inputs.push({
          name: f.name,
          text: strictUtf8.decode(await f.arrayBuffer()),
        });
      } catch {
        return fail(
          t("workspace_error_verify_not_utf8", {
            name: displayFileName(f.name),
          }),
        );
      }
    }
    // Every staged file: a verdict under a list must speak for all of it.
    const results = [];
    for (const input of inputs) {
      const result = await heldBackIfCapped(
        pgpOps.verify({
          signedMessage: input.text,
          verificationPublicKeys: verificationKeys(c),
          maxOutputBytes: c.cap,
        }),
      );
      // An inline-signed message can be compressed.
      withinCap(c, { data: result.text });
      results.push({ name: input.name, result });
    }

    const failed = results.find(
      ({ result }) =>
        result.signatureStatus === "invalid" ||
        result.signatureStatus === "unsigned",
    );
    if (failed) {
      return {
        kind: "error",
        error: {
          message:
            failed.result.signatureStatus === "invalid"
              ? t("workspace_error_signature_invalid")
              : t("workspace_error_not_signed"),
          ...(results.length > 1 ? { detail: failed.name } : {}),
        },
      };
    }
    if (results.length > 1) {
      return { kind: "done", ...batchVerdict(c, results) };
    }
    const only = results[0].result;
    if (only.signatureStatus === "valid") {
      autoDownload(c, c.files.length > 0, { text: only.text });
    }
    // Show what was SIGNED -- the engine's text, not the paste.
    return {
      kind: "done",
      text: only.text,
      ...signatureVerdict(c, only, { text: only.text }),
    };
  } catch (e) {
    if (e instanceof HeldBackForSize) return { kind: "held-back" };
    return {
      kind: "error",
      error: presentError(e, t("workspace_error_verify_failed")),
    };
  }
}

// ── CRX (Chrome extension) packages ─────────────────────────────────

/** Sign the single staged manifest-bearing .zip. Gated upstream on that
 *  input, so never the multi-file path. */
export async function signCrx(
  c: RunContext,
  crxKey: CrxSigningKeyBlob,
  password?: string,
): Promise<Outcome> {
  try {
    const crx = await signZipWithCrxKey(
      crxKey,
      await fileBytes(c.files[0]),
      password ? { password } : {},
    );
    const base = c.files[0].name.replace(/\.(zip|crx)$/i, "");
    const name = `${base}.crx`;
    return {
      kind: "done",
      files: [{ name, data: crx }],
      status: t("workspace_status_crx_signed", { name }),
    };
  } catch (e) {
    // Backing out of the passkey prompt is a decision, not a failure.
    if (isWebAuthnCancel(e)) return NONE;
    return password
      ? { kind: "rejected", message: t("workspace_error_crx_wrong_password") }
      : {
          kind: "error",
          error: presentError(e, t("workspace_error_crx_sign_failed")),
        };
  }
}

export async function verifyCrx(c: RunContext): Promise<Outcome> {
  try {
    const r = await verifyCrxFile(await fileBytes(c.files[0]));
    return r.valid
      ? {
          kind: "done",
          status: t("workspace_status_crx_valid", { id: r.extensionId ?? "" }),
        }
      : {
          kind: "error",
          error: presentError(r.error, t("workspace_error_crx_invalid")),
        };
  } catch (e) {
    // Malformed input is `valid:false`; a throw is unexpected (read failed).
    return {
      kind: "error",
      error: presentError(e, t("workspace_error_read_file")),
    };
  }
}
