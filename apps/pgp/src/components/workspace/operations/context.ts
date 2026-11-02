import { resolveSelectedRecipients } from "~/lib/encrypt-recipients";
import { AppError } from "~/lib/errors/app-error";
import { t } from "~/lib/i18n";
import { OutputCapReached } from "~/lib/pgp/wasm-public";
import { contactRecipients } from "~/lib/storage/contact-recipients";
import type { PublicContactKey } from "~/lib/storage/contacts";
import { recordHistory, type NewHistoryEntry } from "~/lib/storage/history";
import { isPgpRecord, isSshRecord } from "~/lib/storage/key-kind";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import { isContact } from "~/lib/storage/stored-key";
import { toast } from "~/lib/toast";
import {
  downloadBinary,
  downloadResults,
  downloadText,
  type FileResult,
} from "~/lib/utils/download";
import { formatFileSize } from "~/lib/utils/formatting";
import {
  displayUserId,
  formatKeyDisplayName,
  parseUserId,
} from "~/lib/utils/key-naming";
import { hasLoneCarriageReturn } from "~/lib/utils/line-breaks";
import {
  hasHiddenCharacters,
  hiddenCharactersToConfirm,
} from "../hidden-characters";
import { outputFileName, uniqueOutputNames } from "../output-name";
import { selectionEngine } from "../recipient-engine";
import {
  mixedBatchNote,
  notAddressed,
  signatureNote,
  signedForOthers,
  summariseBatch,
  type SignedResult,
} from "../signature-summary";
import type { Mode, Outcome, RunResult } from "../workspace-state";

/** Output ceiling for UNATTENDED (context-menu) runs; age takes no engine
 *  ceiling, so results are re-checked after the run too. */
export const AUTO_RUN_MAX_BYTES = 1024 * 1024;

export interface RunContext {
  mode: Mode;
  files: File[];
  getInput: () => string;
  hasText: boolean;
  isAge: boolean;
  zipFiles: boolean;
  recipientIds: string[];
  keyId: string | null;
  myKeys: ProtectedKeyBlob[];
  contacts: PublicContactKey[];
  alsoSign: boolean;
  encryptToSelf: boolean;
  defaultKeyId: string | null;
  recentRecipients: string[];
  /** `undefined` when unarmed, never `""` (an empty string is a password). */
  password: string | undefined;
  autoDownloadFiles: boolean;
  autoDownloadText: boolean;
  getKeyHandle: (keyId: string) => number | null;
  unlockWithPasskey: (blob: ProtectedKeyBlob) => Promise<boolean | "cancelled">;
  /** Never ask for a secret, never write to disk. Checked at each prompt,
   *  since a key can close mid-run. */
  unattended: boolean;
  /** Context-menu auto-run only. */
  cap: number | undefined;
  hiddenCharsConfirmed: boolean;
}

export const NONE: Outcome = { kind: "none" };
export const fail = (message: string): Outcome => ({
  kind: "error",
  error: { message },
});

/** Abandons an unattended run over the ceiling. Never shown as an error. */
export class HeldBackForSize extends Error {}

export async function heldBackIfCapped<T>(run: Promise<T>): Promise<T> {
  try {
    return await run;
  } catch (e) {
    if (e instanceof OutputCapReached) throw new HeldBackForSize();
    throw e;
  }
}

export function withinCap<T extends { data: string | Uint8Array }>(
  c: RunContext,
  result: T,
): T {
  if (c.cap !== undefined && result.data.length > c.cap) {
    if (result.data instanceof Uint8Array) result.data.fill(0);
    throw new HeldBackForSize();
  }
  return result;
}

export const fileBytes = async (f: File) =>
  new Uint8Array(await f.arrayBuffer());
export const totalSize = (results: FileResult[]) =>
  formatFileSize(results.reduce((sum, r) => sum + r.data.length, 0));

export function nameApart(results: FileResult[]): string[] {
  const names = uniqueOutputNames(results.map((r) => r.name));
  results.forEach((r, i) => (r.name = names[i]));
  return names;
}

/** The key in effect when it is OpenPGP, else the first PGP key. */
export function pgpSignerId(c: RunContext): string | null {
  const pgpKeys = c.myKeys.filter(isPgpRecord);
  if (c.keyId && pgpKeys.some((k) => k.keyId === c.keyId)) return c.keyId;
  return pgpKeys[0]?.keyId ?? null;
}

export function findSigner(c: RunContext, signerKeyId: string | null) {
  if (!signerKeyId) return null;
  const hex = signerKeyId.toUpperCase();
  // Any of a contact's keys, not only the first.
  return (
    c.contacts.find((ct) =>
      contactRecipients(ct).some((r) => r.keyId.toUpperCase().endsWith(hex)),
    ) ??
    c.myKeys.find((k) => k.keyId.toUpperCase().endsWith(hex)) ??
    null
  );
}

export function signerName(c: RunContext, keyId: string): string {
  const signer = findSigner(c, keyId);
  const userId = signer ? displayUserId(signer) : undefined;
  return userId ? parseUserId(userId).name : keyId.slice(-16);
}

export function placeholderSigner(
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

export function verificationKeys(c: RunContext): string[] {
  return [
    ...c.myKeys.filter(isPgpRecord).map((k) => k.publicKeyArmored),
    ...c.contacts
      .filter((ct) => !isSshRecord(ct))
      .flatMap((ct) => contactRecipients(ct).map((r) => r.armored)),
  ];
}

/** Sets only the keys it decides, so an unsigned result keeps the caller's
 *  status. `notEncrypted` is amber, never green, and gets a card unsigned. */
export function signatureVerdict(
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
      isContact(signer) && !signer.verified && !myIds.includes(signer.keyId);
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

export function batchVerdict(
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
export async function ensureUnlocked(
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
  return { kind: "prompt", prompt: "key", keyId };
}

export function hiddenCharsHold(c: RunContext): Outcome | null {
  if (c.hiddenCharsConfirmed) return null;
  const chars = hiddenCharactersToConfirm(c.getInput());
  return chars.length > 0 ? { kind: "hidden-chars", chars } : null;
}

export function selectedRecipientKeys(c: RunContext) {
  // Own keys win an id both hold (see `resolveSelectedRecipients`).
  return resolveSelectedRecipients(c.recipientIds, c.contacts, c.myKeys);
}

export function recipientNames(c: RunContext): string[] {
  return selectedRecipientKeys(c).map((k) => {
    const uid = k.userIds[0];
    return uid ? formatKeyDisplayName(uid).name : k.keyId.slice(-8);
  });
}

/** Staged files plus any written message as `msg.txt`. Built per run,
 *  never kept: the box stays the one copy of the text. */
export function stagedFiles(c: RunContext): File[] {
  const name = messageFileName(c);
  if (name === null) return c.files;
  return [...c.files, new File([c.getInput()], name, { type: "text/plain" })];
}

export function messageFileName(c: RunContext): string | null {
  if (c.mode !== "encrypt" || c.files.length === 0 || !c.hasText) return null;
  const taken = new Set(c.files.map((f) => f.name));
  let name = "msg.txt";
  for (let n = 2; taken.has(name); n++) name = `msg-${n}.txt`;
  return name;
}

/** The download name. Names only: safe in render. */
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

export function download(
  c: RunContext,
  r: { files?: FileResult[]; binary?: Uint8Array; text?: string },
): void {
  if (r.files && r.files.length > 0) downloadResults(r.files);
  else if (r.binary) downloadBinary(r.binary, outputName(c, !r.text));
  else downloadText(r.text ?? "", outputName(c, false));
}

/** Never for unattended runs: their input is whatever a web page selected. */
export function autoDownload(
  c: RunContext,
  fileInput: boolean,
  r: { files?: FileResult[]; binary?: Uint8Array; text?: string },
) {
  if (c.unattended) return;
  if (fileInput ? c.autoDownloadFiles : c.autoDownloadText) download(c, r);
}

/** Failure must surface: a user trusting history may delete the original. */
export function captureHistory(entry: NewHistoryEntry): void {
  void recordHistory(entry).then((result) => {
    if (result === "failed") {
      toast.error(t("workspace_history_save_failed"), {
        id: "history-save-failed",
      });
    }
  });
}

export const split = (data: string | Uint8Array) =>
  typeof data === "string" ? { text: data } : { binary: data };
