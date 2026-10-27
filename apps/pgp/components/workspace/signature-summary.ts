import type { SignatureDetails, SignatureStatus } from "../../lib/pgp/types";
import { t, tn } from "../../lib/i18n";
import { formatDate } from "../../lib/i18n/format";

/** The signature half of a verify or decrypt result. */
export type SignedResult = SignatureDetails & {
  signatureStatus: SignatureStatus;
  signerKeyId: string | null;
};

/** Names a signer by key id: their display name, else the key id. */
export type SignerName = (keyId: string) => string;

/**
 * What the signer card says beyond "verified": when the signature claims
 * it was made (the signer chooses that, so it is shown, not trusted),
 * whether the key has been retired since, and every other signature on
 * the message -- none of which may be silently dropped.
 */
export function signatureNote(
  r: SignatureDetails,
  signerName: SignerName,
  forOthers = false,
): string | null {
  const parts: string[] = [];
  if (forOthers) {
    parts.push(
      t("workspace_signed_for_others", {
        names: r.intendedRecipients.map(signerName).join(", "),
      }),
    );
  }
  if (r.signedAt !== null) {
    parts.push(t("workspace_signed_on", { date: formatDate(r.signedAt) }));
  }
  if (!r.signerKeyCurrent) parts.push(t("workspace_signer_key_retired"));
  if (r.otherSignerKeyIds.length > 0) {
    parts.push(
      t("workspace_also_signed_by", {
        names: r.otherSignerKeyIds.map(signerName).join(", "),
      }),
    );
  }
  if (r.unverifiedSignatures > 0) {
    parts.push(tn("workspace_unverified_cosigners", r.unverifiedSignatures));
  }
  return parts.length > 0 ? parts.join(" · ") : null;
}

/**
 * The signature names who it was FOR, and none of them is one of the
 * user's keys. Opening a message with a key, Sequoia enforces the list
 * itself; a password decrypt or a verify has no "us" to check against,
 * so a message Alice signed for Bob, re-wrapped and passed on, would
 * otherwise read as addressed to whoever opens it.
 */
export function signedForOthers(
  r: SignatureDetails,
  myFingerprints: readonly string[],
): boolean {
  if (r.intendedRecipients.length === 0) return false;
  const mine = new Set(myFingerprints.map((f) => f.toUpperCase()));
  return !r.intendedRecipients.some((f) => mine.has(f.toUpperCase()));
}

export type BatchSummary =
  /** Nothing in the batch is signed: no card at all. */
  | { kind: "unsigned" }
  /** Every file good, every one by the same key: that signer's card. */
  | { kind: "same"; result: SignedResult }
  /** Anything else: an amber card saying, file by file, who signed what. */
  | { kind: "mixed"; files: { name: string; result: SignedResult }[] };

/**
 * One verdict for a batch of files, which must never be the verdict of
 * just one of them: the card used to show whichever file set it last, so
 * one genuinely signed file vouched for an unsigned one beside it.
 */
export function summariseBatch(
  batch: { name: string; result: SignedResult }[],
  myFingerprints: readonly string[] = [],
): BatchSummary {
  const first = batch.at(0)?.result;
  if (!first || batch.every((b) => b.result.signatureStatus === "unsigned")) {
    return { kind: "unsigned" };
  }
  const sameSigner = batch.every(
    ({ result }) =>
      result.signatureStatus === "valid" &&
      result.signerKeyId === first.signerKeyId,
  );
  if (!sameSigner) return { kind: "mixed", files: batch };
  return {
    kind: "same",
    result: {
      ...first,
      // Amber if ANY file was signed with the key after it was retired.
      signerKeyCurrent: batch.every((b) => b.result.signerKeyCurrent),
      // Each file has its own date; one date would describe one file.
      signedAt: batch.length === 1 ? first.signedAt : null,
      otherSignerKeyIds: [
        ...new Set(batch.flatMap((b) => b.result.otherSignerKeyIds)),
      ],
      unverifiedSignatures: Math.max(
        ...batch.map((b) => b.result.unverifiedSignatures),
      ),
      // Judged per file: a union of the lists would let one file signed
      // for {you, Bob} vouch for another signed for Bob alone. If any
      // file was signed for others, the batch says so.
      intendedRecipients:
        batch.find((b) => signedForOthers(b.result, myFingerprints))?.result
          .intendedRecipients ?? [],
    },
  };
}

/** The mixed card's note: each file and what signed it. */
export function mixedBatchNote(
  files: { name: string; result: SignedResult }[],
  signerName: SignerName,
): string {
  return files
    .map(({ name, result }) =>
      t("workspace_file_signature", {
        name,
        outcome:
          result.signatureStatus === "valid" && result.signerKeyId
            ? signerName(result.signerKeyId)
            : result.signatureStatus === "unknown_key"
              ? t("workspace_unknown_signer")
              : t("workspace_file_not_signed"),
      }),
    )
    .join(" · ");
}
