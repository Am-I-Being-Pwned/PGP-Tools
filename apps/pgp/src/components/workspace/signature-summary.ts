import { t, tn } from "~/lib/i18n";
import { formatDate } from "~/lib/i18n/format";
import type { SignatureDetails, SignatureStatus } from "~/lib/pgp/types";
import { displayFileName } from "~/lib/utils/file-name";

export type SignedResult = SignatureDetails & {
  signatureStatus: SignatureStatus;
  signerKeyId: string | null;
};

export type SignerName = (keyId: string) => string;

/**
 * The signed-at time is signer-chosen: shown, not trusted. Every other
 * signature on the message must be listed, never silently dropped.
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
 * Signed FOR others only. A key decrypt has Sequoia enforce this; a
 * password decrypt or verify has no "us", so a forwarded message would
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

/**
 * Encrypted to us but naming no intended recipients: possibly surreptitious
 * forwarding. Many senders omit the subpacket, so a note, not amber.
 */
export function notAddressed(
  r: SignatureDetails,
  { decrypted, notEncrypted }: { decrypted: boolean; notEncrypted: boolean },
): boolean {
  return decrypted && !notEncrypted && r.intendedRecipients.length === 0;
}

export type BatchSummary =
  | { kind: "unsigned" }
  | { kind: "same"; result: SignedResult }
  | { kind: "mixed"; files: { name: string; result: SignedResult }[] };

/** One verdict for the batch, never one file's: a signed file must not
 *  vouch for an unsigned one beside it. */
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
      signerKeyCurrent: batch.every((b) => b.result.signerKeyCurrent),
      signedAt: batch.length === 1 ? first.signedAt : null,
      otherSignerKeyIds: [
        ...new Set(batch.flatMap((b) => b.result.otherSignerKeyIds)),
      ],
      unverifiedSignatures: Math.max(
        ...batch.map((b) => b.result.unverifiedSignatures),
      ),
      // Per file: a union would let a file signed for {you, Bob} vouch for one
      // signed for Bob alone.
      intendedRecipients:
        batch.find((b) => signedForOthers(b.result, myFingerprints))?.result
          .intendedRecipients ?? [],
    },
  };
}

/**
 * File names are attacker-chosen: cleaned (bidi/invisible/control), shortened
 * and quoted so a name can't read as another file's verdict.
 */
export function mixedBatchNote(
  files: { name: string; result: SignedResult }[],
  signerName: SignerName,
): string {
  return files
    .map(({ name, result }) =>
      t("workspace_file_signature", {
        name: `“${displayFileName(name)}”`,
        outcome:
          result.signatureStatus === "valid" && result.signerKeyId
            ? signerName(result.signerKeyId)
            : result.signatureStatus === "unknown_key"
              ? t("workspace_unknown_signer")
              : t("workspace_file_not_signed"),
      }),
    )
    .join("\n");
}
