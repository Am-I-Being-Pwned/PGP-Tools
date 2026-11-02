import * as ageOps from "~/lib/age/operations";
import {
  buildEncryptRecipients,
  sshPasswordReason,
  toSelectedRecipient,
} from "~/lib/encrypt-recipients";
import { t, tn } from "~/lib/i18n";
import * as pgpOps from "~/lib/pgp/operations";
import type { EncryptInput } from "~/lib/pgp/types";
import { updateRecentRecipients } from "~/lib/recipient-ordering";
import { preferencesStore } from "~/lib/storage/preferences-store";
import type { FileResult } from "~/lib/utils/download";
import { zipFiles } from "~/lib/utils/zip";
import { outputFileName } from "../output-name";
import { selectionEngine } from "../recipient-engine";
import type { Outcome } from "../workspace-state";
import {
  autoDownload,
  captureHistory,
  ensureUnlocked,
  fail,
  fileBytes,
  hiddenCharsHold,
  nameApart,
  pgpSignerId,
  recipientNames,
  selectedRecipientKeys,
  split,
  stagedFiles,
  totalSize,
  type RunContext,
} from "./context";

export async function encrypt(c: RunContext): Promise<Outcome> {
  const recipients = selectedRecipientKeys(c);
  if (recipients.length === 0 && c.password === undefined) {
    return fail(t("workspace_error_need_recipient_or_password"));
  }
  const isAge = selectionEngine(recipients) === "ssh";
  // Backstop: age never sees the password, so this would SILENTLY drop it.
  if (isAge && c.password !== undefined) return fail(sshPasswordReason());

  // One answer for both the recipient set and the handle, so the key the
  // message says signed it is the one that did.
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
  // The password was for THIS message; kept, it would quietly arm the next.
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

  // Swallowed: a toast over a successful encrypt would read as it failing.
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
