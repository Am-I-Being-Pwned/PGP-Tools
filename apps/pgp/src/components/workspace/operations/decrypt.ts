import * as ageOps from "~/lib/age/operations";
import { presentError } from "~/lib/errors/present";
import { t, tn } from "~/lib/i18n";
import * as pgpOps from "~/lib/pgp/operations";
import type { DecryptOptions, DecryptResult } from "~/lib/pgp/types";
import { isSshRecord } from "~/lib/storage/key-kind";
import type { FileResult } from "~/lib/utils/download";
import { displayFileName } from "~/lib/utils/file-name";
import { isZipArchive } from "~/lib/utils/zip";
import { outputFileName } from "../output-name";
import type { SignedResult } from "../signature-summary";
import type { Outcome } from "../workspace-state";
import {
  autoDownload,
  batchVerdict,
  ensureUnlocked,
  fail,
  fileBytes,
  HeldBackForSize,
  heldBackIfCapped,
  nameApart,
  NONE,
  signatureVerdict,
  split,
  totalSize,
  verificationKeys,
  withinCap,
  type RunContext,
} from "./context";

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

/** A matching key wins over the password. Detection is redone here, not
 *  read off the scan effect: a paste then an instant click would race it. */
export async function decrypt(c: RunContext): Promise<Outcome> {
  if (c.isAge) {
    if (!c.keyId) return fail(t("workspace_error_select_decryption_key"));
    const handle = await ensureUnlocked(c, c.keyId);
    if (typeof handle !== "number") return handle;
    return decryptAge(c, handle);
  }

  const input = await stagedPgpInput(c);
  // Unreadable headers fall through to the key path, whose errors say so.
  const encryption = await pgpOps.messageEncryption(input).catch(() => null);

  // Checked BEFORE any key unlocks: an unencrypted "PGP MESSAGE" would
  // otherwise dress up anything ever signed in public as private.
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

/** A wrong password is `rejected`, so the prompt stays up for a retype. */
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

/** Shared by the key, password and unencrypted paths so they cannot drift.
 *  A tampered signature anywhere fails the whole run and shows nothing. */
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
        // ignoreBOM: a leading BOM is part of the file and must round-trip.
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
    return {
      kind: "error",
      error: presentError(err, t("workspace_error_decrypt_failed")),
    };
  }
}
