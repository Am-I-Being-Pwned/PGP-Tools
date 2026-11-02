import { signZipWithCrxKey, verifyCrxFile } from "~/lib/crx/operations";
import type { CrxSigningKeyBlob } from "~/lib/crx/types";
import { presentError } from "~/lib/errors/present";
import { t, tn } from "~/lib/i18n";
import { MAX_VERIFY_FILE_BYTES, MAX_VERIFY_FILE_LABEL } from "~/lib/limits";
import * as pgpOps from "~/lib/pgp/operations";
import { isWebAuthnCancel } from "~/lib/protection/webauthn-prf";
import type { FileResult } from "~/lib/utils/download";
import { displayFileName } from "~/lib/utils/file-name";
import { outputFileName } from "../output-name";
import type { Outcome } from "../workspace-state";
import {
  autoDownload,
  batchVerdict,
  captureHistory,
  ensureUnlocked,
  fail,
  fileBytes,
  HeldBackForSize,
  heldBackIfCapped,
  hiddenCharsHold,
  nameApart,
  NONE,
  pgpSignerId,
  signatureVerdict,
  verificationKeys,
  withinCap,
  type RunContext,
} from "./context";

export async function sign(c: RunContext): Promise<Outcome> {
  const keyId = pgpSignerId(c);
  if (!keyId) {
    return fail(
      c.myKeys.length > 0
        ? t("workspace_error_no_signing_key_ssh")
        : t("workspace_error_no_signing_key"),
    );
  }
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

export async function verify(c: RunContext): Promise<Outcome> {
  try {
    // Size first: nothing past the engine's cap can verify.
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

/** Single staged .zip only; gated upstream. */
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
