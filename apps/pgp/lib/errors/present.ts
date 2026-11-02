import { t } from "../i18n";
import { isQuotaExceeded } from "../storage/chunked";
import { errorMessage } from "../utils/errors";
import { AppError } from "./app-error";
import { EngineError } from "./engine-error";

/** What the UI can offer the user to fix the error. A union, not
 *  callbacks, so this module stays decoupled from React. */
export type RemedyAction =
  "import-key" | "unlock" | "retry" | "check-recipient";

/** Curated, user-facing rendering of a caught error. Raw error text only
 *  ever appears in `detail` (collapsed "technical details"). */
export interface PresentedError {
  message: string;
  detail?: string;
  remedy?: { label: string; action: RemedyAction };
}

/** Matched on the raw name so it also catches values that aren't
 *  `instanceof Error` in this realm. */
function isWebAuthnCancelName(e: unknown): boolean {
  const name = e instanceof Object && "name" in e ? e.name : null;
  return (
    name === "NotAllowedError" ||
    name === "AbortError" ||
    name === "InvalidStateError"
  );
}

/** A recipient key ID (8 or 16 hex chars, optional 0x) in raw text. */
function extractKeyId(raw: string): string | null {
  const m = /\b(?:0x)?([0-9A-Fa-f]{16}|[0-9A-F]{8})\b/.exec(raw);
  return m ? m[1].toUpperCase() : null;
}

const retry = () => ({
  label: t("app_error_remedy_try_again"),
  action: "retry" as const,
});
const checkKey = () => ({
  label: t("app_error_remedy_check_key"),
  action: "check-recipient" as const,
});

function fromAppError(e: AppError): PresentedError {
  switch (e.code) {
    case "key-not-found":
      return {
        message: t("app_error_key_not_found"),
        detail: e.message,
        remedy: {
          label: t("app_error_remedy_import_key"),
          action: "import-key",
        },
      };
    case "key-locked":
      return {
        message: t("app_error_key_locked"),
        detail: e.message,
        remedy: { label: t("common_unlock"), action: "unlock" },
      };
    case "vault-locked":
      return {
        message: t("app_error_vault_locked"),
        detail: e.message,
        remedy: { label: t("common_unlock"), action: "unlock" },
      };
    case "weak-password":
      return {
        message: t("app_error_weak_password"),
        detail: e.message,
      };
    case "password-required":
      return {
        message: t("app_error_password_required"),
        detail: e.message,
        remedy: { label: t("common_unlock"), action: "unlock" },
      };
    case "passkey-failed":
      return {
        message: t("app_error_passkey_failed"),
        detail: e.message,
        remedy: retry(),
      };
    case "ssh-passphrase-required":
      // The engine's sentence is the instruction and the import step
      // answers it in place, so: unrewritten, no remedy.
      return { message: e.message };
  }
}

/** Engine errors, by the code the engine tagged them with. The engine's
 *  text is only ever the detail. */
function fromEngineError(e: EngineError): PresentedError {
  const raw = e.message.trim();
  switch (e.code) {
    case "wrong-passphrase":
      return {
        message: t("app_error_wrong_password"),
        detail: raw,
        remedy: retry(),
      };
    case "not-encrypted":
      return { message: t("workspace_status_not_encrypted"), detail: raw };
    case "too-large":
      // The password or key may well have been right.
      return { message: t("app_error_too_large_to_open"), detail: raw };
    case "symmetric-wrong-password":
      // Wrong password and damage are one class: a v4 SKESK can't tell
      // them apart. Never "corrupted": the message is usually fine.
      return {
        message: t("app_error_symmetric_wrong_password"),
        detail: raw,
        remedy: retry(),
      };
    case "ocb-unsupported":
      // No password opens it here, so no retry.
      return { message: t("app_error_ocb_unsupported"), detail: raw };
    case "no-decryption-key": {
      const keyId = extractKeyId(raw);
      return {
        message: keyId
          ? t("app_error_no_decryption_key_with_id", { key_id: keyId })
          : t("app_error_no_decryption_key"),
        detail: raw,
        remedy: {
          label: t("app_error_remedy_import_key"),
          action: "import-key",
        },
      };
    }
    case "not-crx":
      return { message: t("app_error_not_crx"), detail: raw };
    case "crx-unsigned":
      return { message: t("app_error_crx_unsigned"), detail: raw };
    case "text-outside-signature":
      return {
        message: t("app_error_unsigned_text_around_signature"),
        detail: raw,
      };
    case "key-expired":
      return {
        message: t("app_error_key_expired"),
        detail: raw,
        remedy: checkKey(),
      };
    case "key-revoked":
      return {
        message: t("app_error_key_revoked"),
        detail: raw,
        remedy: checkKey(),
      };
    case "not-pgp-data":
      return { message: t("app_error_not_pgp_data"), detail: raw };
  }
}

/** Substring rules for text our engine does not code: Sequoia's / std's
 *  own Display strings, and the decrypt path's tamper refusal. Order
 *  matters: more specific first. */
function fromForeignString(raw: string): PresentedError | null {
  const lower = raw.toLowerCase();

  // Thrown by useWorkspaceOperations' `refuseInvalid`.
  if (lower.includes("tampered")) {
    return { message: t("app_error_tampered"), detail: raw };
  }

  if (lower.includes("expired")) {
    return {
      message: t("app_error_key_expired"),
      detail: raw,
      remedy: checkKey(),
    };
  }
  if (lower.includes("revoked")) {
    return {
      message: t("app_error_key_revoked"),
      detail: raw,
      remedy: checkKey(),
    };
  }

  // Before the generic malformed class: "Malformed packet" is damage,
  // not "not PGP data".
  if (
    lower.includes("malformed packet") ||
    lower.includes("bad checksum") ||
    lower.includes("truncated") ||
    lower.includes("corrupt")
  ) {
    return { message: t("app_error_corrupted"), detail: raw, remedy: retry() };
  }

  if (
    lower.includes("malformed") ||
    lower.includes("invalid armor") ||
    lower.includes("unexpected eof")
  ) {
    return { message: t("app_error_not_pgp_data"), detail: raw };
  }

  return null;
}

/**
 * Turn any caught value into curated, user-facing copy. The raw error
 * text is preserved in `detail`, never shown as the message. Unknown
 * errors fall back to the caller's (already curated) `fallback`.
 */
export function presentError(e: unknown, fallback: string): PresentedError {
  if (isWebAuthnCancelName(e)) {
    return {
      message: t("app_error_passkey_dismissed"),
      remedy: retry(),
    };
  }

  if (e instanceof AppError) return fromAppError(e);
  if (e instanceof EngineError) return fromEngineError(e);

  // Already curated, platform-specific copy.
  if (e instanceof Error && e.name === "PrfNotSupportedError") {
    return { message: e.message };
  }

  if (isQuotaExceeded(e)) {
    return {
      message: t("app_error_storage_full"),
      detail: errorMessage(e, ""),
    };
  }

  const raw = errorMessage(e, "").trim();
  if (raw) {
    const known = fromForeignString(raw);
    if (known) return known;
  }

  return { message: fallback, detail: raw || undefined };
}
