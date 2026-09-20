import { t } from "../i18n";
import { isQuotaExceeded } from "../storage/chunked";
import { errorMessage } from "../utils/errors";
import { AppError } from "./app-error";

/** What the UI can offer the user to fix the error. Kept as a small
 *  union (not callbacks) so this module stays decoupled from React --
 *  each surface maps actions to its own handlers, or ignores them. */
export type RemedyAction =
  "import-key" | "unlock" | "retry" | "check-recipient";

/** A curated, user-facing rendering of a caught error. `message` always
 *  states what happened and what to do; raw error text only ever appears
 *  in `detail` (rendered collapsed as "technical details"). */
export interface PresentedError {
  message: string;
  detail?: string;
  remedy?: { label: string; action: RemedyAction };
}

/** Cancelling a WebAuthn prompt is a decision, not a failure. Mirrors
 *  isWebAuthnCancel but on the raw name so it also matches values that
 *  aren't `instanceof Error` in this realm. */
function isWebAuthnCancelName(e: unknown): boolean {
  const name = e instanceof Object && "name" in e ? e.name : null;
  return (
    name === "NotAllowedError" ||
    name === "AbortError" ||
    name === "InvalidStateError"
  );
}

/** Pull a recipient key ID (8 or 16 hex chars, optional 0x) out of a raw
 *  error string, so "encrypted to a key you don't hold" can say which. */
function extractKeyId(raw: string): string | null {
  const m = /\b(?:0x)?([0-9A-Fa-f]{16}|[0-9A-F]{8})\b/.exec(raw);
  return m ? m[1].toUpperCase() : null;
}

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
        remedy: { label: t("app_error_remedy_try_again"), action: "retry" },
      };
    case "ssh-passphrase-required":
      // The engine's own sentence already says exactly what to do, and
      // the import step answers it in place by revealing its passphrase
      // field -- so this is passed through unrewritten and carries no
      // remedy, which would send the user somewhere else mid-import.
      return { message: e.message };
  }
}

/** Substring rules for errors we don't construct ourselves -- mostly
 *  Rust/Sequoia strings surfaced verbatim through wasm-bindgen. Order
 *  matters: more specific classes come first. */
function fromKnownString(raw: string): PresentedError | null {
  const lower = raw.toLowerCase();

  // Wrong password / bad passphrase (Sequoia S2K + our AES-GCM unlock).
  if (
    lower.includes("incorrect passphrase") ||
    lower.includes("bad passphrase") ||
    lower.includes("wrong credentials or corrupted data")
  ) {
    return {
      message: t("app_error_wrong_password"),
      detail: raw,
      remedy: { label: t("app_error_remedy_try_again"), action: "retry" },
    };
  }

  // Symmetric decrypt: the password did not open the message. The engine
  // folds two different failure POINTS into this one phrase on purpose --
  // a v4 SKESK unwraps the session key with no integrity check, so a
  // wrong password fails later as an MDC mismatch, while an AEAD one
  // fails at the unwrap. Both are the same answer to the user.
  //
  // BEFORE the corrupt/malformed rules below, which the raw Sequoia text
  // riding along in this string would otherwise match -- "the data is
  // corrupted, get a fresh copy" is the wrong instruction for a message
  // that is fine and a password that is not.
  if (lower.includes("wrong password, or this message is damaged")) {
    return {
      message: t("app_error_symmetric_wrong_password"),
      detail: raw,
      remedy: { label: t("app_error_remedy_try_again"), action: "retry" },
    };
  }

  // A message we cannot read whatever the password is: GnuPG's
  // `--force-ocb` writes the pre-RFC-9580 AEAD packet, which Sequoia's
  // policy rejects. Named separately from the rule above because telling
  // someone to check a password that will never work is worse than
  // telling them nothing.
  if (lower.includes("aead (ocb) encrypted-data format")) {
    return {
      message: t("app_error_ocb_unsupported"),
      detail: raw,
    };
  }

  // Encrypted to a key we don't hold.
  if (
    lower.includes("no suitable decryption key") ||
    lower.includes("no matching secret key")
  ) {
    const keyId = extractKeyId(raw);
    return {
      message: keyId
        ? t("app_error_no_decryption_key_with_id", { key_id: keyId })
        : t("app_error_no_decryption_key"),
      detail: raw,
      remedy: { label: t("app_error_remedy_import_key"), action: "import-key" },
    };
  }

  // CRX-specific verification failures. Checked before the tamper class:
  // the wasm CRX-mismatch string also contains "tampered".
  if (
    lower.includes("not a crx file") ||
    lower.includes("unsupported crx version")
  ) {
    return {
      message: t("app_error_not_crx"),
      detail: raw,
    };
  }
  if (lower.includes("crx is unsigned by this key")) {
    return {
      message: t("app_error_crx_unsigned"),
      detail: raw,
    };
  }

  // Tampered signature (thrown by decrypt's signature check).
  if (lower.includes("tampered")) {
    return {
      message: t("app_error_tampered"),
      detail: raw,
    };
  }

  // Expired / revoked key material.
  if (lower.includes("expired")) {
    return {
      message: t("app_error_key_expired"),
      detail: raw,
      remedy: {
        label: t("app_error_remedy_check_key"),
        action: "check-recipient",
      },
    };
  }
  if (lower.includes("revoked")) {
    return {
      message: t("app_error_key_revoked"),
      detail: raw,
      remedy: {
        label: t("app_error_remedy_check_key"),
        action: "check-recipient",
      },
    };
  }

  // Weak-algorithm keys rejected by Sequoia's StandardPolicy.
  if (
    lower.includes("rejected by security policy") ||
    lower.includes("self-signed with sha-1") ||
    lower.includes("md5 signatures")
  ) {
    return {
      message: t("app_error_weak_algorithm"),
      detail: raw,
    };
  }

  // Corrupted packet data (before the generic malformed/armor class:
  // "Malformed packet" must not read as "not PGP data").
  if (
    lower.includes("malformed packet") ||
    lower.includes("bad checksum") ||
    lower.includes("truncated") ||
    lower.includes("corrupt")
  ) {
    return {
      message: t("app_error_corrupted"),
      detail: raw,
      remedy: { label: t("app_error_remedy_try_again"), action: "retry" },
    };
  }

  // Malformed / not-armored input.
  if (
    lower.includes("malformed") ||
    lower.includes("invalid armor") ||
    lower.includes("no armored data") ||
    lower.includes("unexpected eof") ||
    lower.includes("no openpgp certificate found")
  ) {
    return {
      message: t("app_error_not_pgp_data"),
      detail: raw,
    };
  }

  // Passkey failures reported as plain strings (older paths / wasm).
  if (
    lower.includes("passkey authentication failed") ||
    lower.includes("passkey registration failed")
  ) {
    return {
      message: t("app_error_passkey_failed"),
      detail: raw,
      remedy: { label: t("app_error_remedy_try_again"), action: "retry" },
    };
  }

  // Locked-session errors reported as plain strings.
  if (lower.includes("vault is locked") || lower.includes("is not unlocked")) {
    return {
      message: t("app_error_vault_locked"),
      detail: raw,
      remedy: { label: t("common_unlock"), action: "unlock" },
    };
  }

  return null;
}

/**
 * Turn any caught value into curated, user-facing copy. Every message
 * states what happened and what to do; the raw error text is preserved
 * in `detail`, never shown as the message. Unknown errors fall back to
 * the caller-supplied `fallback` (which should already be curated for
 * the operation that failed).
 */
export function presentError(e: unknown, fallback: string): PresentedError {
  // Backing out of a passkey prompt is a decision, not a failure.
  if (isWebAuthnCancelName(e)) {
    return {
      message: t("app_error_passkey_dismissed"),
      remedy: { label: t("app_error_remedy_try_again"), action: "retry" },
    };
  }

  if (e instanceof AppError) return fromAppError(e);

  // PrfNotSupportedError already carries curated, platform-specific copy.
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
    const known = fromKnownString(raw);
    if (known) return known;
  }

  return { message: fallback, detail: raw || undefined };
}
