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
        message:
          "That key is no longer in your keyring, so nothing was saved. Re-import the key and try again.",
        detail: e.message,
        remedy: { label: "Import key", action: "import-key" },
      };
    case "key-locked":
      return {
        message: "This key is locked. Unlock it and try again.",
        detail: e.message,
        remedy: { label: "Unlock", action: "unlock" },
      };
    case "vault-locked":
      return {
        message:
          "Your vault is locked, so nothing was changed. Unlock it and run this again.",
        detail: e.message,
        remedy: { label: "Unlock", action: "unlock" },
      };
    case "weak-password":
      return {
        message: "That password is too short. Use at least 8 characters.",
        detail: e.message,
      };
    case "password-required":
      return {
        message:
          "This key needs its password. Enter the key password to unlock it.",
        detail: e.message,
        remedy: { label: "Unlock", action: "unlock" },
      };
    case "passkey-failed":
      return {
        message:
          "Your passkey didn't complete. Try again, or unlock with a different method.",
        detail: e.message,
        remedy: { label: "Try again", action: "retry" },
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
      message: "Wrong password for this key. Check it and try again.",
      detail: raw,
      remedy: { label: "Try again", action: "retry" },
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
      message:
        "That password didn't open this message. Check it and try again - if you're sure it's right, the message may be damaged.",
      detail: raw,
      remedy: { label: "Try again", action: "retry" },
    };
  }

  // A message we cannot read whatever the password is: GnuPG's
  // `--force-ocb` writes the pre-RFC-9580 AEAD packet, which Sequoia's
  // policy rejects. Named separately from the rule above because telling
  // someone to check a password that will never work is worse than
  // telling them nothing.
  if (lower.includes("aead (ocb) encrypted-data format")) {
    return {
      message:
        "This message uses an older AEAD (OCB) format this app can't read. Ask the sender to re-send it encrypted normally - any password they choose will work, it's the format that isn't supported.",
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
      message:
        "This message is encrypted to a key you don't hold" +
        (keyId ? ` (key ID ${keyId})` : "") +
        ". Import that private key, or ask the sender to encrypt to one of your keys.",
      detail: raw,
      remedy: { label: "Import key", action: "import-key" },
    };
  }

  // CRX-specific verification failures. Checked before the tamper class:
  // the wasm CRX-mismatch string also contains "tampered".
  if (
    lower.includes("not a crx file") ||
    lower.includes("unsupported crx version")
  ) {
    return {
      message:
        "This isn't a Chrome extension package this tool can verify. Choose a CRX3 (.crx) file.",
      detail: raw,
    };
  }
  if (lower.includes("crx is unsigned by this key")) {
    return {
      message:
        "The CRX signature doesn't match: it wasn't signed by this key, or the file was modified after signing. Get a fresh copy from the publisher.",
      detail: raw,
    };
  }

  // Tampered signature (thrown by decrypt's signature check).
  if (lower.includes("tampered")) {
    return {
      message:
        "Signature verification failed - this message may have been tampered with. Don't trust the contents; ask the sender to re-send it.",
      detail: raw,
    };
  }

  // Expired / revoked key material.
  if (lower.includes("expired")) {
    return {
      message:
        "A key involved in this operation has expired. Ask the key's owner for an updated key, then import it.",
      detail: raw,
      remedy: { label: "Check key", action: "check-recipient" },
    };
  }
  if (lower.includes("revoked")) {
    return {
      message:
        "A key involved in this operation has been revoked by its owner. Get their replacement key, then import it.",
      detail: raw,
      remedy: { label: "Check key", action: "check-recipient" },
    };
  }

  // Weak-algorithm keys rejected by Sequoia's StandardPolicy.
  if (
    lower.includes("rejected by security policy") ||
    lower.includes("self-signed with sha-1") ||
    lower.includes("md5 signatures")
  ) {
    return {
      message:
        "This key uses a signature algorithm that is no longer considered secure. Ask the key's owner to reissue it with SHA-256 or stronger.",
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
      message:
        "The data is corrupted or was cut off. Get a fresh, complete copy and try again.",
      detail: raw,
      remedy: { label: "Try again", action: "retry" },
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
      message:
        "This doesn't look like PGP data. Make sure you pasted the full armored block, including the BEGIN and END lines.",
      detail: raw,
    };
  }

  // Passkey failures reported as plain strings (older paths / wasm).
  if (
    lower.includes("passkey authentication failed") ||
    lower.includes("passkey registration failed")
  ) {
    return {
      message:
        "Your passkey didn't complete. Try again, or unlock with a different method.",
      detail: raw,
      remedy: { label: "Try again", action: "retry" },
    };
  }

  // Locked-session errors reported as plain strings.
  if (lower.includes("vault is locked") || lower.includes("is not unlocked")) {
    return {
      message:
        "Your vault is locked, so nothing was changed. Unlock it and run this again.",
      detail: raw,
      remedy: { label: "Unlock", action: "unlock" },
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
      message:
        "The passkey prompt was dismissed. Run the operation again when you're ready.",
      remedy: { label: "Try again", action: "retry" },
    };
  }

  if (e instanceof AppError) return fromAppError(e);

  // PrfNotSupportedError already carries curated, platform-specific copy.
  if (e instanceof Error && e.name === "PrfNotSupportedError") {
    return { message: e.message };
  }

  if (isQuotaExceeded(e)) {
    return {
      message:
        "Browser storage is full, so this couldn't be saved. Remove keys or contacts you no longer need, then try again.",
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
