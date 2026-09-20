import type {} from "./prf-types";

import { fromBase64url, toBase64url } from "../encoding.ts";
import { AppError } from "../errors/app-error";
import { t } from "../i18n";

// ── helpers ──────────────────────────────────────────────────────────

function generateChallenge(): ArrayBuffer {
  return crypto.getRandomValues(new Uint8Array(32)).buffer;
}

// ── public API ───────────────────────────────────────────────────────

/** Generate a random 32-byte salt for PRF evaluation. */
export function generatePrfSalt(): ArrayBuffer {
  return crypto.getRandomValues(new Uint8Array(32)).buffer;
}

/** Generate a random 32-byte secret to mix with PRF output via HKDF. */
export function generateStoredSecret(): ArrayBuffer {
  return crypto.getRandomValues(new Uint8Array(32)).buffer;
}

/** Check whether this browser/authenticator combo is likely to support PRF. */
export function checkPrfSupport(): boolean {
  if (typeof window === "undefined") {
    return false;
  }
  const ua = navigator.userAgent.toLowerCase();
  return (
    ua.includes("chrome") || ua.includes("safari") || ua.includes("firefox")
  );
}

export interface PasskeyRegistrationResult {
  credentialId: string; // base64url
  prfEnabled: boolean;
}

/**
 * Register a new passkey with the PRF extension enabled.
 *
 * PRF output is NOT available at registration time — only at authentication.
 * We store the credential ID so we can request PRF later.
 */
export async function registerPasskey(
  userName?: string,
  displayName?: string,
  signal?: AbortSignal,
): Promise<PasskeyRegistrationResult> {
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: generateChallenge(),
      rp: {
        name: "PGP Tools",
        id: window.location.hostname,
      },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: userName ?? t("keygen_passkey_default_user"),
        displayName:
          displayName ?? userName ?? t("keygen_passkey_default_user"),
      },
      pubKeyCredParams: [
        { alg: -7, type: "public-key" }, // ES256
        { alg: -257, type: "public-key" }, // RS256
      ],
      authenticatorSelection: {
        requireResidentKey: true,
        residentKey: "required",
        userVerification: "preferred",
      },
      attestation: "none",
      timeout: 60_000,
      extensions: { prf: {} },
    },
    signal,
  });

  if (!credential || !(credential instanceof PublicKeyCredential)) {
    throw new AppError("passkey-failed", "Passkey registration failed");
  }

  const ext = credential.getClientExtensionResults();
  const prfEnabled = ext.prf?.enabled === true;

  return {
    credentialId: toBase64url(credential.rawId),
    prfEnabled,
  };
}

export interface PasskeyAuthResult {
  prfOutput: Uint8Array;
  /** PRF output for `secondSalt`, present iff one was requested and the
   *  authenticator evaluated it. Caller-owned; `.fill(0)` it too. */
  secondOutput?: Uint8Array;
}

/**
 * Authenticate with an existing passkey and derive an AES-256-GCM key
 * from the PRF output.
 *
 * The same (credentialId, salt) pair always produces the same key.
 *
 * `secondSalt` asks the authenticator to evaluate a second salt in the
 * SAME ceremony (the PRF extension allows exactly two). "Unlock keys
 * with the vault" uses it to re-seal a key under the master salt off
 * the one prompt the user was already answering for that key -- the
 * only way to get a second salt's output without a second prompt, since
 * one salt's output says nothing about another's.
 */
export async function authenticateAndGetPrf(
  credentialId: string,
  prfSalt: BufferSource,
  signal?: AbortSignal,
  secondSalt?: BufferSource,
): Promise<PasskeyAuthResult> {
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: generateChallenge(),
      rpId: window.location.hostname,
      timeout: 60_000,
      userVerification: "required",
      allowCredentials: [
        {
          id: fromBase64url(credentialId),
          type: "public-key",
          transports: ["usb", "nfc", "ble", "hybrid", "internal"],
        },
      ],
      extensions: {
        prf: {
          eval: secondSalt
            ? { first: prfSalt, second: secondSalt }
            : { first: prfSalt },
        },
      },
    },
    signal,
  });

  if (!credential || !(credential instanceof PublicKeyCredential)) {
    throw new AppError("passkey-failed", "Passkey authentication failed");
  }

  const ext = credential.getClientExtensionResults();
  const prfOutput = ext.prf?.results?.first;

  if (!prfOutput) {
    throw new PrfNotSupportedError();
  }

  // Return raw PRF bytes - HKDF happens in WASM so the derived key
  // never enters the JS heap.
  const second = ext.prf?.results?.second;
  return {
    prfOutput: new Uint8Array(prfOutput as ArrayBuffer),
    ...(secondSalt && second
      ? { secondOutput: new Uint8Array(second as ArrayBuffer) }
      : {}),
  };
}

/**
 * True if `e` looks like the user cancelling / aborting a WebAuthn
 * ceremony, OR a "request already pending" race that's effectively
 * a cancel-and-retry. Use to decide whether to show an error toast
 * vs silently ignore.
 */
export function isWebAuthnCancel(e: unknown): boolean {
  if (!(e instanceof Error)) return false;
  return (
    e.name === "NotAllowedError" ||
    e.name === "AbortError" ||
    e.name === "InvalidStateError"
  );
}

/** Thrown when the authenticator doesn't support PRF. */
export class PrfNotSupportedError extends Error {
  constructor() {
    const ua = navigator.userAgent;
    const parts = [t("keygen_prf_unsupported_intro")];
    if (ua.includes("Mac")) {
      parts.push(t("keygen_prf_unsupported_mac"));
    } else if (ua.includes("Windows")) {
      parts.push(t("keygen_prf_unsupported_windows"));
    }
    if (ua.includes("Chrome") && !ua.includes("Android")) {
      parts.push(t("keygen_prf_unsupported_chrome"));
    }
    super(parts.join(" "));
    this.name = "PrfNotSupportedError";
  }
}
