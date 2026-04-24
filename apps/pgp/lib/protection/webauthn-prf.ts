import type {} from "./prf-types";

import { fromBase64url, toBase64url } from "../encoding.ts";

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
        name: userName ?? "PGP Key Protection",
        displayName: displayName ?? userName ?? "PGP Key Protection",
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
  });

  if (!credential || !(credential instanceof PublicKeyCredential)) {
    throw new Error("Passkey registration failed");
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
}

/**
 * Authenticate with an existing passkey and derive an AES-256-GCM key
 * from the PRF output.
 *
 * The same (credentialId, salt) pair always produces the same key.
 */
export async function authenticateAndGetPrf(
  credentialId: string,
  prfSalt: ArrayBuffer,
  signal?: AbortSignal,
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
        prf: { eval: { first: prfSalt } },
      },
    },
    signal,
  });

  if (!credential || !(credential instanceof PublicKeyCredential)) {
    throw new Error("Passkey authentication failed");
  }

  const ext = credential.getClientExtensionResults();
  const prfOutput = ext.prf?.results?.first;

  if (!prfOutput) {
    throw new PrfNotSupportedError();
  }

  // Return raw PRF bytes - HKDF happens in WASM so the derived key
  // never enters the JS heap.
  return { prfOutput: new Uint8Array(prfOutput as ArrayBuffer) };
}


/** Thrown when the authenticator doesn't support PRF. */
export class PrfNotSupportedError extends Error {
  constructor() {
    const ua = navigator.userAgent;
    let msg = "PRF not supported by this authenticator. ";
    if (ua.includes("Mac")) {
      msg += "macOS requires 15+ with iCloud Keychain. ";
    } else if (ua.includes("Windows")) {
      msg +=
        "Windows Hello doesn't support PRF - use a security key (e.g. YubiKey). ";
    }
    if (ua.includes("Chrome") && !ua.includes("Android")) {
      msg +=
        "Chrome profile passkeys may not support PRF - try Google Password Manager or an external key.";
    }
    super(msg.trim());
    this.name = "PrfNotSupportedError";
  }
}
