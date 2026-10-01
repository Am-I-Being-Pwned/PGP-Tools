import type {} from "./prf-types";

import { fromBase64url, toBase64url } from "../encoding.ts";
import { AppError } from "../errors/app-error";
import { t } from "../i18n";

// ── helpers ──────────────────────────────────────────────────────────

function generateChallenge(): ArrayBuffer {
  return crypto.getRandomValues(new Uint8Array(32)).buffer;
}

// ── ceremony gate ────────────────────────────────────────────────────
//
// Browsers allow ONE pending WebAuthn request at a time, and the OS
// dialog behind it does not go away the instant its promise rejects.
// macOS tears its sheet down fast enough that "abort the old one, start
// a new one" looks fine there; Windows Hello and Chrome's own Linux UI
// close asynchronously, so a request issued straight after an abort
// trips "A request is already pending" (InvalidStateError, or
// OperationError in newer Chrome) -- which used to be swallowed as a
// cancel, so the user clicked and nothing happened.
//
// Every ceremony therefore goes through this gate: a new one supersedes
// the open one, waits for it to settle, and retries briefly if the
// browser still holds the old request. UI reads `isPasskeyPromptOpen`
// (via `subscribePasskeyPrompt`) to show a waiting state instead of
// re-enabling a button the user will click again.

/** How long to wait before retrying a "request already pending". */
const PENDING_RETRY_DELAY_MS = 300;
const PENDING_RETRIES = 3;
/** A NotAllowedError faster than this never reached the user: the
 *  browser refused to show a prompt (most often: the page lacked focus). */
const PROMPT_BLOCKED_WITHIN_MS = 500;

interface OpenCeremony {
  controller: AbortController;
  settled: Promise<void>;
}

let openCeremony: OpenCeremony | null = null;
const listeners = new Set<() => void>();

function notify(): void {
  for (const l of listeners) l();
}

/** True while a passkey prompt is (or is about to be) on screen. */
export function isPasskeyPromptOpen(): boolean {
  return openCeremony !== null;
}

/** Subscribe to `isPasskeyPromptOpen` changes (useSyncExternalStore). */
export function subscribePasskeyPrompt(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Cancel whatever passkey prompt is open, if any. The ceremony's
 *  caller sees an AbortError, which `isWebAuthnCancel` treats as a
 *  cancel. */
export function cancelPasskeyPrompt(): void {
  openCeremony?.controller.abort();
}

function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function errorName(e: unknown): string {
  return e instanceof Object && "name" in e ? String(e.name) : "";
}

/** "A request is already pending": InvalidStateError in older Chrome,
 *  OperationError in newer. Only the message tells the latter apart
 *  from a genuine authenticator error. */
function isPendingError(e: unknown): boolean {
  const name = errorName(e);
  if (name === "InvalidStateError") return true;
  return (
    name === "OperationError" &&
    e instanceof Error &&
    /pending/i.test(e.message)
  );
}

/** The browser would not show a passkey prompt at all -- it refused
 *  instantly (no focus), or another request never let go. Distinct from
 *  a cancel: the user did nothing, so silence would read as a dead
 *  button. */
export class PasskeyPromptBlockedError extends Error {
  constructor() {
    super(t("shared_passkey_prompt_blocked"));
    this.name = "PasskeyPromptBlockedError";
  }
}

async function runCeremony<T>(
  start: (signal: AbortSignal) => Promise<T>,
  signal?: AbortSignal,
): Promise<T> {
  const controller = new AbortController();
  let markSettled!: () => void;
  const entry: OpenCeremony = {
    controller,
    settled: new Promise<void>((r) => (markSettled = r)),
  };
  // Claim the slot synchronously so two callers racing in the same tick
  // queue behind each other rather than both starting.
  const previous = openCeremony;
  openCeremony = entry;
  notify();

  const forwardAbort = () => controller.abort(signal?.reason);
  if (signal?.aborted) forwardAbort();
  else signal?.addEventListener("abort", forwardAbort, { once: true });

  try {
    if (previous) {
      previous.controller.abort();
      await previous.settled;
    }
    for (let attempt = 0; ; attempt++) {
      controller.signal.throwIfAborted();
      const startedAt = performance.now();
      try {
        return await start(controller.signal);
      } catch (e) {
        if (controller.signal.aborted) throw e;
        if (isPendingError(e)) {
          if (attempt < PENDING_RETRIES) {
            await delay(PENDING_RETRY_DELAY_MS);
            continue;
          }
          throw new PasskeyPromptBlockedError();
        }
        if (
          errorName(e) === "NotAllowedError" &&
          performance.now() - startedAt < PROMPT_BLOCKED_WITHIN_MS
        ) {
          throw new PasskeyPromptBlockedError();
        }
        throw e;
      }
    }
  } finally {
    signal?.removeEventListener("abort", forwardAbort);
    if (openCeremony === entry) {
      openCeremony = null;
      notify();
    }
    markSettled();
  }
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
  /** What the browser REPORTED. Advisory only: Chrome/Edge up to 146
   *  report false for Windows Hello passkeys that do evaluate PRF at
   *  authentication, so never refuse a credential on this alone --
   *  `authenticateAndGetPrf` throwing PrfNotSupportedError is the
   *  authoritative "no". */
  prfEnabled: boolean;
  /** PRF output for `prfSalt`, when one was passed and the authenticator
   *  evaluated it during registration (newer browsers/authenticators
   *  do). Saves the follow-up prompt. Caller-owned; `.fill(0)` it. */
  prfOutput?: Uint8Array;
}

/**
 * Register a new passkey with the PRF extension enabled.
 *
 * Pass `prfSalt` to also ask for the PRF output in the same ceremony.
 * Many authenticators only evaluate PRF at authentication, so a caller
 * must still fall back to `authenticateAndGetPrf` when `prfOutput` is
 * absent.
 */
export async function registerPasskey(
  userName?: string,
  displayName?: string,
  signal?: AbortSignal,
  prfSalt?: BufferSource,
): Promise<PasskeyRegistrationResult> {
  const credential = await runCeremony(
    (s) => createCredential(userName, displayName, s, prfSalt),
    signal,
  );

  if (!credential || !(credential instanceof PublicKeyCredential)) {
    throw new AppError("passkey-failed", "Passkey registration failed");
  }

  const ext = credential.getClientExtensionResults();
  const prfEnabled = ext.prf?.enabled === true;
  const first = prfSalt ? ext.prf?.results?.first : undefined;

  return {
    credentialId: toBase64url(credential.rawId),
    prfEnabled,
    ...(first ? { prfOutput: new Uint8Array(first as ArrayBuffer) } : {}),
  };
}

function createCredential(
  userName: string | undefined,
  displayName: string | undefined,
  signal: AbortSignal,
  prfSalt: BufferSource | undefined,
): Promise<Credential | null> {
  return navigator.credentials.create({
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
        // Matches authentication's "required": with "preferred", a
        // PIN-less security key registers fine and is then forced into
        // PIN setup at its first unlock.
        userVerification: "required",
      },
      attestation: "none",
      timeout: 120_000,
      extensions: { prf: prfSalt ? { eval: { first: prfSalt } } : {} },
    },
    signal,
  });
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
  const credential = await runCeremony(
    (s) =>
      navigator.credentials.get({
        publicKey: {
          challenge: generateChallenge(),
          rpId: window.location.hostname,
          timeout: 120_000,
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
        signal: s,
      }),
    signal,
  );

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
