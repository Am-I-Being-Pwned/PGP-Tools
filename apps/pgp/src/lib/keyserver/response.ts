/**
 * Parse a keys.openpgp.org `/vks/v1/by-*` response into a closed result
 * union. Sibling of `lib/github/response.ts`, same two rules: shape
 * validation only (the wasm engine decides validity, panel-side), and
 * tagged codes only -- the 404 body quotes the query back (attacker-
 * influenced) and must not reach a render.
 */

import { splitPublicKeyBlocks } from "~/lib/armor-blocks";
import type { KeyserverKeyFailure } from "~/lib/messages";

/** Caps on a response we do not control. `MAX_BODY_BYTES` is checked as
 *  bytes (measured real cert ~9.5 KiB; VKS strips third-party sigs).
 *  `MAX_CERTS` is 1: every by-* endpoint names a single cert, so extras are
 *  counted and dropped, never forwarded. */
export const MAX_BODY_BYTES = 128 * 1024;
export const MAX_CERTS = 1;

/** Bound on a hostile `retry-after`. */
const MAX_RETRY_AFTER_MS = 24 * 60 * 60 * 1000;

export type KeyserverParseFailure = Exclude<
  KeyserverKeyFailure,
  "invalid-query" | "offline"
>;

export type KeyserverKeyResult =
  | {
      ok: true;
      /** Untrusted text; the panel's engine decides it is a cert. */
      armored: string;
      /** Extra blocks dropped by MAX_CERTS; the panel discloses them. */
      omitted: number;
    }
  | { ok: false; error: KeyserverParseFailure; retryAt?: number };

export interface KeyserverRawResponse {
  status: number;
  contentType: string | null;
  body: string;
  retryAfter?: string | null;
}

/** HTML on a 200 means a captive portal/proxy intercepted it. */
function isPgpKeysContentType(contentType: string | null): boolean {
  if (!contentType) return false;
  return (
    contentType.split(";", 1)[0].trim().toLowerCase() === "application/pgp-keys"
  );
}

function utf8ByteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

/** Delta-seconds only: the HTTP-date form is deliberately not parsed
 *  (`Date.parse` on attacker input, for a cosmetic hint). */
function parseRetryAfter(
  retryAfter: string | null | undefined,
  now: number,
): number | undefined {
  if (!retryAfter) return undefined;
  const trimmed = retryAfter.trim();
  if (!/^\d{1,10}$/.test(trimmed)) return undefined;
  const at = now + Number(trimmed) * 1000;
  // Dropped, not clamped: an invented hint is worse than none.
  if (at > now + MAX_RETRY_AFTER_MS) return undefined;
  return at;
}

export function parseKeyserverKeyResponse(
  raw: KeyserverRawResponse,
  now: number = Date.now(),
): KeyserverKeyResult {
  const { status, contentType, body } = raw;

  // "No such key" for every query kind, distinct from a server failure.
  if (status === 404) return { ok: false, error: "not-found" };

  if (status === 429) {
    return {
      ok: false,
      error: "rate-limited",
      retryAt: parseRetryAfter(raw.retryAfter, now),
    };
  }

  if (status !== 200) return { ok: false, error: "server-error" };
  if (!isPgpKeysContentType(contentType))
    return { ok: false, error: "server-error" };

  // Cheap code-unit check first; bytes >= code units, so it is sound.
  if (body.length > MAX_BODY_BYTES || utf8ByteLength(body) > MAX_BODY_BYTES) {
    return { ok: false, error: "server-error" };
  }

  // Only PUBLIC KEY armor can match, so a private key can never be
  // forwarded as a contact.
  const blocks = splitPublicKeyBlocks(body);
  if (blocks.length === 0) return { ok: false, error: "server-error" };

  return {
    ok: true,
    armored: blocks[0],
    omitted: blocks.length - MAX_CERTS,
  };
}
