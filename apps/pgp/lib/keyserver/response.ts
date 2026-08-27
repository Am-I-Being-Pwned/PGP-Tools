/**
 * Parse a keys.openpgp.org `/vks/v1/by-*` response into a closed result
 * union. Pure: it takes a plain object, never a `Response`, so every
 * branch is unit-testable with no network. The sibling of
 * `lib/github/response.ts`, and it keeps the same two rules.
 *
 * THE WORKER MUST NEVER DECIDE A KEY IS VALID. Everything here is shape
 * validation only -- "is the status 200", "is the content type
 * application/pgp-keys", "does the body contain a PUBLIC KEY BLOCK
 * between its armor markers". The single authority on whether a cert is
 * usable remains the wasm engine, panel-side, via the same
 * `prepareImport` a pasted key goes through. This file only decides what
 * is allowed to cross the message boundary.
 *
 * Error text never crosses either: results carry tagged codes, not the
 * prose the keyserver wrote. Its 404 body is a `text/html` sentence that
 * quotes the address back (measured), which is precisely the kind of
 * attacker-influenced string that must not reach a render.
 */

import type { KeyserverKeyFailure } from "../messages";
import { splitPublicKeyBlocks } from "../armor-blocks";

/** Hard caps on a response we do not control.
 *
 *  `MAX_BODY_BYTES` is BYTES, and is checked as bytes: comparing it
 *  against a JS string's `.length` measures UTF-16 code units, which a
 *  body of astral characters clears at up to a third of its real size.
 *  128 KiB against a measured 9.5 KiB for a well-used real-world cert --
 *  keys.openpgp.org strips third-party certifications, so the pathology
 *  that makes SKS keys megabytes large cannot occur here.
 *
 *  `MAX_CERTS` is 1 because the endpoint returns one key by
 *  construction: `by-email`, `by-fingerprint` and `by-keyid` each name a
 *  single cert. A body carrying more is not a bundle to import, it is a
 *  response that is not the one we asked for -- so the extras are
 *  counted and dropped rather than forwarded. */
export const MAX_BODY_BYTES = 128 * 1024;
export const MAX_CERTS = 1;

/** A `retry-after` further ahead than this is not a rate limit, it is a
 *  hostile header. Without a bound, `1e300` renders as "try again in
 *  about 2.7e+296 hours". Same guard, same reason, as the GitHub
 *  parser's `MAX_RESET_AHEAD_MS`. */
const MAX_RETRY_AFTER_MS = 24 * 60 * 60 * 1000;

/** The subset of {@link KeyserverKeyFailure} a *parsed* response can
 *  produce. `invalid-query` is decided before the request and `offline`
 *  only when the request itself throws, so neither can originate here. */
export type KeyserverParseFailure = Exclude<
  KeyserverKeyFailure,
  "invalid-query" | "offline"
>;

export type KeyserverKeyResult =
  | {
      ok: true;
      /** The armored PUBLIC KEY BLOCK, verbatim between its markers.
       *  Untrusted text: the panel's engine is what decides it is a
       *  cert. */
      armored: string;
      /** How many further blocks the body carried that {@link MAX_CERTS}
       *  refused to forward. Non-zero means the response was not the
       *  single cert the endpoint is documented to return, and the panel
       *  says so rather than importing the first of several silently. */
      omitted: number;
    }
  | { ok: false; error: KeyserverParseFailure; retryAt?: number };

export interface KeyserverRawResponse {
  status: number;
  contentType: string | null;
  body: string;
  /** `retry-after`, verbatim, when present. */
  retryAfter?: string | null;
}

/** The one content type a key answer may have. An HTML body on a 200
 *  means something intercepted the request (captive portal, proxy);
 *  refuse before parsing. */
function isPgpKeysContentType(contentType: string | null): boolean {
  if (!contentType) return false;
  return (
    contentType.split(";", 1)[0].trim().toLowerCase() === "application/pgp-keys"
  );
}

/** UTF-8 size of `body`. Only reached once the cheap `.length` check has
 *  bounded the string, so the transient buffer is bounded too. */
function utf8ByteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

/**
 * `retry-after` as ms since epoch, or undefined when absent/garbage.
 *
 * Delta-seconds only. The header's HTTP-date form is deliberately NOT
 * parsed: `Date.parse` on an attacker-chosen string is a lenient,
 * locale-adjacent surface for a value whose only use is a sentence
 * saying "try again in about five minutes", and the copy reads fine
 * with no hint at all.
 */
function parseRetryAfter(
  retryAfter: string | null | undefined,
  now: number,
): number | undefined {
  if (!retryAfter) return undefined;
  const trimmed = retryAfter.trim();
  if (!/^\d{1,10}$/.test(trimmed)) return undefined;
  const at = now + Number(trimmed) * 1000;
  // Absurdly-far-future values are dropped rather than clamped: a hint
  // we invented is worse than no hint.
  if (at > now + MAX_RETRY_AFTER_MS) return undefined;
  return at;
}

export function parseKeyserverKeyResponse(
  raw: KeyserverRawResponse,
  now: number = Date.now(),
): KeyserverKeyResult {
  const { status, contentType, body } = raw;

  // The endpoint's "no such key" answer for every query kind (measured:
  // 404 with a text/html sentence quoting the query back). Distinct from
  // a server failure, and the distinction is the whole point of the
  // message the user sees.
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

  // Cheap code-unit check first, then the honest byte count -- a string
  // is never shorter in bytes than in code units, so the first test can
  // only reject what the second would have.
  if (body.length > MAX_BODY_BYTES || utf8ByteLength(body) > MAX_BODY_BYTES) {
    return { ok: false, error: "server-error" };
  }

  // Shape only: what crosses the boundary is the text between a matched
  // BEGIN/END pair of PUBLIC KEY armor. A PRIVATE KEY BLOCK cannot match
  // this and so cannot be forwarded as a contact -- the endpoint has no
  // reason to send one, which is exactly why it is worth being unable to
  // accept.
  const blocks = splitPublicKeyBlocks(body);
  if (blocks.length === 0) return { ok: false, error: "server-error" };

  return {
    ok: true,
    armored: blocks[0],
    omitted: blocks.length - MAX_CERTS,
  };
}
