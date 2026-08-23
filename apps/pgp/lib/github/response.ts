/**
 * Parse a GitHub `/users/<user>/keys` response into a closed result
 * union. Pure: it takes a plain object, never a `Response`, so every
 * branch is unit-testable with no network.
 *
 * THE WORKER MUST NEVER DECIDE A KEY IS VALID. Everything here is shape
 * validation only -- "is this an array", "is `entry.key` a non-empty
 * string", "does the line look like `ssh-ed25519 AAAA...`". The single
 * authority on whether an SSH recipient is usable remains
 * `parseSshRecipient` (wasm, panel-side). This file only decides what is
 * allowed to cross the message boundary.
 *
 * Error text never crosses either: results carry tagged codes, not prose
 * GitHub wrote. (Same lesson the codebase already learned with
 * `ssh-passphrase-required`.)
 */

import type { GithubKeysFailure } from "../messages";
import { splitSshPublicKeyCandidateLines } from "../armor-blocks";

/** Hard caps. A user with more keys than this is pathological, and the
 *  body is far smaller than this in every measured case (~624 bytes for
 *  one key). All three are DoS guards on a response we do not control.
 *
 *  `MAX_BODY_BYTES` is BYTES, and is checked as bytes: comparing it
 *  against a JS string's `.length` measures UTF-16 code units, which a
 *  body of astral characters clears at up to a third of its real size.
 *
 *  `MAX_KEY_CHARS` is the per-key-string cap the threat model
 *  (`T-GITHUB-UNTRUSTED-PARSE`) has always claimed. The largest line the
 *  age engine can accept is an RSA-4096 key at ~740 characters, so this
 *  is generous by more than 5x and can only be hit by something that is
 *  not a key we could have used. */
export const MAX_KEYS = 20;
export const MAX_BODY_BYTES = 64 * 1024;
export const MAX_KEY_CHARS = 4096;

/** A `x-ratelimit-reset` further ahead than this is not a rate limit, it
 *  is a hostile header: GitHub's anonymous window is an hour. Without a
 *  bound, `1e300` renders as "try again in about 2.7e+296 hours". */
const MAX_RESET_AHEAD_MS = 24 * 60 * 60 * 1000;

/** UTF-8 size of `body`. Only reached once the cheap `.length` check has
 *  bounded the string, so the transient buffer is bounded too. */
function utf8ByteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

/** The subset of `GithubKeysFailure` a *parsed* response can produce.
 *  `invalid-username` is decided before the request and `offline` only
 *  when the request itself throws, so neither can originate here. */
export type GithubKeysParseFailure = Exclude<
  GithubKeysFailure,
  "invalid-username" | "offline"
>;

export type GithubKeysResult =
  | {
      ok: true;
      lines: string[];
      /** How many published key strings OUR OWN caps refused to forward
       *  ({@link MAX_KEYS}, {@link MAX_KEY_CHARS}). Non-zero means the
       *  list the panel is about to show is not the whole account, and
       *  the panel says so rather than asserting "every key listed
       *  above" over a silent truncation. */
      omitted: number;
    }
  | { ok: false; error: GithubKeysParseFailure; resetAt?: number };

export interface GithubKeysRawResponse {
  status: number;
  contentType: string | null;
  body: string;
  /** `x-ratelimit-remaining`, verbatim, when present. */
  rateLimitRemaining?: string | null;
  /** `x-ratelimit-reset`, verbatim (unix seconds), when present. */
  rateLimitReset?: string | null;
}

function isJsonContentType(contentType: string | null): boolean {
  if (!contentType) return false;
  const essence = contentType.split(";", 1)[0].trim().toLowerCase();
  return essence === "application/json" || essence.endsWith("+json");
}

/** `x-ratelimit-reset` is unix seconds. Return ms since epoch so the UI
 *  can say when access recovers, or undefined when absent/garbage. */
function parseResetAt(
  reset: string | null | undefined,
  now: number,
): number | undefined {
  if (!reset) return undefined;
  const seconds = Number(reset);
  if (!Number.isFinite(seconds) || seconds <= 0) return undefined;
  const at = Math.trunc(seconds) * 1000;
  // Absurdly-far-future values are dropped rather than clamped: a hint
  // we invented is worse than no hint, and the copy reads fine without
  // one. See MAX_RESET_AHEAD_MS.
  if (at > now + MAX_RESET_AHEAD_MS) return undefined;
  return at;
}

export function parseGithubKeysResponse(
  raw: GithubKeysRawResponse,
  now: number = Date.now(),
): GithubKeysResult {
  const { status, contentType, body } = raw;

  if (status === 404) return { ok: false, error: "not-found" };

  // 403 is how GitHub reports the anonymous rate limit (measured, with
  // `x-ratelimit-remaining: 0`); 429 is the documented alternative. A
  // 403 that is not rate limiting is still a refusal we cannot act on,
  // so it maps here either way.
  if (status === 403 || status === 429) {
    return {
      ok: false,
      error: "rate-limited",
      resetAt: parseResetAt(raw.rateLimitReset, now),
    };
  }

  if (status !== 200) return { ok: false, error: "server-error" };

  // An HTML body on a 200 means something intercepted the request
  // (captive portal, proxy). Refuse before parsing.
  if (!isJsonContentType(contentType))
    return { ok: false, error: "server-error" };

  // Cheap code-unit check first, then the honest byte count -- a string
  // is never shorter in bytes than in code units, so the first test can
  // only reject what the second would have.
  if (body.length > MAX_BODY_BYTES || utf8ByteLength(body) > MAX_BODY_BYTES) {
    return { ok: false, error: "server-error" };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return { ok: false, error: "server-error" };
  }

  if (!Array.isArray(parsed)) return { ok: false, error: "server-error" };

  // Shape validation only: take `entry.key` when it is a non-empty
  // string, ignore every other field (id, created_at, last_used).
  const candidates: string[] = [];
  let omitted = 0;
  for (const entry of parsed) {
    if (typeof entry !== "object" || entry === null) continue;
    const key = (entry as { key?: unknown }).key;
    if (typeof key !== "string" || key.trim() === "") continue;
    // Per-key cap. Counted, not skipped: it is one of our caps, so the
    // user is owed the fact that a published key did not make it.
    if (key.length > MAX_KEY_CHARS) {
      omitted += 1;
      continue;
    }
    candidates.push(key);
  }

  // Re-derive the lines with the SSH line matcher rather than trusting
  // the strings: only `<type> AAAA<base64>`-shaped lines can cross the
  // message boundary. Shape only -- deliberately NOT the list of key
  // types the engine supports. A line whose type this app cannot use
  // still crosses, and comes back from `parseSshRecipient` as a curated
  // refusal the panel shows ("ECDSA keys are not supported ..."); the
  // narrower matcher used to drop those here, which reported an account
  // whose only key is ECDSA as having published none. GitHub already
  // strips comments and emails, but we do not rely on that.
  const matched = candidates.flatMap((candidate) =>
    splitSshPublicKeyCandidateLines(candidate),
  );
  const lines = matched.slice(0, MAX_KEYS);
  omitted += matched.length - lines.length;

  if (lines.length === 0 && omitted === 0) {
    // A real account with no keys returns `200 []` -- distinct from a
    // nonexistent account's 404, and the distinction is the whole point
    // of the message the user sees. Only said when nothing was held
    // back: "they published none" and "we refused to forward some" are
    // different answers.
    return { ok: false, error: "no-keys" };
  }

  return { ok: true, lines, omitted };
}
