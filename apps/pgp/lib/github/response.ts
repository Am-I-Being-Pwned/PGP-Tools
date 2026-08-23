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
import { splitSshPublicKeyLines } from "../armor-blocks";

/** Hard caps. A user with more keys than this is pathological, and the
 *  body is far smaller than this in every measured case (~624 bytes for
 *  one key). Both are DoS guards on a response we do not control. */
export const MAX_KEYS = 20;
export const MAX_BODY_BYTES = 64 * 1024;

/** The subset of `GithubKeysFailure` a *parsed* response can produce.
 *  `invalid-username` is decided before the request and `offline` only
 *  when the request itself throws, so neither can originate here. */
export type GithubKeysParseFailure = Exclude<
  GithubKeysFailure,
  "invalid-username" | "offline"
>;

export type GithubKeysResult =
  | { ok: true; lines: string[] }
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
function parseResetAt(reset: string | null | undefined): number | undefined {
  if (!reset) return undefined;
  const seconds = Number(reset);
  if (!Number.isFinite(seconds) || seconds <= 0) return undefined;
  return Math.trunc(seconds) * 1000;
}

export function parseGithubKeysResponse(
  raw: GithubKeysRawResponse,
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
      resetAt: parseResetAt(raw.rateLimitReset),
    };
  }

  if (status !== 200) return { ok: false, error: "server-error" };

  // An HTML body on a 200 means something intercepted the request
  // (captive portal, proxy). Refuse before parsing.
  if (!isJsonContentType(contentType))
    return { ok: false, error: "server-error" };

  if (body.length > MAX_BODY_BYTES) return { ok: false, error: "server-error" };

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
  for (const entry of parsed) {
    if (typeof entry !== "object" || entry === null) continue;
    const key = (entry as { key?: unknown }).key;
    if (typeof key !== "string" || key.trim() === "") continue;
    candidates.push(key);
  }

  // Re-derive the lines with the existing SSH line matcher rather than
  // trusting the strings: only well-shaped `ssh-ed25519|ssh-rsa AAAA...`
  // lines can cross the message boundary. GitHub already strips comments
  // and emails, but we do not rely on that.
  const lines = candidates
    .flatMap((candidate) => splitSshPublicKeyLines(candidate))
    .slice(0, MAX_KEYS);

  if (lines.length === 0) {
    // A real account with no keys returns `200 []` -- distinct from a
    // nonexistent account's 404, and the distinction is the whole point
    // of the message the user sees.
    return { ok: false, error: "no-keys" };
  }

  return { ok: true, lines };
}
