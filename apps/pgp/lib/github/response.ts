/**
 * Parse a GitHub `/users/<user>/keys` response into a closed result union.
 * Pure (no `Response`) so every branch is unit-testable.
 *
 * THE WORKER MUST NEVER DECIDE A KEY IS VALID: shape validation only; the
 * authority is `parseSshRecipient` (wasm, panel-side). Results carry tagged
 * codes, never GitHub's prose.
 */

import { splitSshPublicKeyCandidateLines } from "~/lib/armor-blocks";
import type { GithubKeysFailure } from "~/lib/messages";

/** DoS caps on a response we do not control. `MAX_BODY_BYTES` is checked
 *  as bytes, not UTF-16 `.length`. `MAX_KEY_CHARS` is the per-key cap
 *  T-GITHUB-UNTRUSTED-PARSE claims (largest usable line ~740 chars). */
export const MAX_KEYS = 20;
export const MAX_BODY_BYTES = 64 * 1024;
export const MAX_KEY_CHARS = 4096;

/** Bound on a hostile `x-ratelimit-reset` (GitHub's window is an hour). */
const MAX_RESET_AHEAD_MS = 24 * 60 * 60 * 1000;

function utf8ByteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}

/** Failures a parsed response can produce. */
export type GithubKeysParseFailure = Exclude<
  GithubKeysFailure,
  "invalid-username" | "offline"
>;

export type GithubKeysResult =
  | {
      ok: true;
      lines: string[];
      /** Keys our own caps refused to forward; the panel must disclose
       *  a non-zero count rather than imply the list is complete. */
      omitted: number;
    }
  | { ok: false; error: GithubKeysParseFailure; resetAt?: number };

export interface GithubKeysRawResponse {
  status: number;
  contentType: string | null;
  body: string;
  rateLimitRemaining?: string | null;
  /** Unix seconds, verbatim. */
  rateLimitReset?: string | null;
}

function isJsonContentType(contentType: string | null): boolean {
  if (!contentType) return false;
  const essence = contentType.split(";", 1)[0].trim().toLowerCase();
  return essence === "application/json" || essence.endsWith("+json");
}

function parseResetAt(
  reset: string | null | undefined,
  now: number,
): number | undefined {
  if (!reset) return undefined;
  const seconds = Number(reset);
  if (!Number.isFinite(seconds) || seconds <= 0) return undefined;
  const at = Math.trunc(seconds) * 1000;
  // Dropped, not clamped: an invented hint is worse than none.
  if (at > now + MAX_RESET_AHEAD_MS) return undefined;
  return at;
}

export function parseGithubKeysResponse(
  raw: GithubKeysRawResponse,
  now: number = Date.now(),
): GithubKeysResult {
  const { status, contentType, body } = raw;

  if (status === 404) return { ok: false, error: "not-found" };

  // GitHub reports the anonymous rate limit as 403 (measured) or 429.
  if (status === 403 || status === 429) {
    return {
      ok: false,
      error: "rate-limited",
      resetAt: parseResetAt(raw.rateLimitReset, now),
    };
  }

  if (status !== 200) return { ok: false, error: "server-error" };

  // HTML on a 200 means a captive portal/proxy intercepted it.
  if (!isJsonContentType(contentType))
    return { ok: false, error: "server-error" };

  // Cheap code-unit check first; bytes >= code units, so it is sound.
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

  const candidates: string[] = [];
  let omitted = 0;
  for (const entry of parsed) {
    if (typeof entry !== "object" || entry === null) continue;
    const key = (entry as { key?: unknown }).key;
    if (typeof key !== "string" || key.trim() === "") continue;
    // Counted, not skipped: our cap, so the user is told.
    if (key.length > MAX_KEY_CHARS) {
      omitted += 1;
      continue;
    }
    candidates.push(key);
  }

  // Only `<type> AAAA<base64>`-shaped lines cross the boundary. Shape
  // only, NOT the supported-type list: an unusable type must reach
  // `parseSshRecipient` to get its curated refusal.
  const matched = candidates.flatMap((candidate) =>
    splitSshPublicKeyCandidateLines(candidate),
  );
  const lines = matched.slice(0, MAX_KEYS);
  omitted += matched.length - lines.length;

  if (lines.length === 0 && omitted === 0) {
    // `200 []` (real account, no keys) vs 404 is the point of the message;
    // only claimed when nothing was held back.
    return { ok: false, error: "no-keys" };
  }

  return { ok: true, lines, omitted };
}
