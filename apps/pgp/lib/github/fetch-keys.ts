/**
 * The one and only file in this codebase that contains the string
 * `https://api.github.com`, and the one and only `fetch` behind the
 * GitHub recipient import. Keeping both to a single file is an
 * invariant the build audit asserts against `background.js`.
 *
 * No host permission is needed: the endpoint sends
 * `access-control-allow-origin: *`, so the extension origin can read it
 * cross-origin unauthenticated (measured: 200, `x-ratelimit-limit: 60`,
 * i.e. the anonymous limit). What IS needed is the manifest CSP
 * `connect-src` entry -- CSP applies to the MV3 service worker. See
 * wxt.config.ts.
 *
 * `lib/network-lockdown` already forces `credentials: "omit"` and strips
 * Authorization/Cookie on every fetch; we restate `credentials: "omit"`
 * here so the call site is honest on its own.
 */

import type { GithubKeysFailure } from "../messages";
import { MAX_BODY_BYTES, parseGithubKeysResponse } from "./response";
import { githubKeysUrl } from "./username";

export type FetchGithubKeysResult =
  | { ok: true; lines: string[]; omitted: number }
  | { ok: false; error: GithubKeysFailure; resetAt?: number };

const GITHUB_API_ORIGIN = "https://api.github.com";

/**
 * Wall clock for the whole request, headers and body together.
 *
 * There must be one. The panel gates BOTH import paths -- fetch and
 * paste -- on a single `parsingRef` that is only cleared in a `finally`,
 * so a response that never settles does not just hang this lookup: it
 * disables key import until the panel is closed and reopened. A body
 * that trickles a byte a second is enough, and the threat model already
 * admits an attacker who can write the response.
 */
const REQUEST_TIMEOUT_MS = 15_000;

/**
 * Read at most `MAX_BODY_BYTES + 1` bytes of the response.
 *
 * `await response.text()` would buffer the WHOLE body first and only
 * then let us measure it -- the cap would be applied after the
 * allocation it exists to prevent, which is not what SECURITY.md and
 * `T-GITHUB-UNTRUSTED-PARSE` say ("caps applied before parsing"). One
 * byte over the cap is enough for `parseGithubKeysResponse` to refuse,
 * so we stop there and drop the connection.
 *
 * The extra byte matters: stopping exactly AT the cap would make a
 * hostile 10 GB body indistinguishable from a legitimate 64 KiB one.
 */
/** What an over-cap body is reported as: one byte past the cap, which
 *  is all `parseGithubKeysResponse` needs to refuse it. */
const OVER_CAP_BODY = "x".repeat(MAX_BODY_BYTES + 1);

async function readCappedBody(response: Response): Promise<string> {
  // Content-Length is a hint, not a promise -- it can lie, be absent, or
  // be dropped by a chunked/compressed response. Believing it when it is
  // over the cap costs nothing; the reader below is what enforces.
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    void response.body?.cancel();
    // Over the cap either way; the parser only needs to see that.
    return OVER_CAP_BODY;
  }

  const body = response.body;
  // No stream to read (a body-less status, or a fetch implementation
  // without one): fall back, still slicing before the parse.
  if (!body) return (await response.text()).slice(0, MAX_BODY_BYTES + 1);

  const reader = body.getReader();
  const decoder = new TextDecoder();
  let read = 0;
  let text = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      read += value.byteLength;
      if (read > MAX_BODY_BYTES) {
        // Hang up and decode nothing further. What comes back is a
        // stand-in one byte over the cap rather than the bytes read:
        // past this point the body is refused whatever it says, so
        // decoding the rest of it would be work done for nothing.
        void reader.cancel();
        return OVER_CAP_BODY;
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } finally {
    reader.releaseLock();
  }
  return text;
}

export async function fetchGithubKeys(
  username: string,
): Promise<FetchGithubKeysResult> {
  let url: URL;
  try {
    url = githubKeysUrl(username, GITHUB_API_ORIGIN);
  } catch {
    // Unreachable in practice -- background.ts validates first -- but a
    // throw here means the URL was not the one we intended, so refuse.
    return { ok: false, error: "invalid-username" };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, REQUEST_TIMEOUT_MS);

  try {
    return await requestKeys(url, controller.signal);
  } finally {
    // Cleared on every exit, including the abort's own: an uncleared
    // timer keeps the MV3 worker alive for no reason.
    clearTimeout(timer);
  }
}

async function requestKeys(
  url: URL,
  signal: AbortSignal,
): Promise<FetchGithubKeysResult> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      signal,
      credentials: "omit",
      // Deliberate: GitHub 301-redirects renamed accounts. Following one
      // silently would import the SSH keys of whoever owns that name
      // NOW, under the name the user typed -- exactly the confusion this
      // feature must not create. A rename is a hard error the user gets
      // to resolve.
      redirect: "error",
      cache: "no-store",
      headers: { Accept: "application/vnd.github+json" },
    });
  } catch {
    // Offline, DNS failure, CSP block, the redirect refusal above, or
    // the timeout. TypeError/AbortError is all any of them surface, so
    // they collapse into one code; none carry text we would forward
    // anyway, and "couldn't reach github.com" is true of all of them.
    return { ok: false, error: "offline" };
  }

  let body: string;
  try {
    // Bounded as it arrives -- never buffered whole and measured after.
    body = await readCappedBody(response);
  } catch {
    return { ok: false, error: "server-error" };
  }

  return parseGithubKeysResponse({
    status: response.status,
    contentType: response.headers.get("content-type"),
    body,
    rateLimitRemaining: response.headers.get("x-ratelimit-remaining"),
    rateLimitReset: response.headers.get("x-ratelimit-reset"),
  });
}
