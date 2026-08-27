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
import { readCappedBody } from "../net/capped-body";
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
    body = await readCappedBody(response, MAX_BODY_BYTES);
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
