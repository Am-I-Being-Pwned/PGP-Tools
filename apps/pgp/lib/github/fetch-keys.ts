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
  | { ok: true; lines: string[] }
  | { ok: false; error: GithubKeysFailure; resetAt?: number };

const GITHUB_API_ORIGIN = "https://api.github.com";

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

  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
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
    // Offline, DNS failure, CSP block, or the redirect refusal above.
    // TypeError is all any of them surface, so they collapse into one
    // code; none carry text we would forward anyway.
    return { ok: false, error: "offline" };
  }

  let body: string;
  try {
    body = await response.text();
  } catch {
    return { ok: false, error: "server-error" };
  }

  return parseGithubKeysResponse({
    status: response.status,
    contentType: response.headers.get("content-type"),
    // Truncate before parsing so a hostile body cannot cost more than
    // the cap; `parseGithubKeysResponse` rejects anything over it.
    body: body.slice(0, MAX_BODY_BYTES + 1),
    rateLimitRemaining: response.headers.get("x-ratelimit-remaining"),
    rateLimitReset: response.headers.get("x-ratelimit-reset"),
  });
}
