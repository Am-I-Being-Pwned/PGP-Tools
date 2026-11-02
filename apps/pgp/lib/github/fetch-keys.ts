/**
 * The ONLY file containing `https://api.github.com` and the only fetch for
 * this import (build audit asserts it against background.js). No host
 * permission: ACAO `*`; the worker CSP `connect-src` entry admits it.
 * `credentials: "omit"` is restated though network-lockdown forces it.
 */

import type { GithubKeysFailure } from "~/lib/messages";
import { readCappedBody } from "~/lib/net/capped-body";
import { MAX_BODY_BYTES, parseGithubKeysResponse } from "./response";
import { githubKeysUrl } from "./username";

export type FetchGithubKeysResult =
  | { ok: true; lines: string[]; omitted: number }
  | { ok: false; error: GithubKeysFailure; resetAt?: number };

const GITHUB_API_ORIGIN = "https://api.github.com";

/** Whole-request deadline: the panel gates import on a `parsingRef`
 *  cleared only in `finally`, so a trickling body would disable import. */
const REQUEST_TIMEOUT_MS = 15_000;

export async function fetchGithubKeys(
  username: string,
): Promise<FetchGithubKeysResult> {
  let url: URL;
  try {
    url = githubKeysUrl(username, GITHUB_API_ORIGIN);
  } catch {
    // A throw means the URL is not the one we intended.
    return { ok: false, error: "invalid-username" };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, REQUEST_TIMEOUT_MS);

  try {
    return await requestKeys(url, controller.signal);
  } finally {
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
      // GitHub redirects renamed accounts; following would import whoever
      // owns the name now, under the name the user typed.
      redirect: "error",
      cache: "no-store",
      headers: { Accept: "application/vnd.github+json" },
    });
  } catch {
    // Offline, CSP, redirect refusal or timeout all collapse to one code.
    return { ok: false, error: "offline" };
  }

  let body: string;
  try {
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
