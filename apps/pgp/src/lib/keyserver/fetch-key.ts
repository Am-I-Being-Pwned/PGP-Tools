/**
 * The ONLY file containing `https://keys.openpgp.org` and the only fetch for
 * this lookup (build audit asserts it against background.js). No host
 * permission: the endpoint sends ACAO `*`; the worker CSP `connect-src`
 * entry is what admits it (wxt.config.ts). `credentials: "omit"` is
 * restated though network-lockdown forces it.
 *
 * T-KEYSERVER-LOOKUP-DISCLOSURE: the path tells keys.openpgp.org which
 * identity this IP is about to write to, so the feature sits behind
 * `keyDiscoveryEnabled` and is off in the strictest preset.
 */

import type { KeyserverKeyFailure } from "~/lib/messages";
import { readCappedBody } from "~/lib/net/capped-body";
import { keyserverKeyUrl, type KeyserverQuery } from "./query";
import { MAX_BODY_BYTES, parseKeyserverKeyResponse } from "./response";

export type FetchKeyserverKeyResult =
  | { ok: true; armored: string; omitted: number }
  | { ok: false; error: KeyserverKeyFailure; retryAt?: number };

const KEYSERVER_ORIGIN = "https://keys.openpgp.org";

/** Whole-request deadline: the panel gates import on a `parsingRef`
 *  cleared only in `finally`, so a trickling body would disable import. */
const REQUEST_TIMEOUT_MS = 15_000;

export async function fetchKeyserverKey(
  query: KeyserverQuery,
): Promise<FetchKeyserverKeyResult> {
  let url: URL;
  try {
    url = keyserverKeyUrl(query, KEYSERVER_ORIGIN);
  } catch {
    // A throw means the URL is not the one we intended.
    return { ok: false, error: "invalid-query" };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, REQUEST_TIMEOUT_MS);

  try {
    return await requestKey(url, controller.signal);
  } finally {
    clearTimeout(timer);
  }
}

async function requestKey(
  url: URL,
  signal: AbortSignal,
): Promise<FetchKeyserverKeyResult> {
  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      signal,
      credentials: "omit",
      // A redirect is a server-chosen destination that would carry the
      // identity in the path to any origin.
      redirect: "error",
      cache: "no-store",
      headers: { Accept: "application/pgp-keys" },
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

  return parseKeyserverKeyResponse({
    status: response.status,
    contentType: response.headers.get("content-type"),
    body,
    retryAfter: response.headers.get("retry-after"),
  });
}
