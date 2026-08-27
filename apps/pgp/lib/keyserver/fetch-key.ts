/**
 * The one and only file in this codebase that contains the string
 * `https://keys.openpgp.org`, and the one and only `fetch` behind the
 * keyserver key lookup. Keeping both to a single file is an invariant
 * the build audit asserts against `background.js` -- the same shape
 * `lib/github/fetch-keys.ts` holds for its own origin.
 *
 * No host permission is needed: the endpoint sends
 * `access-control-allow-origin: *`, so the extension origin can read it
 * cross-origin unauthenticated (measured: 200, `content-type:
 * application/pgp-keys`, no rate-limit headers of any kind). What IS
 * needed is the manifest CSP `connect-src` entry -- CSP applies to the
 * MV3 service worker. See wxt.config.ts.
 *
 * `lib/network-lockdown` already forces `credentials: "omit"` and strips
 * Authorization/Cookie on every fetch; we restate `credentials: "omit"`
 * here so the call site is honest on its own.
 *
 * WHAT THIS LOOKUP DISCLOSES, said plainly because it is worse than the
 * GitHub one: the path carries the address or fingerprint the user typed
 * for someone they are about to write to. keys.openpgp.org learns that
 * this IP address is interested in that identity, at that moment. That
 * is `T-KEYSERVER-LOOKUP-DISCLOSURE`, and it is why the whole feature
 * sits behind `keyDiscoveryEnabled` and is off in the strictest preset.
 */

import type { KeyserverKeyFailure } from "../messages";
import type { KeyserverQuery } from "./query";
import { readCappedBody } from "../net/capped-body";
import { keyserverKeyUrl } from "./query";
import { MAX_BODY_BYTES, parseKeyserverKeyResponse } from "./response";

export type FetchKeyserverKeyResult =
  | { ok: true; armored: string; omitted: number }
  | { ok: false; error: KeyserverKeyFailure; retryAt?: number };

const KEYSERVER_ORIGIN = "https://keys.openpgp.org";

/**
 * Wall clock for the whole request, headers and body together.
 *
 * There must be one, for the same reason the GitHub lookup has one: the
 * panel gates every import path on a single `parsingRef` cleared only in
 * a `finally`, so a response that never settles disables key import
 * until the panel is closed and reopened. A body that trickles a byte a
 * second is enough, and the threat model already admits an attacker who
 * can write the response.
 */
const REQUEST_TIMEOUT_MS = 15_000;

export async function fetchKeyserverKey(
  query: KeyserverQuery,
): Promise<FetchKeyserverKeyResult> {
  let url: URL;
  try {
    url = keyserverKeyUrl(query, KEYSERVER_ORIGIN);
  } catch {
    // Unreachable in practice -- background.ts validates first -- but a
    // throw here means the URL was not the one we intended, so refuse.
    return { ok: false, error: "invalid-query" };
  }

  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, REQUEST_TIMEOUT_MS);

  try {
    return await requestKey(url, controller.signal);
  } finally {
    // Cleared on every exit, including the abort's own: an uncleared
    // timer keeps the MV3 worker alive for no reason.
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
      // Deliberate, and load-bearing here in a way it is not for a
      // static API: a redirect is a server-chosen destination, and the
      // whole point of `keyserverKeyUrl` is that the destination is
      // ours. Following one would let the endpoint hand the lookup --
      // and the identity in its path -- to any origin it liked, with the
      // CSP `connect-src` entry as the only thing left saying no.
      redirect: "error",
      cache: "no-store",
      headers: { Accept: "application/pgp-keys" },
    });
  } catch {
    // Offline, DNS failure, CSP block, the redirect refusal above, or
    // the timeout. TypeError/AbortError is all any of them surface, so
    // they collapse into one code; none carry text we would forward
    // anyway, and "couldn't reach the keyserver" is true of all of them.
    return { ok: false, error: "offline" };
  }

  let body: string;
  try {
    // Bounded as it arrives -- never buffered whole and measured after.
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
