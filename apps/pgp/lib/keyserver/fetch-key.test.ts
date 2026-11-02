/**
 * The transport half: what happens to a response we do not control
 * BEFORE `parseKeyserverKeyResponse` ever sees it. The twin of
 * `lib/github/fetch-keys.test.ts`, because the two lookups now share the
 * bounded reader (`lib/net/capped-body.ts`) and a cap that is only
 * exercised on one of them is a cap that can silently stop applying to
 * the other.
 *
 * `fetch` is stubbed with a hand-rolled response object rather than a
 * real one: the point of each case is exactly which of `body`, `text()`
 * and `cancel()` the code touches.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

import type { FakeResponseInit } from "../net/fake-response";
import type { KeyserverQuery } from "./query";
import {
  encode,
  expectContentLengthRefusal,
  expectTimeoutOffline,
  fakeResponse,
  stubFetch,
} from "../net/fake-response";
import { fetchKeyserverKey } from "./fetch-key";
import { MAX_BODY_BYTES } from "./response";

const PGP_CT = "application/pgp-keys";
const QUERY: KeyserverQuery = { kind: "email", value: "alice@example.com" };
const CERT = [
  "-----BEGIN PGP PUBLIC KEY BLOCK-----",
  "",
  "mDMEZaBcDRYJKwYBBAHaRw8BAQdA0000000000000000000000000000000000000",
  "=abcd",
  "-----END PGP PUBLIC KEY BLOCK-----",
].join("\n");

const respond = (init?: FakeResponseInit) => fakeResponse(PGP_CT, init);

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("fetchKeyserverKey request", () => {
  it("asks the documented URL, with the pinned init", () => {
    const { response } = respond({ chunks: encode(CERT) });
    const stub = stubFetch(response);

    return fetchKeyserverKey(QUERY).then(() => {
      const [url, init] = stub.mock.calls[0] as [URL, RequestInit];
      expect(url.href).toBe(
        "https://keys.openpgp.org/vks/v1/by-email/alice%40example.com",
      );
      expect(init.credentials).toBe("omit");
      // Not following a redirect is what keeps the destination ours: a
      // 302 is a server-chosen origin, and the URL builder's whole job is
      // that the origin is not server-chosen.
      expect(init.redirect).toBe("error");
      expect(init.cache).toBe("no-store");
      expect(init.signal).toBeInstanceOf(AbortSignal);
    });
  });

  it("refuses a query it did not itself derive, without fetching", async () => {
    const stub = vi.fn();
    vi.stubGlobal("fetch", stub);

    const result = await fetchKeyserverKey({
      kind: "email",
      value: "alice@example.com/../../gists",
    });
    expect(result).toEqual({ ok: false, error: "invalid-query" });
    expect(stub).not.toHaveBeenCalled();
  });

  it("reports a thrown fetch as offline, whatever threw", async () => {
    // Offline, DNS, a CSP block and the redirect refusal all surface as
    // a TypeError with no text worth forwarding.
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("nope")));
    await expect(fetchKeyserverKey(QUERY)).resolves.toEqual({
      ok: false,
      error: "offline",
    });
  });
});

describe("fetchKeyserverKey body caps", () => {
  it("reads a measured response", async () => {
    const { response } = respond({ chunks: encode(CERT) });
    stubFetch(response);

    await expect(fetchKeyserverKey(QUERY)).resolves.toEqual({
      ok: true,
      armored: CERT,
      omitted: 0,
    });
  });

  it("refuses on Content-Length without reading the body at all", () =>
    expectContentLengthRefusal(PGP_CT, MAX_BODY_BYTES, () =>
      fetchKeyserverKey(QUERY),
    ));

  it("stops reading an endless body at the cap instead of buffering it", async () => {
    // No Content-Length -- a chunked response, which is how a hostile
    // body would actually arrive. Without the bounded read this call
    // never returns.
    const { response, probe } = respond({ endless: true });
    stubFetch(response);

    const result = await fetchKeyserverKey(QUERY);
    expect(result).toEqual({ ok: false, error: "server-error" });
    expect(probe.cancelled).toBe(true);
    // 16 KiB chunks against the cap: a handful of reads, not millions.
    expect(probe.pulls).toBeLessThanOrEqual(MAX_BODY_BYTES / 1024);
  });

  it("accepts a body that exactly fills the cap", async () => {
    const padded = `${CERT}${" ".repeat(MAX_BODY_BYTES - CERT.length)}`;
    expect(padded.length).toBe(MAX_BODY_BYTES);
    const { response } = respond({ chunks: encode(padded) });
    stubFetch(response);

    await expect(fetchKeyserverKey(QUERY)).resolves.toMatchObject({ ok: true });
  });
});

describe("fetchKeyserverKey timeout", () => {
  it("gives up on a response that never arrives", () =>
    expectTimeoutOffline(() => fetchKeyserverKey(QUERY)));
});
