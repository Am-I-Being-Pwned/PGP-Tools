/** Transport half; twin of `lib/github/fetch-keys.test.ts` so the shared
 *  capped reader is exercised on both lookups. */
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
      // A redirect is a server-chosen origin.
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
    // Chunked, no Content-Length: how a hostile body arrives.
    const { response, probe } = respond({ endless: true });
    stubFetch(response);

    const result = await fetchKeyserverKey(QUERY);
    expect(result).toEqual({ ok: false, error: "server-error" });
    expect(probe.cancelled).toBe(true);
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
