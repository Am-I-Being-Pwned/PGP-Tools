/**
 * The transport half: what happens to a response we do not control
 * BEFORE `parseGithubKeysResponse` ever sees it.
 *
 * These are the tests for the caps SECURITY.md claims are "applied
 * before parsing" -- the claim is only true if the body is bounded as it
 * arrives. `fetch` is stubbed with a hand-rolled response object rather
 * than a real one: the point of each case is exactly which of `body`,
 * `text()` and `cancel()` the code touches.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

import type { FakeResponseInit } from "../net/fake-response";
import {
  encode,
  expectContentLengthRefusal,
  expectTimeoutOffline,
  fakeResponse,
  stubFetch,
} from "../net/fake-response";
import { fetchGithubKeys } from "./fetch-keys";
import { MAX_BODY_BYTES } from "./response";

const JSON_CT = "application/json; charset=utf-8";
const ED25519 =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGdummykeymaterialforunittests01";

const respond = (init?: FakeResponseInit) => fakeResponse(JSON_CT, init);

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("fetchGithubKeys body caps", () => {
  it("reads a measured response", async () => {
    const { response } = respond({
      chunks: encode(JSON.stringify([{ id: 1, key: ED25519 }])),
    });
    stubFetch(response);

    const result = await fetchGithubKeys("octocat");
    expect(result).toEqual({ ok: true, lines: [ED25519], omitted: 0 });
  });

  it("refuses on Content-Length without reading the body at all", () =>
    expectContentLengthRefusal(JSON_CT, MAX_BODY_BYTES, () =>
      fetchGithubKeys("octocat"),
    ));

  it("stops reading an endless body at the cap instead of buffering it", async () => {
    // No Content-Length -- a chunked response, which is how a hostile
    // body would actually arrive. Without the bounded read this call
    // never returns.
    const { response, probe } = respond({ endless: true });
    stubFetch(response);

    const result = await fetchGithubKeys("octocat");
    expect(result).toEqual({ ok: false, error: "server-error" });
    expect(probe.cancelled).toBe(true);
    // 16 KiB chunks against a 64 KiB cap: five reads, not five million.
    expect(probe.pulls).toBeLessThanOrEqual(MAX_BODY_BYTES / 1024);
  });

  it("accepts a body one byte under the cap", async () => {
    const keys = JSON.stringify([{ id: 1, key: ED25519 }]);
    const padded = `${keys}${" ".repeat(MAX_BODY_BYTES - keys.length)}`;
    expect(padded.length).toBe(MAX_BODY_BYTES);
    const { response } = respond({ chunks: encode(padded) });
    stubFetch(response);

    const result = await fetchGithubKeys("octocat");
    expect(result.ok).toBe(true);
  });
});

describe("fetchGithubKeys timeout", () => {
  it("gives up on a response that never arrives", () =>
    expectTimeoutOffline(() => fetchGithubKeys("octocat")));

  it("passes an AbortSignal to fetch", async () => {
    const { response } = respond({
      chunks: encode(JSON.stringify([{ id: 1, key: ED25519 }])),
    });
    const stub = stubFetch(response);

    await fetchGithubKeys("octocat");
    const init = stub.mock.calls[0][1] as RequestInit;
    expect(init.signal).toBeInstanceOf(AbortSignal);
    expect(init.credentials).toBe("omit");
    expect(init.redirect).toBe("error");
  });
});
