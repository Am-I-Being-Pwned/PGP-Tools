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

import type { KeyserverQuery } from "./query";
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

interface FakeResponseInit {
  status?: number;
  headers?: Record<string, string>;
  chunks?: Uint8Array[];
  /** Emit chunks forever -- the multi-GB body a bounded read must not
   *  buffer. */
  endless?: boolean;
}

/** Records what the code under test actually pulled. */
interface Probe {
  pulls: number;
  cancelled: boolean;
  textCalled: boolean;
}

function fakeResponse(init: FakeResponseInit = {}): {
  response: Response;
  probe: Probe;
} {
  const probe: Probe = { pulls: 0, cancelled: false, textCalled: false };
  const headers = new Headers({ "content-type": PGP_CT, ...init.headers });
  const chunks = init.chunks ?? [];
  let index = 0;

  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      probe.pulls += 1;
      if (init.endless) {
        controller.enqueue(new Uint8Array(16 * 1024).fill(0x20));
        return;
      }
      if (index >= chunks.length) {
        controller.close();
        return;
      }
      controller.enqueue(chunks[index++]);
    },
    cancel() {
      probe.cancelled = true;
    },
  });

  const response = {
    status: init.status ?? 200,
    headers,
    body,
    text: () => {
      probe.textCalled = true;
      return Promise.resolve("");
    },
  } as unknown as Response;

  return { response, probe };
}

function encode(text: string): Uint8Array[] {
  return [new TextEncoder().encode(text)];
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("fetchKeyserverKey request", () => {
  it("asks the documented URL, with the pinned init", () => {
    const { response } = fakeResponse({ chunks: encode(CERT) });
    const stub = vi.fn().mockResolvedValue(response);
    vi.stubGlobal("fetch", stub);

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
    const { response } = fakeResponse({ chunks: encode(CERT) });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));

    await expect(fetchKeyserverKey(QUERY)).resolves.toEqual({
      ok: true,
      armored: CERT,
      omitted: 0,
    });
  });

  it("refuses on Content-Length without reading the body at all", async () => {
    const { response, probe } = fakeResponse({
      headers: { "content-length": String(MAX_BODY_BYTES * 100) },
      endless: true,
    });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));

    const result = await fetchKeyserverKey(QUERY);
    expect(result).toEqual({ ok: false, error: "server-error" });
    // The whole point: nothing was read, and the connection was dropped
    // rather than drained. (One pull is the stream filling its own
    // one-chunk queue at construction -- no reader was ever taken.)
    expect(probe.pulls).toBeLessThanOrEqual(1);
    expect(probe.cancelled).toBe(true);
    expect(probe.textCalled).toBe(false);
  });

  it("stops reading an endless body at the cap instead of buffering it", async () => {
    // No Content-Length -- a chunked response, which is how a hostile
    // body would actually arrive. Without the bounded read this call
    // never returns.
    const { response, probe } = fakeResponse({ endless: true });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));

    const result = await fetchKeyserverKey(QUERY);
    expect(result).toEqual({ ok: false, error: "server-error" });
    expect(probe.cancelled).toBe(true);
    // 16 KiB chunks against the cap: a handful of reads, not millions.
    expect(probe.pulls).toBeLessThanOrEqual(MAX_BODY_BYTES / 1024);
  });

  it("accepts a body that exactly fills the cap", async () => {
    const padded = `${CERT}${" ".repeat(MAX_BODY_BYTES - CERT.length)}`;
    expect(padded.length).toBe(MAX_BODY_BYTES);
    const { response } = fakeResponse({ chunks: encode(padded) });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));

    await expect(fetchKeyserverKey(QUERY)).resolves.toMatchObject({ ok: true });
  });
});

describe("fetchKeyserverKey timeout", () => {
  it("gives up on a response that never arrives", async () => {
    vi.useFakeTimers();
    // The slow-trickle attacker: headers, then silence. `parsingRef` in
    // the panel gates the paste path too, so a hang here disables all
    // key import until the panel is reopened.
    vi.stubGlobal(
      "fetch",
      vi.fn(
        (_url: URL, init: RequestInit) =>
          new Promise((_resolve, reject) => {
            init.signal?.addEventListener("abort", () => {
              reject(new DOMException("aborted", "AbortError"));
            });
          }),
      ),
    );

    const pending = fetchKeyserverKey(QUERY);
    await vi.advanceTimersByTimeAsync(60_000);
    await expect(pending).resolves.toEqual({ ok: false, error: "offline" });
  });
});
