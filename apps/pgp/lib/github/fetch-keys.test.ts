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

import { fetchGithubKeys } from "./fetch-keys";
import { MAX_BODY_BYTES } from "./response";

const JSON_CT = "application/json; charset=utf-8";
const ED25519 =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGdummykeymaterialforunittests01";

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
  const headers = new Headers({ "content-type": JSON_CT, ...init.headers });
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

describe("fetchGithubKeys body caps", () => {
  it("reads a measured response", async () => {
    const { response } = fakeResponse({
      chunks: encode(JSON.stringify([{ id: 1, key: ED25519 }])),
    });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));

    const result = await fetchGithubKeys("octocat");
    expect(result).toEqual({ ok: true, lines: [ED25519], omitted: 0 });
  });

  it("refuses on Content-Length without reading the body at all", async () => {
    const { response, probe } = fakeResponse({
      headers: { "content-length": String(MAX_BODY_BYTES * 100) },
      endless: true,
    });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));

    const result = await fetchGithubKeys("octocat");
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
    const { response } = fakeResponse({ chunks: encode(padded) });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));

    const result = await fetchGithubKeys("octocat");
    expect(result.ok).toBe(true);
  });
});

describe("fetchGithubKeys timeout", () => {
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

    const pending = fetchGithubKeys("octocat");
    await vi.advanceTimersByTimeAsync(60_000);
    await expect(pending).resolves.toEqual({ ok: false, error: "offline" });
  });

  it("passes an AbortSignal to fetch", async () => {
    const { response } = fakeResponse({
      chunks: encode(JSON.stringify([{ id: 1, key: ED25519 }])),
    });
    const stub = vi.fn().mockResolvedValue(response);
    vi.stubGlobal("fetch", stub);

    await fetchGithubKeys("octocat");
    const init = stub.mock.calls[0][1] as RequestInit;
    expect(init.signal).toBeInstanceOf(AbortSignal);
    expect(init.credentials).toBe("omit");
    expect(init.redirect).toBe("error");
  });
});
