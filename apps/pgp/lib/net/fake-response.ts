/**
 * TEST-ONLY `fetch` doubles for the lookups that share `capped-body.ts`
 * (GitHub keys, keys.openpgp.org). Imported exclusively from `*.test.ts`.
 *
 * The response is hand-rolled rather than a real `Response`: the point of
 * each case is exactly which of `body`, `text()` and `cancel()` the code
 * touches, and the probe records that.
 */

import { expect, vi } from "vitest";

export interface FakeResponseInit {
  status?: number;
  headers?: Record<string, string>;
  chunks?: Uint8Array[];
  /** Emit chunks forever -- the multi-GB body a bounded read must not
   *  buffer. */
  endless?: boolean;
}

/** Records what the code under test actually pulled. */
export interface Probe {
  pulls: number;
  cancelled: boolean;
  textCalled: boolean;
}

export function fakeResponse(
  contentType: string,
  init: FakeResponseInit = {},
): { response: Response; probe: Probe } {
  const probe: Probe = { pulls: 0, cancelled: false, textCalled: false };
  const headers = new Headers({ "content-type": contentType, ...init.headers });
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

export function encode(text: string): Uint8Array[] {
  return [new TextEncoder().encode(text)];
}

/** Stub global `fetch` to resolve with `response`; returns the mock. */
export function stubFetch(response: Response) {
  const stub = vi.fn().mockResolvedValue(response);
  vi.stubGlobal("fetch", stub);
  return stub;
}

// ── cases both fetchers must pass ────────────────────────────────────

/** A Content-Length over the cap is refused without reading the body. */
export async function expectContentLengthRefusal(
  contentType: string,
  maxBodyBytes: number,
  call: () => Promise<unknown>,
) {
  const { response, probe } = fakeResponse(contentType, {
    headers: { "content-length": String(maxBodyBytes * 100) },
    endless: true,
  });
  stubFetch(response);

  const result = await call();
  expect(result).toEqual({ ok: false, error: "server-error" });
  // The whole point: nothing was read, and the connection was dropped
  // rather than drained. (One pull is the stream filling its own
  // one-chunk queue at construction -- no reader was ever taken.)
  expect(probe.pulls).toBeLessThanOrEqual(1);
  expect(probe.cancelled).toBe(true);
  expect(probe.textCalled).toBe(false);
}

/** The slow-trickle attacker: headers, then silence. `parsingRef` in the
 *  panel gates the paste path too, so a hang here disables all key import
 *  until the panel is reopened. Caller restores real timers. */
export async function expectTimeoutOffline(call: () => Promise<unknown>) {
  vi.useFakeTimers();
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

  const pending = call();
  await vi.advanceTimersByTimeAsync(60_000);
  await expect(pending).resolves.toEqual({ ok: false, error: "offline" });
}
