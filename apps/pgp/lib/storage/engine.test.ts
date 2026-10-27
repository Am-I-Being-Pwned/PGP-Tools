import { afterEach, describe, expect, it, vi } from "vitest";

import { withLock, withSharedLock } from "./engine";

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("withLock", () => {
  it("serializes operations on the same key", async () => {
    const order: string[] = [];
    const first = withLock("same", async () => {
      order.push("first:start");
      await wait(20);
      order.push("first:end");
    });
    const second = withLock("same", () => {
      order.push("second");
      return Promise.resolve();
    });
    await Promise.all([first, second]);
    expect(order).toEqual(["first:start", "first:end", "second"]);
  });

  it("lets different keys interleave", async () => {
    const order: string[] = [];
    const slow = withLock("a", async () => {
      await wait(20);
      order.push("slow");
    });
    const fast = withLock("b", () => {
      order.push("fast");
      return Promise.resolve();
    });
    await Promise.all([slow, fast]);
    expect(order).toEqual(["fast", "slow"]);
  });

  it("returns the callback's value", async () => {
    await expect(withLock("ret", () => Promise.resolve(42))).resolves.toBe(42);
  });

  it("releases the lock after a rejection", async () => {
    await expect(
      withLock("err", () => Promise.reject(new Error("boom"))),
    ).rejects.toThrow("boom");
    await expect(withLock("err", () => Promise.resolve("ok"))).resolves.toBe(
      "ok",
    );
  });
});

/**
 * `withLock` is one Map per page, so two panel windows could both pass
 * the master protection's "none exists" check before either wrote, or
 * lose a ledger update. The shared variant goes through Web Locks, which
 * every extension page of the origin shares.
 */
describe("withSharedLock", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("takes a Web Lock named for the key when the API exists", async () => {
    const request = vi.fn((_name: string, fn: () => Promise<unknown>) => fn());
    vi.stubGlobal("navigator", { locks: { request } });
    await expect(withSharedLock("k", () => Promise.resolve(7))).resolves.toBe(
      7,
    );
    expect(request).toHaveBeenCalledWith("pgp-tools:k", expect.any(Function));
  });

  it("falls back to the per-page lock without it", async () => {
    vi.stubGlobal("navigator", {});
    const order: string[] = [];
    const first = withSharedLock("same", async () => {
      order.push("first:start");
      await wait(20);
      order.push("first:end");
    });
    const second = withSharedLock("same", () => {
      order.push("second");
      return Promise.resolve();
    });
    await Promise.all([first, second]);
    expect(order).toEqual(["first:start", "first:end", "second"]);
  });
});
