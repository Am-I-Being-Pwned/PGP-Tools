import { describe, expect, it } from "vitest";

import { withLock } from "./engine";

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
