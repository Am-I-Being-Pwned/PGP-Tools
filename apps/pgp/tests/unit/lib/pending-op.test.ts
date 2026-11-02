import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SESSION_PENDING_OP } from "~/lib/constants";
import type { PendingOperation } from "~/lib/messages";
import {
  isPendingOperation,
  isPendingOpForWindow,
  isPendingOpFresh,
  PENDING_OP_TTL_MS,
  sweepStalePendingOp,
} from "~/lib/pending-op";

const NOW = 1_700_000_000_000;

function op(overrides: Partial<PendingOperation> = {}): PendingOperation {
  return {
    type: "PENDING_OPERATION",
    id: "op-1",
    action: "encrypt",
    text: "attack at dawn",
    sourceTabId: 7,
    createdAt: NOW,
    ...overrides,
  };
}

/** `onRead` fires after each `get`, where the writer's racing `set` lands. */
function fakeSession(initial: unknown) {
  const store: { value: unknown } = { value: initial };
  let reads = 0;
  const hooks: { onRead?: (n: number) => void } = {};
  const area = {
    get: vi.fn((_key: string) => {
      reads += 1;
      const snapshot = store.value;
      hooks.onRead?.(reads);
      return Promise.resolve(
        snapshot === undefined ? {} : { [SESSION_PENDING_OP]: snapshot },
      );
    }),
    remove: vi.fn((_key: string) => {
      store.value = undefined;
      return Promise.resolve();
    }),
  };
  return { area, store, hooks };
}

function install(initial: unknown) {
  const session = fakeSession(initial);
  (globalThis as { chrome?: unknown }).chrome = {
    storage: { session: session.area },
  };
  return session;
}

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  delete (globalThis as { chrome?: unknown }).chrome;
});

describe("isPendingOperation", () => {
  it("accepts a well-formed op", () => {
    expect(isPendingOperation(op())).toBe(true);
  });

  it("rejects an unknown action, so a future action cannot be smuggled in", () => {
    expect(isPendingOperation({ ...op(), action: "exfiltrate" })).toBe(false);
  });

  it("rejects non-objects and missing fields", () => {
    expect(isPendingOperation(null)).toBe(false);
    expect(isPendingOperation("PENDING_OPERATION")).toBe(false);
    const { text: _text, ...noText } = op();
    expect(isPendingOperation(noText)).toBe(false);
  });
});

describe("isPendingOpFresh", () => {
  it("is fresh up to the TTL and stale after it", () => {
    expect(isPendingOpFresh(op(), NOW + PENDING_OP_TTL_MS - 1)).toBe(true);
    expect(isPendingOpFresh(op(), NOW + PENDING_OP_TTL_MS)).toBe(false);
  });
});

/** Security-relevant: the unsealed selection's lifetime is its exposure. */
describe("sweepStalePendingOp", () => {
  it("removes an op the panel never collected", async () => {
    const s = install(op({ createdAt: NOW - PENDING_OP_TTL_MS - 1 }));
    await sweepStalePendingOp(NOW);
    expect(s.area.remove).toHaveBeenCalledWith(SESSION_PENDING_OP);
    expect(s.store.value).toBeUndefined();
  });

  it("removes a malformed value, which the panel's reader ignores forever", async () => {
    const s = install({ type: "PENDING_OPERATION", text: "attack at dawn" });
    await sweepStalePendingOp(NOW);
    expect(s.store.value).toBeUndefined();
  });

  it("leaves a fresh op alone -- the panel may still be starting up", async () => {
    const s = install(op({ createdAt: NOW - 1 }));
    await sweepStalePendingOp(NOW);
    expect(s.area.remove).not.toHaveBeenCalled();
    expect(s.store.value).not.toBeUndefined();
  });

  it("does nothing when there is no entry", async () => {
    const s = install(undefined);
    await sweepStalePendingOp(NOW);
    expect(s.area.remove).not.toHaveBeenCalled();
  });

  it("does not eat a selection written between the read and the remove", async () => {
    // The click that woke the worker writes right after our first read.
    const fresh = op({ id: "op-2", createdAt: NOW });
    const s = install(
      op({ id: "op-1", createdAt: NOW - PENDING_OP_TTL_MS - 1 }),
    );
    s.hooks.onRead = (n) => {
      if (n === 1) s.store.value = fresh;
    };
    await sweepStalePendingOp(NOW);
    expect(s.area.remove).not.toHaveBeenCalled();
    expect(s.store.value).toBe(fresh);
  });
});

describe("isPendingOpForWindow", () => {
  const op = (windowId?: number): PendingOperation => ({
    type: "PENDING_OPERATION",
    id: "x",
    action: "verify",
    text: "t",
    sourceTabId: 1,
    ...(windowId === undefined ? {} : { windowId }),
    createdAt: 0,
  });

  it("gives a selection only to the panel of the window it came from", () => {
    expect(isPendingOpForWindow(op(7), 7)).toBe(true);
    expect(isPendingOpForWindow(op(7), 8)).toBe(false);
  });

  it("lets any panel take an op written before ops carried a window", () => {
    expect(isPendingOpForWindow(op(), 8)).toBe(true);
  });

  it("validates the window id's type", () => {
    expect(isPendingOperation({ ...op(), windowId: "7" })).toBe(false);
    expect(isPendingOperation(op(7))).toBe(true);
  });
});
