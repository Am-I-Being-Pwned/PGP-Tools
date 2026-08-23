import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { PendingOperation } from "./messages";
import { SESSION_PENDING_OP } from "./constants";
import {
  isPendingOperation,
  isPendingOpFresh,
  PENDING_OP_TTL_MS,
  sweepStalePendingOp,
} from "./pending-op";

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

/**
 * A `chrome.storage.session` stand-in. `onRead` fires after each `get`
 * resolves, which is where the writer's `set` lands in the race the
 * sweep's id re-read exists to survive.
 */
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

/**
 * The security-relevant half. The stored `text` is the user's raw
 * selection, and it is stored unsealed, so the only thing bounding the
 * exposure is how long the entry lives. Before this sweep existed the
 * entry was removed ONLY by the side panel reading it, so any path where
 * the panel never mounted left the selection in `chrome.storage.session`
 * until browser shutdown.
 */
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
    // The realistic race: this sweep runs at worker start, and the thing
    // that woke the worker is the context-menu click, whose `set` lands
    // right after our first read. Deleting there would drop the user's
    // brand-new selection.
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
