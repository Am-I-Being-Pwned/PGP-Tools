import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  createKeySessionStore,
  dropHandle,
  openThenReseal,
  type KeyHandleEntry,
  type KeySessionStoreDeps,
} from "~/hooks";

const wasm = vi.hoisted(() => ({ dropKey: vi.fn(() => Promise.resolve()) }));
const age = vi.hoisted(() => ({
  closeSshIdentity: vi.fn(() => Promise.resolve()),
  openSshIdentity: vi.fn(),
}));
vi.mock("~/lib/pgp/wasm", () => wasm);
vi.mock("~/lib/age/protect-flow", () => age);

function makeStore() {
  const deps = {
    dropHandle: vi.fn((_e: KeyHandleEntry) => Promise.resolve()),
    updateLastUsed: vi.fn((_id: string) => Promise.resolve()),
    onUnlockedChanged: vi.fn((_ids: Set<string>) => undefined),
    onActivity: vi.fn(),
  } satisfies KeySessionStoreDeps;
  return { store: createKeySessionStore(deps), deps };
}

/** Resolved by hand; stands in for a slow WebAuthn ceremony. */
function deferredOpen() {
  let resolve!: (handle: number) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<number>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { open: () => promise, resolve, reject };
}

/** T-ACTIVE-WASM-CALL / T-FORENSIC-AFTER-LOCK: no handle survives a lock. */
describe("createKeySessionStore: an unlock cannot survive a lock", () => {
  beforeEach(() => vi.clearAllMocks());

  it("drops, rather than stores, a handle whose unlock resolved after lockAll", async () => {
    const { store, deps } = makeStore();
    const ceremony = deferredOpen();

    const unlocked = store.unlock("KEY1", "pgp", ceremony.open);

    // The map is EMPTY, so lockAll alone drops nothing.
    store.lockAll();
    expect(deps.dropHandle).not.toHaveBeenCalled();

    ceremony.resolve(7);

    await expect(unlocked).resolves.toBe(false);
    expect(deps.dropHandle).toHaveBeenCalledExactlyOnceWith({
      handle: 7,
      kind: "pgp",
    });
    expect(store.size()).toBe(0);
    expect(store.getHandle("KEY1")).toBeNull();
    expect(deps.onUnlockedChanged).not.toHaveBeenCalledWith(new Set(["KEY1"]));
    expect(deps.updateLastUsed).not.toHaveBeenCalled();
  });

  it("drops an SSH handle through the SSH dropper when a lock intervenes", async () => {
    const { store, deps } = makeStore();
    const ceremony = deferredOpen();

    const unlocked = store.unlock("SSH1", "ssh", ceremony.open);
    store.lockAll();
    ceremony.resolve(3);

    await expect(unlocked).resolves.toBe(false);
    expect(deps.dropHandle).toHaveBeenCalledExactlyOnceWith({
      handle: 3,
      kind: "ssh",
    });
  });

  it("a per-key lock also invalidates an unlock in flight", async () => {
    const { store, deps } = makeStore();
    const ceremony = deferredOpen();

    const unlocked = store.unlock("KEY1", "pgp", ceremony.open);
    store.lock("KEY1");
    ceremony.resolve(9);

    await expect(unlocked).resolves.toBe(false);
    expect(deps.dropHandle).toHaveBeenCalledExactlyOnceWith({
      handle: 9,
      kind: "pgp",
    });
    expect(store.size()).toBe(0);
  });

  it("does not invalidate an unlock that started AFTER the lock", async () => {
    const { store, deps } = makeStore();

    store.lockAll();
    const ceremony = deferredOpen();
    const unlocked = store.unlock("KEY1", "pgp", ceremony.open);
    ceremony.resolve(4);

    await expect(unlocked).resolves.toBe(true);
    expect(deps.dropHandle).not.toHaveBeenCalled();
    expect(store.getHandle("KEY1")).toBe(4);
  });

  it("invalidates every unlock in flight, not just the newest", async () => {
    const { store, deps } = makeStore();
    const a = deferredOpen();
    const b = deferredOpen();

    const first = store.unlock("KEY1", "pgp", a.open);
    const second = store.unlock("KEY2", "ssh", b.open);
    store.lockAll();
    a.resolve(1);
    b.resolve(2);

    await expect(first).resolves.toBe(false);
    await expect(second).resolves.toBe(false);
    expect(deps.dropHandle).toHaveBeenCalledTimes(2);
    expect(store.size()).toBe(0);
  });

  it("propagates a failed unlock without dropping anything", async () => {
    const { store, deps } = makeStore();
    const ceremony = deferredOpen();

    const unlocked = store.unlock("KEY1", "pgp", ceremony.open);
    ceremony.reject(new Error("wrong password"));

    await expect(unlocked).rejects.toThrow("wrong password");
    expect(deps.dropHandle).not.toHaveBeenCalled();
    expect(store.size()).toBe(0);
  });
});

describe("createKeySessionStore: overwriting an entry never orphans a handle", () => {
  beforeEach(() => vi.clearAllMocks());

  it("drops the previous handle before storing a fresh one for the same key", async () => {
    const { store, deps } = makeStore();

    await store.unlock("KEY1", "pgp", () => Promise.resolve(1));
    expect(deps.dropHandle).not.toHaveBeenCalled();

    // `cacheKeyHandle` path: second handle for the same keyId.
    await store.unlock("KEY1", "pgp", () => Promise.resolve(2));

    expect(deps.dropHandle).toHaveBeenCalledExactlyOnceWith({
      handle: 1,
      kind: "pgp",
    });
    expect(store.getHandle("KEY1")).toBe(2);
    expect(store.size()).toBe(1);
  });

  it("drops the replaced handle with the dropper for ITS kind, not the new one's", async () => {
    const { store, deps } = makeStore();

    await store.unlock("KEY1", "ssh", () => Promise.resolve(5));
    await store.unlock("KEY1", "pgp", () => Promise.resolve(6));

    expect(deps.dropHandle).toHaveBeenCalledExactlyOnceWith({
      handle: 5,
      kind: "ssh",
    });
  });

  it("does not drop a handle that is being re-cached under the same index", async () => {
    const { store, deps } = makeStore();

    await store.unlock("KEY1", "pgp", () => Promise.resolve(1));
    await store.unlock("KEY1", "pgp", () => Promise.resolve(1));

    expect(deps.dropHandle).not.toHaveBeenCalled();
    expect(store.getHandle("KEY1")).toBe(1);
  });

  it("leaves a different key's handle alone", async () => {
    const { store, deps } = makeStore();

    await store.unlock("KEY1", "pgp", () => Promise.resolve(1));
    await store.unlock("KEY2", "pgp", () => Promise.resolve(2));

    expect(deps.dropHandle).not.toHaveBeenCalled();
    expect(store.size()).toBe(2);
  });
});

describe("createKeySessionStore: preserved behaviour", () => {
  beforeEach(() => vi.clearAllMocks());

  it("publishes unlocked ids, stamps last-used and re-arms the timer on unlock", async () => {
    const { store, deps } = makeStore();

    await expect(
      store.unlock("KEY1", "pgp", () => Promise.resolve(1)),
    ).resolves.toBe(true);

    expect(deps.onUnlockedChanged).toHaveBeenLastCalledWith(new Set(["KEY1"]));
    expect(deps.updateLastUsed).toHaveBeenCalledExactlyOnceWith("KEY1");
    expect(deps.onActivity).toHaveBeenCalledOnce();
  });

  it("getHandle returns null without touching the timer for an unknown key", () => {
    const { store, deps } = makeStore();

    expect(store.getHandle("NOPE")).toBeNull();
    expect(deps.onActivity).not.toHaveBeenCalled();
  });

  it("getHandle re-arms the timer on every cryptographic use", async () => {
    const { store, deps } = makeStore();
    await store.unlock("KEY1", "pgp", () => Promise.resolve(1));
    deps.onActivity.mockClear();

    store.getHandle("KEY1");
    store.getHandle("KEY1");

    expect(deps.onActivity).toHaveBeenCalledTimes(2);
  });

  it("lockAll drops every live handle with its own kind and empties the map", async () => {
    const { store, deps } = makeStore();
    await store.unlock("KEY1", "pgp", () => Promise.resolve(1));
    await store.unlock("SSH1", "ssh", () => Promise.resolve(2));

    store.lockAll();

    expect(deps.dropHandle).toHaveBeenCalledTimes(2);
    expect(deps.dropHandle).toHaveBeenCalledWith({ handle: 1, kind: "pgp" });
    expect(deps.dropHandle).toHaveBeenCalledWith({ handle: 2, kind: "ssh" });
    expect(store.size()).toBe(0);
    expect(deps.onUnlockedChanged).toHaveBeenLastCalledWith(new Set());
  });

  it("lock drops only the named key", async () => {
    const { store, deps } = makeStore();
    await store.unlock("KEY1", "pgp", () => Promise.resolve(1));
    await store.unlock("KEY2", "pgp", () => Promise.resolve(2));

    store.lock("KEY1");

    expect(deps.dropHandle).toHaveBeenCalledExactlyOnceWith({
      handle: 1,
      kind: "pgp",
    });
    expect(deps.onUnlockedChanged).toHaveBeenLastCalledWith(new Set(["KEY2"]));
  });

  it("locking an unlocked-but-unknown key is a no-op drop", () => {
    const { store, deps } = makeStore();
    store.lock("NOPE");
    expect(deps.dropHandle).not.toHaveBeenCalled();
  });
});

/** `unlockMany` (SECURITY.md §14): the per-entry check only cancels the
 *  unlock in flight; the batch rule stops the rest. */
describe("createKeySessionStore: a lock mid-batch stops the batch", () => {
  beforeEach(() => vi.clearAllMocks());

  it("stores every entry and resolves to the count", async () => {
    const { store, deps } = makeStore();

    await expect(
      store.unlockMany([
        { keyId: "KEY1", kind: "pgp", open: () => Promise.resolve(1) },
        { keyId: "SSH1", kind: "ssh", open: () => Promise.resolve(2) },
        { keyId: "KEY2", kind: "pgp", open: () => Promise.resolve(3) },
      ]),
    ).resolves.toBe(3);

    expect(store.size()).toBe(3);
    expect(store.getHandle("KEY1")).toBe(1);
    expect(store.getHandle("SSH1")).toBe(2);
    expect(store.getHandle("KEY2")).toBe(3);
    expect(deps.onUnlockedChanged).toHaveBeenLastCalledWith(
      new Set(["KEY1", "SSH1", "KEY2"]),
    );
    expect(deps.updateLastUsed).toHaveBeenCalledTimes(3);
    expect(deps.updateLastUsed).toHaveBeenCalledWith("KEY1");
    expect(deps.updateLastUsed).toHaveBeenCalledWith("SSH1");
    expect(deps.updateLastUsed).toHaveBeenCalledWith("KEY2");
    expect(deps.dropHandle).not.toHaveBeenCalled();
  });

  it("captures the generation BEFORE awaiting a loader, so a lock during the read cancels the batch", async () => {
    const { store, deps } = makeStore();
    const open1 = vi.fn(() => Promise.resolve(1));
    const open2 = vi.fn(() => Promise.resolve(2));
    let release!: () => void;
    const loader = () =>
      new Promise<
        { keyId: string; kind: "pgp" | "ssh"; open: () => Promise<number> }[]
      >((res) => {
        release = () =>
          res([
            { keyId: "KEY1", kind: "pgp", open: open1 },
            { keyId: "KEY2", kind: "pgp", open: open2 },
          ]);
      });

    const batch = store.unlockMany(loader);
    store.lockAll();
    release();

    await expect(batch).resolves.toBe(0);
    expect(open1).not.toHaveBeenCalled();
    expect(open2).not.toHaveBeenCalled();
    expect(store.size()).toBe(0);
    expect(deps.dropHandle).not.toHaveBeenCalled();
  });

  it("a loader with no lock in between runs like a list", async () => {
    const { store } = makeStore();
    await expect(
      store.unlockMany(() =>
        Promise.resolve([
          { keyId: "KEY1", kind: "pgp", open: () => Promise.resolve(1) },
        ]),
      ),
    ).resolves.toBe(1);
    expect(store.getHandle("KEY1")).toBe(1);
  });

  it("a lockAll mid-batch drops the in-flight handle AND never opens the rest", async () => {
    const { store, deps } = makeStore();
    const first = deferredOpen();
    const second = vi.fn(() => Promise.resolve(2));
    const third = vi.fn(() => Promise.resolve(3));

    const batch = store.unlockMany([
      { keyId: "KEY1", kind: "pgp", open: first.open },
      { keyId: "KEY2", kind: "pgp", open: second },
      { keyId: "KEY3", kind: "ssh", open: third },
    ]);

    store.lockAll();
    first.resolve(1);

    await expect(batch).resolves.toBe(0);
    expect(deps.dropHandle).toHaveBeenCalledExactlyOnceWith({
      handle: 1,
      kind: "pgp",
    });
    expect(second).not.toHaveBeenCalled();
    expect(third).not.toHaveBeenCalled();
    expect(store.size()).toBe(0);
    expect(deps.updateLastUsed).not.toHaveBeenCalled();
  });

  it("a per-key lock of an UNRELATED key mid-batch also stops the batch", async () => {
    const { store, deps } = makeStore();
    const first = deferredOpen();
    const second = vi.fn(() => Promise.resolve(2));

    const batch = store.unlockMany([
      { keyId: "KEY1", kind: "pgp", open: first.open },
      { keyId: "KEY2", kind: "pgp", open: second },
    ]);

    store.lock("OTHER");
    first.resolve(1);

    await expect(batch).resolves.toBe(0);
    expect(deps.dropHandle).toHaveBeenCalledExactlyOnceWith({
      handle: 1,
      kind: "pgp",
    });
    expect(second).not.toHaveBeenCalled();
    expect(store.size()).toBe(0);
  });

  it("skips an entry whose open rejects and still stores the rest", async () => {
    const { store, deps } = makeStore();

    await expect(
      store.unlockMany([
        { keyId: "KEY1", kind: "pgp", open: () => Promise.resolve(1) },
        {
          keyId: "BAD",
          kind: "pgp",
          open: () => Promise.reject(new Error("aead failure")),
        },
        { keyId: "KEY3", kind: "pgp", open: () => Promise.resolve(3) },
      ]),
    ).resolves.toBe(2);

    expect(store.size()).toBe(2);
    expect(store.getHandle("KEY1")).toBe(1);
    expect(store.getHandle("BAD")).toBeNull();
    expect(store.getHandle("KEY3")).toBe(3);
    expect(deps.dropHandle).not.toHaveBeenCalled();
    expect(deps.updateLastUsed).not.toHaveBeenCalledWith("BAD");
  });

  it("a batch started AFTER a lock runs normally", async () => {
    const { store, deps } = makeStore();

    store.lockAll();
    store.lock("KEY1");

    await expect(
      store.unlockMany([
        { keyId: "KEY1", kind: "pgp", open: () => Promise.resolve(1) },
        { keyId: "KEY2", kind: "pgp", open: () => Promise.resolve(2) },
      ]),
    ).resolves.toBe(2);

    expect(store.size()).toBe(2);
    expect(deps.dropHandle).not.toHaveBeenCalled();
  });
});

describe("dropHandle routes to the store the handle came from", () => {
  beforeEach(() => vi.clearAllMocks());

  it("sends a PGP handle to wasm dropKey", async () => {
    await dropHandle({ handle: 4, kind: "pgp" });
    expect(wasm.dropKey).toHaveBeenCalledExactlyOnceWith(4);
    expect(age.closeSshIdentity).not.toHaveBeenCalled();
  });

  it("sends an SSH handle to closeSshIdentity", async () => {
    await dropHandle({ handle: 4, kind: "ssh" });
    expect(age.closeSshIdentity).toHaveBeenCalledExactlyOnceWith(4);
    expect(wasm.dropKey).not.toHaveBeenCalled();
  });
});

describe("openThenReseal: the migration is on disk before the key shows unlocked", () => {
  beforeEach(() => vi.clearAllMocks());

  it("persists the re-seal before the handle is published", async () => {
    const { store, deps } = makeStore();
    const order: string[] = [];
    deps.onUnlockedChanged.mockImplementation(() => {
      order.push("published");
    });
    const reseal = vi.fn(async (handle: number) => {
      await Promise.resolve();
      order.push(`resealed:${handle}`);
    });

    await expect(
      store.unlock("KEY1", "pgp", () =>
        openThenReseal(() => Promise.resolve(7), reseal),
      ),
    ).resolves.toBe(true);

    expect(reseal).toHaveBeenCalledExactlyOnceWith(7);
    expect(order).toEqual(["resealed:7", "published"]);
    expect(store.getHandle("KEY1")).toBe(7);
  });

  it("a failed re-seal still unlocks the key", async () => {
    const { store } = makeStore();
    await expect(
      store.unlock("KEY1", "pgp", () =>
        openThenReseal(
          () => Promise.resolve(3),
          () => Promise.reject(new Error("write failed")),
        ),
      ),
    ).resolves.toBe(true);
    expect(store.getHandle("KEY1")).toBe(3);
  });

  it("no re-seal: just the open", async () => {
    await expect(openThenReseal(() => Promise.resolve(5), null)).resolves.toBe(
      5,
    );
  });

  it("does not re-seal when the open fails", async () => {
    const reseal = vi.fn(() => Promise.resolve());
    await expect(
      openThenReseal(() => Promise.reject(new Error("wrong key")), reseal),
    ).rejects.toThrow("wrong key");
    expect(reseal).not.toHaveBeenCalled();
  });

  it("a lock during the re-seal still drops the handle", async () => {
    const { store, deps } = makeStore();
    let finish!: () => void;
    const pending = store.unlock("KEY1", "pgp", () =>
      openThenReseal(
        () => Promise.resolve(9),
        () =>
          new Promise<void>((res) => {
            finish = res;
          }),
      ),
    );
    await vi.waitFor(() => expect(finish).toBeTypeOf("function"));
    store.lockAll();
    finish();
    await expect(pending).resolves.toBe(false);
    expect(store.getHandle("KEY1")).toBeNull();
    expect(deps.dropHandle).toHaveBeenCalledWith({ handle: 9, kind: "pgp" });
  });
});
