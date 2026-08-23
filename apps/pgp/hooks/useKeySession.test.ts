import { beforeEach, describe, expect, it, vi } from "vitest";

const wasm = vi.hoisted(() => ({ dropKey: vi.fn(() => Promise.resolve()) }));
const age = vi.hoisted(() => ({
  closeSshIdentity: vi.fn(() => Promise.resolve()),
  openSshIdentity: vi.fn(),
}));
vi.mock("../lib/pgp/wasm", () => wasm);
vi.mock("../lib/age/protect-flow", () => age);

import type { KeyHandleEntry, KeySessionStoreDeps } from "./useKeySession";
import { createKeySessionStore, dropHandle } from "./useKeySession";

/** A store wired to spies, plus the spies. */
function makeStore() {
  const deps = {
    dropHandle: vi.fn((_e: KeyHandleEntry) => Promise.resolve()),
    updateLastUsed: vi.fn((_id: string) => Promise.resolve()),
    onUnlockedChanged: vi.fn((_ids: Set<string>) => undefined),
    onActivity: vi.fn(),
  } satisfies KeySessionStoreDeps;
  return { store: createKeySessionStore(deps), deps };
}

/** An `open` that the test resolves by hand, standing in for the
 *  seconds-long user-interactive WebAuthn ceremony. */
function deferredOpen() {
  let resolve!: (handle: number) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<number>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { open: () => promise, resolve, reject };
}

/**
 * The load-bearing claim in the threat model (T-ACTIVE-WASM-CALL,
 * T-FORENSIC-AFTER-LOCK) is that no key handle survives a lock, so the
 * attack window is exactly the unlocked window. These two describes are
 * the counterexamples that used to be reachable.
 */
describe("createKeySessionStore: an unlock cannot survive a lock", () => {
  beforeEach(() => vi.clearAllMocks());

  it("drops, rather than stores, a handle whose unlock resolved after lockAll", async () => {
    const { store, deps } = makeStore();
    const ceremony = deferredOpen();

    // User clicks Unlock; the OS passkey dialog is up.
    const unlocked = store.unlock("KEY1", "pgp", ceremony.open);

    // The machine locks. The map is EMPTY, so lockAll drops nothing --
    // this is exactly why the count-based check is not enough.
    store.lockAll();
    expect(deps.dropHandle).not.toHaveBeenCalled();

    // User comes back and completes the ceremony.
    ceremony.resolve(7);

    await expect(unlocked).resolves.toBe(false);
    expect(deps.dropHandle).toHaveBeenCalledExactlyOnceWith({
      handle: 7,
      kind: "pgp",
    });
    expect(store.size()).toBe(0);
    expect(store.getHandle("KEY1")).toBeNull();
    // Nothing may claim the key is unlocked, and nothing may re-arm the
    // inactivity timer on behalf of a handle that no longer exists.
    expect(deps.onUnlockedChanged).not.toHaveBeenCalledWith(
      new Set(["KEY1"]),
    );
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

    // The `cacheKeyHandle` path: a re-import of a key that is currently
    // unlocked hands us a second handle for the same keyId. Handle 1 is
    // about to leave the map, so this is the last chance to drop it.
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

    // The entry handed to dropHandle carries `ssh`, so the SSH_KEY_STORE
    // dropper is selected -- handing index 5 to the PGP store would
    // either leak the identity or drop an unrelated PGP key.
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

    await expect(store.unlock("KEY1", "pgp", () => Promise.resolve(1))).resolves.toBe(
      true,
    );

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
