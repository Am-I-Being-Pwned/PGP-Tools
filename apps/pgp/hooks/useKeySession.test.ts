import { beforeEach, describe, expect, it, vi } from "vitest";

import type { KeyHandleEntry, KeySessionStoreDeps } from "./useKeySession";
import { createKeySessionStore, dropHandle } from "./useKeySession";

const wasm = vi.hoisted(() => ({ dropKey: vi.fn(() => Promise.resolve()) }));
const age = vi.hoisted(() => ({
  closeSshIdentity: vi.fn(() => Promise.resolve()),
  openSshIdentity: vi.fn(),
}));
vi.mock("../lib/pgp/wasm", () => wasm);
vi.mock("../lib/age/protect-flow", () => age);

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

/**
 * `unlockMany` is the "unlock keys when the vault unlocks" batch: several
 * unlocks off ONE PRF output (SECURITY.md §14). Each entry still goes
 * through `unlock`, so the per-entry generation check above applies --
 * but that check only cancels the unlock IN FLIGHT. Without the batch
 * rule, the next iteration would capture the NEW generation and insert
 * a live key behind the lock screen. The mid-batch lock tests are that
 * counterexample.
 */
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
    // App hands the batch a loader (preference + keyring reads, both
    // IndexedDB round trips) rather than a list. A lock that lands
    // while the loader is pending must cancel everything: otherwise
    // that window sits outside the rule and only the store read
    // failing without a session keeps keys from going live behind the
    // lock screen.
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
    // The vault locks while the keyring is still being read.
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

    // The machine locks while the first open is still pending.
    store.lockAll();
    first.resolve(1);

    await expect(batch).resolves.toBe(0);
    // The one in flight is dropped by the per-entry check...
    expect(deps.dropHandle).toHaveBeenCalledExactlyOnceWith({
      handle: 1,
      kind: "pgp",
    });
    // ...and the rest are never even started: an open under the new
    // generation would have been STORED, behind the lock screen.
    expect(second).not.toHaveBeenCalled();
    expect(third).not.toHaveBeenCalled();
    expect(store.size()).toBe(0);
    expect(deps.updateLastUsed).not.toHaveBeenCalled();
  });

  it("a per-key lock of an UNRELATED key mid-batch also stops the batch", async () => {
    // Per-key locks bump the global generation; the batch rule keys off
    // that same counter, so it is just as conservative here.
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
    // A blob that turns out not to open off this output (tampered, or
    // sealed differently after all) must not cost the user the others.
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
    // The generation captured at batch start is the one that counts;
    // an earlier lock is history, not a mid-batch event.
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
