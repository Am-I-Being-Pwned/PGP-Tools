import { describe, expect, it, vi } from "vitest";

import { createLiveList, notifyStoreChanged } from "./live-list";

let n = 0;
const key = () => `store-${++n}`;

function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((res) => (resolve = res));
  return { promise, resolve };
}

describe("createLiveList", () => {
  it("starts loading and reads on first subscribe", async () => {
    const load = vi.fn().mockResolvedValue(["a"]);
    const list = createLiveList(key(), load);
    expect(list.get()).toEqual({ items: [], loading: true, error: null });

    list.subscribe(() => undefined);
    await vi.waitFor(() => expect(list.get().items).toEqual(["a"]));
    expect(list.get().loading).toBe(false);
    expect(load).toHaveBeenCalledTimes(1);
  });

  // An empty keyring and an unreadable one render alike; only one means
  // "your keys are gone".
  it("reports a store that will not open as an error, not as empty", async () => {
    const list = createLiveList(key(), () =>
      Promise.reject(new Error("aead tag mismatch")),
    );
    await list.refresh();
    expect(list.get()).toMatchObject({ items: [], loading: false });
    expect(list.get().error?.message).toBe("aead tag mismatch");
  });

  it("wraps a non-Error rejection (wasm throws strings)", async () => {
    const list = createLiveList(key(), () =>
      // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors -- the shape under test
      Promise.reject("tag"),
    );
    await list.refresh();
    expect(list.get().error).toBeInstanceOf(Error);
  });

  it("clears the error once a read succeeds", async () => {
    const load = vi
      .fn()
      .mockRejectedValueOnce(new Error("x"))
      .mockResolvedValue([]);
    const list = createLiveList(key(), load);
    await list.refresh();
    await list.refresh();
    expect(list.get().error).toBeNull();
  });

  it("reloads on a write to its own store while watched", async () => {
    const k = key();
    const load = vi.fn().mockResolvedValueOnce([1]).mockResolvedValue([1, 2]);
    const list = createLiveList(k, load);
    list.subscribe(() => undefined);
    await vi.waitFor(() => expect(list.get().items).toEqual([1]));

    notifyStoreChanged("some-other-store");
    notifyStoreChanged(k);
    await vi.waitFor(() => expect(list.get().items).toEqual([1, 2]));
    expect(load).toHaveBeenCalledTimes(2);
  });

  it("an unwatched list reads on its next subscribe instead", async () => {
    const k = key();
    const load = vi.fn().mockResolvedValueOnce([1]).mockResolvedValue([2]);
    const list = createLiveList(k, load);
    const stop = list.subscribe(() => undefined);
    await vi.waitFor(() => expect(list.get().items).toEqual([1]));
    stop();

    notifyStoreChanged(k);
    expect(load).toHaveBeenCalledTimes(1);
    list.subscribe(() => undefined);
    await vi.waitFor(() => expect(list.get().items).toEqual([2]));
  });

  it("an older, slower read cannot overwrite a newer one", async () => {
    const slow = deferred<number[]>();
    const load = vi
      .fn()
      .mockReturnValueOnce(slow.promise)
      .mockResolvedValue([2]);
    const list = createLiveList(key(), load);

    const first = list.refresh();
    await list.refresh();
    slow.resolve([1]);
    await first;
    expect(list.get().items).toEqual([2]);
  });

  it("keeps the same array, and stays quiet, when a read changes nothing", async () => {
    const load = vi.fn().mockImplementation(() => Promise.resolve([{ id: 1 }]));
    const list = createLiveList(key(), load);
    await list.refresh();
    const before = list.get().items;
    const listener = vi.fn();
    list.subscribe(listener);
    await list.refresh();
    expect(list.get().items).toBe(before);
    expect(listener).not.toHaveBeenCalled();
  });
});
