import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type * as PreferencesModule from "./preferences";
import type { PgpPreferences } from "./preferences";
import { STORAGE_SETTINGS } from "../constants";
import { DEFAULT_PREFERENCES, strictestPreferences } from "./preferences";
import {
  preferencesStore,
  resetPreferencesStoreForTests,
} from "./preferences-store";

const io = vi.hoisted(() => ({
  getPreferences: vi.fn<() => Promise<PgpPreferences>>(),
  savePreferences: vi.fn<(p: Partial<PgpPreferences>) => Promise<void>>(),
  currentStorageLocation: vi.fn<() => Promise<"local" | "sync">>(),
  hasContactsSession: vi.fn<() => Promise<boolean>>(),
}));

vi.mock("./preferences", async (importOriginal) => ({
  ...(await importOriginal<typeof PreferencesModule>()),
  getPreferences: io.getPreferences,
  savePreferences: io.savePreferences,
}));
vi.mock("../pgp/wasm", () => ({
  hasContactsSession: io.hasContactsSession,
}));
vi.mock("./engine", () => ({
  currentStorageLocation: io.currentStorageLocation,
}));

type ChangeListener = (
  changes: Record<string, chrome.storage.StorageChange>,
  area: chrome.storage.AreaName,
) => void;
const changeListeners = new Set<ChangeListener>();

beforeEach(() => {
  changeListeners.clear();
  vi.stubGlobal("chrome", {
    ...globalThis.chrome,
    storage: {
      onChanged: {
        addListener: (l: ChangeListener) => changeListeners.add(l),
        removeListener: (l: ChangeListener) => changeListeners.delete(l),
      },
    },
  });
  resetPreferencesStoreForTests();
  io.getPreferences.mockReset();
  io.savePreferences.mockReset().mockResolvedValue(undefined);
  io.currentStorageLocation.mockReset().mockResolvedValue("local");
  io.hasContactsSession.mockReset().mockResolvedValue(true);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function deferred<T>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const stored = (patch: Partial<PgpPreferences>): PgpPreferences => ({
  ...DEFAULT_PREFERENCES,
  ...patch,
});

describe("preferencesStore", () => {
  it("starts on the defaults", () => {
    expect(preferencesStore.get()).toEqual(DEFAULT_PREFERENCES);
  });

  it("reload puts what storage holds in the snapshot and notifies", async () => {
    const listener = vi.fn();
    preferencesStore.subscribe(listener);
    io.getPreferences.mockResolvedValue(stored({ autoLockMinutes: 5 }));

    await preferencesStore.reload();

    expect(preferencesStore.get().autoLockMinutes).toBe(5);
    expect(listener).toHaveBeenCalledTimes(1);
  });

  it("a reload that reads the same values keeps the snapshot and stays quiet", async () => {
    io.getPreferences.mockResolvedValue(
      stored({ recentRecipients: ["a", "b"] }),
    );
    await preferencesStore.reload();
    const before = preferencesStore.get();
    const listener = vi.fn();
    preferencesStore.subscribe(listener);

    // A fresh object with equal contents, as every storage read returns.
    io.getPreferences.mockResolvedValue(
      stored({ recentRecipients: ["a", "b"] }),
    );
    await preferencesStore.reload();

    expect(preferencesStore.get()).toBe(before);
    expect(listener).not.toHaveBeenCalled();
  });

  it("a failed read falls back to the strictest preset, not the defaults", async () => {
    io.getPreferences.mockRejectedValue(new Error("torn read"));
    io.currentStorageLocation.mockResolvedValue("sync");

    const result = await preferencesStore.reload();

    expect(result).toBeNull();
    expect(preferencesStore.get()).toEqual({
      ...strictestPreferences(),
      storageLocation: "sync",
    });
  });

  it("update shows the change before the save lands", async () => {
    const save = deferred<void>();
    io.savePreferences.mockReturnValue(save.promise);

    const pending = preferencesStore.update({ advancedMode: true });
    expect(preferencesStore.get().advancedMode).toBe(true);

    save.resolve();
    await pending;
    expect(io.savePreferences).toHaveBeenCalledWith({ advancedMode: true });
  });

  it("a non-optimistic update moves only once the save has landed", async () => {
    const save = deferred<void>();
    io.savePreferences.mockReturnValue(save.promise);

    const pending = preferencesStore.update(
      { unlockKeysOnOpen: true },
      { optimistic: false },
    );
    expect(preferencesStore.get().unlockKeysOnOpen).toBe(false);

    save.resolve();
    await pending;
    expect(preferencesStore.get().unlockKeysOnOpen).toBe(true);
  });

  it("a rejected save rejects and puts the stored value back", async () => {
    io.savePreferences.mockRejectedValue(new Error("will not open"));
    io.getPreferences.mockResolvedValue(stored({ lockOnTabAway: false }));

    await expect(
      preferencesStore.update({ lockOnTabAway: true }),
    ).rejects.toThrow("will not open");
    expect(preferencesStore.get().lockOnTabAway).toBe(false);
  });

  it("a rejected non-optimistic save never shows the new value", async () => {
    io.savePreferences.mockRejectedValue(new Error("will not open"));
    io.getPreferences.mockResolvedValue(stored({}));
    const seen: boolean[] = [];
    preferencesStore.subscribe(() =>
      seen.push(preferencesStore.get().unlockKeysOnOpen),
    );

    await expect(
      preferencesStore.update(
        { unlockKeysOnOpen: true },
        { optimistic: false },
      ),
    ).rejects.toThrow();
    expect(seen).not.toContain(true);
  });

  it("a read that started before a write cannot undo it", async () => {
    const read = deferred<PgpPreferences>();
    io.getPreferences.mockReturnValueOnce(read.promise);

    const reloading = preferencesStore.reload();
    await preferencesStore.update({ autoDownloadText: true });
    // The read was taken before the save: it does not hold the change.
    read.resolve(stored({ autoDownloadText: false }));
    await reloading;

    expect(preferencesStore.get().autoDownloadText).toBe(true);
  });

  it("a read that lands while a write is still saving is dropped", async () => {
    const save = deferred<void>();
    io.savePreferences.mockReturnValue(save.promise);
    const updating = preferencesStore.update({ autoDownloadFiles: true });

    io.getPreferences.mockResolvedValue(stored({ autoDownloadFiles: false }));
    await preferencesStore.reload();
    expect(preferencesStore.get().autoDownloadFiles).toBe(true);

    save.resolve();
    await updating;
    expect(preferencesStore.get().autoDownloadFiles).toBe(true);
  });

  it("a read the last write pushed aside is made again once it settles", async () => {
    // The unlock-time read and the write's own re-read are both dropped while
    // the write settles; a catch-up read must still land.
    const unlockRead = deferred<PgpPreferences>();
    const save = deferred<void>();
    const strict = stored({ autoLockMinutes: 2, lockOnTabAway: true });
    io.getPreferences
      .mockReturnValueOnce(unlockRead.promise)
      .mockResolvedValue(stored({ ...strict, defaultKeyId: "k" }));
    io.savePreferences.mockReturnValue(save.promise);

    const reloading = preferencesStore.reload();
    const updating = preferencesStore.update({ defaultKeyId: "k" });
    unlockRead.resolve(strict);
    await reloading;
    await preferencesStore.reload(); // the write's storage change
    save.resolve();
    await updating;

    await vi.waitFor(() =>
      expect(preferencesStore.get()).toMatchObject({
        autoLockMinutes: 2,
        lockOnTabAway: true,
        defaultKeyId: "k",
      }),
    );
  });

  it("while locked, a re-read takes the bootstrap and keeps the settings", async () => {
    io.getPreferences.mockResolvedValue(
      stored({ autoLockMinutes: 2, neverCacheKeys: true }),
    );
    await preferencesStore.reload();

    // Locked: encrypted settings read back as defaults.
    io.hasContactsSession.mockResolvedValue(false);
    io.getPreferences.mockResolvedValue(stored({ storageLocation: "sync" }));
    await preferencesStore.reload();

    expect(preferencesStore.get()).toMatchObject({
      autoLockMinutes: 2,
      neverCacheKeys: true,
      storageLocation: "sync",
    });
  });

  it("a lock that lands mid-read keeps the settings too", async () => {
    io.getPreferences.mockResolvedValue(stored({ autoLockMinutes: 2 }));
    await preferencesStore.reload();

    io.hasContactsSession
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce(false);
    io.getPreferences.mockResolvedValue(stored({}));
    await preferencesStore.reload();

    expect(preferencesStore.get().autoLockMinutes).toBe(2);
  });

  it("listens for storage changes only while subscribed", () => {
    const off = preferencesStore.subscribe(() => undefined);
    expect(changeListeners.size).toBe(1);
    off();
    expect(changeListeners.size).toBe(0);
  });

  it("re-reads on a settings change from another window", async () => {
    preferencesStore.subscribe(() => undefined);
    io.getPreferences.mockResolvedValue(stored({ crxSigningEnabled: true }));

    for (const l of changeListeners) {
      l({ [STORAGE_SETTINGS]: { newValue: {} } }, "local");
    }
    await vi.waitFor(() =>
      expect(preferencesStore.get().crxSigningEnabled).toBe(true),
    );
  });

  it("ignores changes to other keys and other areas", () => {
    preferencesStore.subscribe(() => undefined);
    for (const l of changeListeners) {
      l({ "some-other-key": { newValue: 1 } }, "local");
      l({ [STORAGE_SETTINGS]: { newValue: {} } }, "session");
    }
    expect(io.getPreferences).not.toHaveBeenCalled();
  });
});
