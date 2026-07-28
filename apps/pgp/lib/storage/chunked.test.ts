import { describe, expect, it } from "vitest";

import type { StorageArea } from "./chunked";
import {
  getChunked,
  IncompleteChunkedValueError,
  isQuotaExceeded,
  removeChunked,
  setChunked,
} from "./chunked";

/**
 * In-memory stand-in for a browser.storage area. `perItemCap` mirrors
 * sync's QUOTA_BYTES_PER_ITEM: set() throws the same way Chrome does when
 * an item's key + JSON(value) exceeds the cap, so a test can prove that
 * chunking keeps every item under the limit.
 */
function fakeArea(perItemCap = Infinity) {
  const store = new Map<string, unknown>();
  const itemBytes = (k: string, v: unknown) =>
    k.length + JSON.stringify(v).length;
  const area = {
    store,
    get: (keys?: string | string[] | null) => {
      if (keys == null) return Promise.resolve(Object.fromEntries(store));
      const list = Array.isArray(keys) ? keys : [keys];
      const out: Record<string, unknown> = {};
      for (const k of list) if (store.has(k)) out[k] = store.get(k);
      return Promise.resolve(out);
    },
    set: (items: Record<string, unknown>) => {
      for (const [k, v] of Object.entries(items)) {
        if (itemBytes(k, v) > perItemCap) {
          return Promise.reject(
            new Error("Resource::kQuotaBytesPerItem quota exceeded"),
          );
        }
      }
      for (const [k, v] of Object.entries(items)) store.set(k, v);
      return Promise.resolve();
    },
    remove: (keys: string | string[]) => {
      const list = Array.isArray(keys) ? keys : [keys];
      for (const k of list) store.delete(k);
      return Promise.resolve();
    },
  };
  return area as typeof area & StorageArea;
}

const SYNC_PER_ITEM_CAP = 8192;
const blob = (n: number) => ({ iv: "aXY=", ciphertext: "Q".repeat(n) });

describe("chunked storage", () => {
  it("stores a small value verbatim (no manifest, no chunk items)", async () => {
    const area = fakeArea(SYNC_PER_ITEM_CAP);
    await setChunked(area, "k", blob(100), true);

    expect(area.store.get("k")).toEqual(blob(100));
    expect([...area.store.keys()]).toEqual(["k"]);
    expect(await getChunked(area, "k")).toEqual(blob(100));
  });

  it("splits an oversized value so no single item exceeds the cap", async () => {
    // ~40 KB blob: one item would be ~5x the 8 KB cap.
    const area = fakeArea(SYNC_PER_ITEM_CAP);
    const big = blob(40_000);

    // Would throw against the cap if written as one item; must not here.
    await expect(setChunked(area, "k", big, true)).resolves.toBeUndefined();

    // The head key holds a manifest, not the value.
    const head = area.store.get("k") as { __sc?: number };
    expect(typeof head.__sc).toBe("number");
    // Every stored item is under the per-item cap.
    for (const [key, value] of area.store) {
      expect(key.length + JSON.stringify(value).length).toBeLessThanOrEqual(
        SYNC_PER_ITEM_CAP,
      );
    }
    // Round-trips back to the original value.
    expect(await getChunked(area, "k")).toEqual(big);
  });

  it("a single oversized item throws, proving the fix is load-bearing", async () => {
    const area = fakeArea(SYNC_PER_ITEM_CAP);
    await expect(area.set({ k: blob(40_000) })).rejects.toThrow(/quota/i);
  });

  it("shrinking a chunked value drops the stale chunk items", async () => {
    const area = fakeArea(SYNC_PER_ITEM_CAP);
    await setChunked(area, "k", blob(40_000), true);
    const chunkedCount = area.store.size;
    expect(chunkedCount).toBeGreaterThan(2);

    // Overwrite with something small: manifest + all chunks collapse to one.
    await setChunked(area, "k", blob(50), true);
    expect([...area.store.keys()]).toEqual(["k"]);
    expect(await getChunked(area, "k")).toEqual(blob(50));
  });

  it("removeChunked clears the manifest and every chunk", async () => {
    const area = fakeArea(SYNC_PER_ITEM_CAP);
    await setChunked(area, "k", blob(40_000), true);
    expect(area.store.size).toBeGreaterThan(1);

    await removeChunked(area, "k");
    expect(area.store.size).toBe(0);
    expect(await getChunked(area, "k")).toBeUndefined();
  });

  it("never chunks when chunk=false (local), even for large values", async () => {
    // No cap (local); a huge value stays one verbatim item so length-hiding
    // padding survives untouched.
    const area = fakeArea();
    const big = blob(40_000);
    await setChunked(area, "k", big, false);

    expect([...area.store.keys()]).toEqual(["k"]);
    expect(area.store.get("k")).toEqual(big);
  });

  it("getChunked throws (not undefined) when a chunk is missing", async () => {
    // A missing chunk means a torn / mid-sync read, NOT an empty store --
    // returning undefined here would let a read-modify-write clobber the
    // real data. It must throw so the caller aborts.
    const area = fakeArea(SYNC_PER_ITEM_CAP);
    await setChunked(area, "k", blob(40_000), true);
    const manifest = area.store.get("k") as { __sc: number };
    area.store.delete(`k::sc${manifest.__sc - 1}`);

    await expect(getChunked(area, "k")).rejects.toBeInstanceOf(
      IncompleteChunkedValueError,
    );
  });

  it("getChunked throws when a chunk is stale (length mismatch)", async () => {
    // Cross-device: the new manifest has arrived but an old, shorter chunk
    // of a prior write is still present. The length guard catches it.
    const area = fakeArea(SYNC_PER_ITEM_CAP);
    await setChunked(area, "k", blob(40_000), true);
    area.store.set("k::sc0", "tampered-short");

    await expect(getChunked(area, "k")).rejects.toBeInstanceOf(
      IncompleteChunkedValueError,
    );
  });

  it("a genuinely absent key still returns undefined", async () => {
    const area = fakeArea(SYNC_PER_ITEM_CAP);
    expect(await getChunked(area, "nope")).toBeUndefined();
  });

  it("isQuotaExceeded recognises the Chrome quota error", () => {
    expect(
      isQuotaExceeded(new Error("Resource::kQuotaBytesPerItem quota exceeded")),
    ).toBe(true);
    expect(isQuotaExceeded(new Error("QUOTA_BYTES quota exceeded"))).toBe(true);
    expect(isQuotaExceeded(new Error("network error"))).toBe(false);
  });
});
