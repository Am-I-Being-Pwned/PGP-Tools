/**
 * TEST-ONLY in-memory `chrome.storage` area, shared so semantics can't
 * drift between suites. `perItemCap` models sync's 8 KB/item quota with
 * Chrome's error message; default `Infinity` behaves like `local`.
 */

import { vi } from "vitest";

import type { StorageArea } from "~/lib/storage/chunked";
import { invalidateLocationCache } from "~/lib/storage/engine";

export type FakeArea = StorageArea & {
  /** The backing map, for direct seeding and assertions. */
  store: Map<string, unknown>;
};

export function fakeArea(perItemCap = Infinity): FakeArea {
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
  return area as FakeArea;
}

/** Stub `chrome` with `local`/`sync` areas plus `extra`, and drop the
 *  engine's cached location. Pair with `vi.unstubAllGlobals()`. */
export function stubChromeStorage(
  areas: { local?: FakeArea; sync?: FakeArea } = {},
  extra: Record<string, unknown> = {},
): { local: FakeArea; sync: FakeArea } {
  const local = areas.local ?? fakeArea();
  const sync = areas.sync ?? fakeArea();
  vi.stubGlobal("chrome", { storage: { local, sync }, ...extra });
  invalidateLocationCache();
  return { local, sync };
}
