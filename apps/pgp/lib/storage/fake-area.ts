/**
 * TEST-ONLY in-memory stand-in for a `chrome.storage` area. Imported
 * exclusively from `*.test.ts`, so it is tree-shaken out of the bundle.
 *
 * It lives here as one shared module for the same reason as
 * `fake-store-crypto.ts`: five suites had grown their own byte-identical
 * copy, and a storage fake that drifts between files can let a store
 * "pass" against semantics the real area does not have.
 *
 * `perItemCap` models `sync`'s 8 KB/item quota -- exceeding it rejects
 * with the same message Chrome uses, which is what `chunked.ts` splits
 * blobs to avoid. The default of `Infinity` makes the fake behave as an
 * unbounded `local` area.
 */

import type { StorageArea } from "./chunked";

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
