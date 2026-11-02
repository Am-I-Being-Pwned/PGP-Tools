/**
 * Edge behaviour of the shared keyring/contacts store:
 *
 *  - a locked vault reads as EMPTY but can never WRITE (a save of `[]`
 *    over a sealed blob would delete every item);
 *  - the legacy envelope reads; the retired plaintext index does not, and
 *    is never sealed into the vault;
 *  - a location move re-packs rather than byte-copies (sync's 8 KB cap);
 *  - `normalizePadding` never changes a stored item.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { STORAGE_PREFERENCES } from "~/lib/constants";
import {
  copyEncryptedBlobRepacked,
  loadEncryptedArray,
  normalizePadding,
  purgeEncryptedBlob,
  saveEncryptedArray,
  type EncryptedStore,
} from "./encrypted-store";
import { invalidateLocationCache } from "./engine";
import { stubChromeStorage, type FakeArea } from "./fake-area";
import {
  domainEnvelope,
  isDomainSealed,
  legacyEnvelope,
  storedPlaintext,
} from "./fake-store-crypto";
import { splitGeneration } from "./integrity";
import { unpadPlaintext } from "./padding";

const wasmMock = vi.hoisted(() => ({ session: true }));

vi.mock("../pgp/wasm", async () =>
  (await import("./fake-store-crypto")).fakeStoreWasm(() => wasmMock.session),
);

const KEY = "test_store";

interface Item {
  id: string;
}

const store: EncryptedStore<Item> = {
  storageKey: KEY,
  isValid: (v): v is Item =>
    typeof v === "object" &&
    v !== null &&
    typeof (v as Record<string, unknown>).id === "string",
  label: "test store",
};

let local: FakeArea;
let sync: FakeArea;

beforeEach(() => {
  ({ local, sync } = stubChromeStorage());
  wasmMock.session = true;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function setLocation(loc: "local" | "sync") {
  sync.store.set(STORAGE_PREFERENCES, { storageLocation: loc });
  invalidateLocationCache();
}

function json(items: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(items));
}

/** The stored items, without the generation element. */
function itemsIn(blob: unknown): unknown {
  const plaintext = unpadPlaintext(storedPlaintext(blob as never));
  const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as unknown[];
  return splitGeneration(parsed).items;
}

describe("loadEncryptedArray", () => {
  it("reads back what was saved", async () => {
    await saveEncryptedArray(store, [{ id: "a" }, { id: "b" }]);
    expect(await loadEncryptedArray(store)).toEqual([{ id: "a" }, { id: "b" }]);
  });

  it("reads a locked vault as empty rather than throwing", async () => {
    await saveEncryptedArray(store, [{ id: "a" }]);
    wasmMock.session = false;
    expect(await loadEncryptedArray(store)).toEqual([]);
  });

  it("returns empty for an absent blob", async () => {
    expect(await loadEncryptedArray(store)).toEqual([]);
  });

  it("drops items that fail the store's own validator", async () => {
    local.store.set(
      KEY,
      domainEnvelope(KEY, json([{ id: "ok" }, { nope: 1 }, "string", null])),
    );
    expect(await loadEncryptedArray(store)).toEqual([{ id: "ok" }]);
  });

  it("returns empty when the sealed payload is not an array", async () => {
    local.store.set(KEY, domainEnvelope(KEY, json({ id: "not-an-array" })));
    expect(await loadEncryptedArray(store)).toEqual([]);
  });

  it("returns empty for a stored value that is neither envelope nor array", async () => {
    local.store.set(KEY, "garbage");
    expect(await loadEncryptedArray(store)).toEqual([]);
  });

  it("reads a pre-domain-separation envelope", async () => {
    local.store.set(KEY, legacyEnvelope(json([{ id: "old" }])));
    expect(await loadEncryptedArray(store)).toEqual([{ id: "old" }]);
  });

  it("does NOT re-seal a legacy blob on read", async () => {
    // Reads run inside and outside the lock, so they must never write.
    const blob = legacyEnvelope(json([{ id: "old" }]));
    local.store.set(KEY, blob);
    await loadEncryptedArray(store);
    expect(local.store.get(KEY)).toBe(blob);
  });
});

describe("retired plaintext format", () => {
  /** The retired plaintext format: index + one plaintext item per id. */
  function seedPlaintext(ids: string[], items: Record<string, unknown>) {
    local.store.set(KEY, ids);
    for (const [id, item] of Object.entries(items)) {
      local.store.set(`${KEY}:${id}`, item);
    }
  }

  it("reads as an empty store and seals nothing", async () => {
    seedPlaintext(["a", "b"], { a: { id: "a" }, b: { id: "b" } });
    expect(await loadEncryptedArray(store)).toEqual([]);
    expect(local.store.get(KEY)).toEqual(["a", "b"]);
  });

  it("is never sealed by a later write either", async () => {
    seedPlaintext(["a"], { a: { id: "a" } });
    await loadEncryptedArray(store);
    await saveEncryptedArray(store, [{ id: "mine" }]);
    expect(itemsIn(local.store.get(KEY))).toEqual([{ id: "mine" }]);
  });

  it("does not run again after a sealed blob is replaced by an index", async () => {
    // The attack: a real sealed store, swapped for a plaintext index.
    await saveEncryptedArray(store, [{ id: "real" }]);
    seedPlaintext(["evil"], { evil: { id: "evil" } });
    expect(await loadEncryptedArray(store)).toEqual([]);
    expect(local.store.get(KEY)).toEqual(["evil"]);
  });
});

describe("saveEncryptedArray", () => {
  it("refuses to write without a session", async () => {
    // Deliberate asymmetry: a locked read is `[]`, so a locked save would
    // persist `[]` over every item.
    wasmMock.session = false;
    await expect(saveEncryptedArray(store, [{ id: "a" }])).rejects.toThrow(
      /no active contacts session/,
    );
  });

  it("seals under the storage key as its domain", async () => {
    await saveEncryptedArray(store, [{ id: "a" }]);
    expect(isDomainSealed(local.store.get(KEY))).toBe(true);
  });

  it("upgrades a legacy blob on the next write", async () => {
    local.store.set(KEY, legacyEnvelope(json([{ id: "old" }])));
    await saveEncryptedArray(store, [{ id: "new" }]);
    expect(isDomainSealed(local.store.get(KEY))).toBe(true);
  });

  it("pads on local but not on sync", async () => {
    setLocation("local");
    await saveEncryptedArray(store, [{ id: "a" }]);
    const padded = storedPlaintext(local.store.get(KEY) as never);

    setLocation("sync");
    await saveEncryptedArray(store, [{ id: "a" }]);
    const unpadded = storedPlaintext(sync.store.get(KEY) as never);

    // sync's 8 KB/item cap can't absorb length-hiding padding.
    expect(padded.length).toBeGreaterThan(unpadded.length);
  });
});

describe("copyEncryptedBlobRepacked", () => {
  it("does nothing when the source and destination are the same", async () => {
    await copyEncryptedBlobRepacked(KEY, "local", "local");
    expect(local.store.size).toBe(0);
  });

  it("does nothing when the source holds no value", async () => {
    await copyEncryptedBlobRepacked(KEY, "local", "sync");
    expect(sync.store.has(KEY)).toBe(false);
  });

  it("re-packs rather than byte-copying, dropping padding on the way to sync", async () => {
    setLocation("local");
    await saveEncryptedArray(store, [{ id: "a" }]);
    const source = local.store.get(KEY);

    await copyEncryptedBlobRepacked(KEY, "local", "sync");
    const moved = sync.store.get(KEY);

    expect(moved).not.toEqual(source);
    expect(itemsIn(moved)).toEqual([{ id: "a" }]);
    expect(storedPlaintext(moved as never).length).toBeLessThan(
      storedPlaintext(source as never).length,
    );
  });

  it("adds padding on the way to local", async () => {
    setLocation("sync");
    await saveEncryptedArray(store, [{ id: "a" }]);
    await copyEncryptedBlobRepacked(KEY, "sync", "local");

    expect(
      storedPlaintext(local.store.get(KEY) as never).length,
    ).toBeGreaterThan(storedPlaintext(sync.store.get(KEY) as never).length);
  });

  it("upgrades a legacy blob as it crosses", async () => {
    local.store.set(KEY, legacyEnvelope(json([{ id: "old" }])));
    await copyEncryptedBlobRepacked(KEY, "local", "sync");
    expect(isDomainSealed(sync.store.get(KEY))).toBe(true);
    expect(itemsIn(sync.store.get(KEY))).toEqual([{ id: "old" }]);
  });

  it("copies a non-envelope value verbatim so nothing is dropped", async () => {
    // A non-envelope value is moved verbatim, not judged.
    local.store.set(KEY, ["a", "b"]);
    await copyEncryptedBlobRepacked(KEY, "local", "sync");
    expect(sync.store.get(KEY)).toEqual(["a", "b"]);
  });

  it("leaves the source in place for the caller to commit", async () => {
    await saveEncryptedArray(store, [{ id: "a" }]);
    await copyEncryptedBlobRepacked(KEY, "local", "sync");
    expect(local.store.has(KEY)).toBe(true);
  });
});

describe("purgeEncryptedBlob", () => {
  it("removes the blob from one area only", async () => {
    await saveEncryptedArray(store, [{ id: "a" }]);
    await copyEncryptedBlobRepacked(KEY, "local", "sync");

    await purgeEncryptedBlob(KEY, "local");

    expect(local.store.has(KEY)).toBe(false);
    expect(sync.store.has(KEY)).toBe(true);
  });
});

describe("normalizePadding", () => {
  it("upgrades a legacy blob without changing the stored items", async () => {
    const before = [{ id: "a" }, { id: "b" }];
    local.store.set(KEY, legacyEnvelope(json(before)));

    await normalizePadding(store);

    expect(isDomainSealed(local.store.get(KEY))).toBe(true);
    expect(itemsIn(local.store.get(KEY))).toEqual(before);
  });

  it("is a no-op on an already-canonical blob", async () => {
    await saveEncryptedArray(store, [{ id: "a" }]);
    const before = local.store.get(KEY);
    await normalizePadding(store);
    // Idempotent: no rewrite, so not even a fresh IV.
    expect(local.store.get(KEY)).toEqual(before);
  });

  it("does nothing without a session", async () => {
    local.store.set(KEY, legacyEnvelope(json([{ id: "a" }])));
    const before = local.store.get(KEY);
    wasmMock.session = false;
    await normalizePadding(store);
    expect(local.store.get(KEY)).toBe(before);
  });

  it("does nothing for an absent or non-envelope value", async () => {
    await normalizePadding(store);
    expect(local.store.has(KEY)).toBe(false);

    local.store.set(KEY, ["a"]);
    await normalizePadding(store);
    expect(local.store.get(KEY)).toEqual(["a"]);
  });
});
