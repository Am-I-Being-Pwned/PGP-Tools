/**
 * The shared load/save behind the keyring and contacts stores.
 *
 * `contacts.test.ts` exercises this module incidentally, through one
 * store on the happy path. What is pinned HERE is the behaviour that
 * only shows up at the edges, and that a caller would otherwise discover
 * the hard way:
 *
 *  - a locked vault reads as an EMPTY store, never as an error, and a
 *    locked vault must not be able to WRITE one (the asymmetry is the
 *    whole safety property: an unguarded save of `[]` over a sealed blob
 *    is indistinguishable from deleting every key);
 *  - the two legacy formats are read transparently, and the plaintext
 *    one is cleaned up as it migrates rather than left behind as a
 *    second, unencrypted copy of the same data;
 *  - a location move re-packs rather than byte-copies, because `local`
 *    padding does not fit `sync`'s 8 KB/item cap;
 *  - `normalizePadding` upgrades a legacy blob WITHOUT changing a single
 *    stored item.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { EncryptedStore } from "./encrypted-store";
import { STORAGE_PREFERENCES } from "../constants";
import {
  copyEncryptedBlobRepacked,
  loadEncryptedArray,
  normalizePadding,
  purgeEncryptedBlob,
  saveEncryptedArray,
} from "./encrypted-store";
import { invalidateLocationCache } from "./engine";
import { fakeArea } from "./fake-area";
import {
  domainEnvelope,
  fakeDecryptContacts,
  fakeDecryptStore,
  fakeEncryptContacts,
  fakeEncryptStore,
  isDomainSealed,
  legacyEnvelope,
  storedPlaintext,
} from "./fake-store-crypto";
import { unpadPlaintext } from "./padding";

const wasmMock = vi.hoisted(() => ({ session: true }));

vi.mock("../pgp/wasm", () => ({
  hasContactsSession: () => Promise.resolve(wasmMock.session),
  encryptStore: (domain: string, plaintext: Uint8Array) =>
    Promise.resolve(fakeEncryptStore(domain, plaintext)),
  decryptStore: (domain: string, ciphertext: Uint8Array) =>
    Promise.resolve(fakeDecryptStore(domain, ciphertext)),
  encryptContacts: (plaintext: Uint8Array) =>
    Promise.resolve(fakeEncryptContacts(plaintext)),
  decryptContacts: (ciphertext: Uint8Array) =>
    Promise.resolve(fakeDecryptContacts(ciphertext)),
}));

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

let local: ReturnType<typeof fakeArea>;
let sync: ReturnType<typeof fakeArea>;

beforeEach(() => {
  local = fakeArea();
  sync = fakeArea();
  vi.stubGlobal("chrome", { storage: { local, sync } });
  wasmMock.session = true;
  invalidateLocationCache();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** Point the engine at an area, the way a real profile's preferences do. */
function setLocation(loc: "local" | "sync") {
  sync.store.set(STORAGE_PREFERENCES, { storageLocation: loc });
  invalidateLocationCache();
}

function json(items: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(items));
}

function itemsIn(blob: unknown): unknown {
  const plaintext = unpadPlaintext(storedPlaintext(blob as never));
  return JSON.parse(new TextDecoder().decode(plaintext));
}

describe("loadEncryptedArray", () => {
  it("reads back what was saved", async () => {
    await saveEncryptedArray(store, [{ id: "a" }, { id: "b" }]);
    expect(await loadEncryptedArray(store)).toEqual([{ id: "a" }, { id: "b" }]);
  });

  it("reads a locked vault as empty rather than throwing", async () => {
    await saveEncryptedArray(store, [{ id: "a" }]);
    wasmMock.session = false;
    // A caller rendering a key list must get "nothing to show", not an
    // error boundary, when the vault happens to be locked.
    expect(await loadEncryptedArray(store)).toEqual([]);
  });

  it("returns empty for an absent blob", async () => {
    expect(await loadEncryptedArray(store)).toEqual([]);
  });

  it("drops items that fail the store's own validator", async () => {
    // A blob hand-edited, or written by a build with a wider schema:
    // the store is the last line of defence before these reach the UI.
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
    // Reads run both inside and outside the store's lock, so writing
    // here could deadlock or clobber a concurrent mutation. The upgrade
    // belongs to saveEncryptedArray / normalizePadding.
    const blob = legacyEnvelope(json([{ id: "old" }]));
    local.store.set(KEY, blob);
    await loadEncryptedArray(store);
    expect(local.store.get(KEY)).toBe(blob);
  });
});

describe("legacy plaintext migration", () => {
  /** The original format: a `string[]` index plus one plaintext item per id. */
  function seedPlaintext(ids: string[], items: Record<string, unknown>) {
    local.store.set(KEY, ids);
    for (const [id, item] of Object.entries(items)) {
      local.store.set(`${KEY}:${id}`, item);
    }
  }

  it("migrates plaintext items into a sealed blob and returns them", async () => {
    seedPlaintext(["a", "b"], { a: { id: "a" }, b: { id: "b" } });
    expect(await loadEncryptedArray(store)).toEqual([{ id: "a" }, { id: "b" }]);
    expect(isDomainSealed(local.store.get(KEY))).toBe(true);
  });

  it("removes the plaintext per-item keys it migrated", async () => {
    // The point of the migration is that the data stops being readable
    // without a session. Leaving the originals would defeat it entirely.
    seedPlaintext(["a"], { a: { id: "a" } });
    await loadEncryptedArray(store);
    expect(local.store.has(`${KEY}:a`)).toBe(false);
  });

  it("skips non-string ids and invalid items", async () => {
    local.store.set(KEY, ["a", 42, { bad: true }]);
    local.store.set(`${KEY}:a`, { id: "a" });
    expect(await loadEncryptedArray(store)).toEqual([{ id: "a" }]);
  });

  it("clears the index when nothing valid survives", async () => {
    seedPlaintext(["a"], { a: { junk: true } });
    expect(await loadEncryptedArray(store)).toEqual([]);
    expect(local.store.has(KEY)).toBe(false);
    expect(local.store.has(`${KEY}:a`)).toBe(false);
  });
});

describe("saveEncryptedArray", () => {
  it("refuses to write without a session", async () => {
    // The asymmetry with the read path is deliberate: a locked-vault
    // read is `[]`, so a save allowed to proceed would persist `[]` over
    // the sealed blob and destroy every item.
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
    // A not-yet-migrated legacy plaintext index must survive the move,
    // or the migration on the far side finds nothing to migrate.
    local.store.set(KEY, ["a", "b"]);
    await copyEncryptedBlobRepacked(KEY, "local", "sync");
    expect(sync.store.get(KEY)).toEqual(["a", "b"]);
  });

  it("leaves the source in place for the caller to commit", async () => {
    await saveEncryptedArray(store, [{ id: "a" }]);
    await copyEncryptedBlobRepacked(KEY, "local", "sync");
    // A crash before the location switch must leave reads working.
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

  it("does nothing for an absent or legacy-plaintext value", async () => {
    await normalizePadding(store);
    expect(local.store.has(KEY)).toBe(false);

    local.store.set(KEY, ["a"]);
    await normalizePadding(store);
    expect(local.store.get(KEY)).toEqual(["a"]);
  });
});
