/**
 * Domain separation and legacy-blob migration for the stores that share
 * `encrypted-store.ts` -- the keyring, the public contacts list, and the
 * CRX signing keys.
 *
 * The property under test is the one history's e2e substitution test
 * asserts at the UI level, checked here per-store: a blob is bound to the
 * storage key it was written to, so it cannot be replayed into another
 * slot or another store. Plus the migration that makes changing the
 * binding safe for existing installs -- losing a user's keyring would be
 * far worse than the integrity gap being closed, so every legacy path has
 * a test.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { EncryptedStore } from "./encrypted-store";
import { STORAGE_CONTACTS, STORAGE_KEYRING } from "../constants";
import {
  copyEncryptedBlobRepacked,
  loadEncryptedArray,
  normalizePadding,
  saveEncryptedArray,
} from "./encrypted-store";
import { invalidateLocationCache } from "./engine";
import {
  domainEnvelope,
  isDomainSealed,
  legacyEnvelope,
  sealedDomain,
  storedPlaintext,
} from "./fake-store-crypto";
import { padPlaintext, unpadPlaintext } from "./padding";

const wasmMock = vi.hoisted(() => ({ session: true }));

vi.mock("../pgp/wasm", async () => {
  const fake = await import("./fake-store-crypto");
  return {
    hasContactsSession: () => Promise.resolve(wasmMock.session),
    encryptStore: (domain: string, plaintext: Uint8Array) =>
      Promise.resolve(fake.fakeEncryptStore(domain, plaintext)),
    decryptStore: (domain: string, ciphertext: Uint8Array) =>
      Promise.resolve(fake.fakeDecryptStore(domain, ciphertext)),
    encryptContacts: (plaintext: Uint8Array) =>
      Promise.resolve(fake.fakeEncryptContacts(plaintext)),
    decryptContacts: (ciphertext: Uint8Array) =>
      Promise.resolve(fake.fakeDecryptContacts(ciphertext)),
  };
});

/** In-memory browser.storage area (same shape as history.test.ts). */
function fakeArea() {
  const store = new Map<string, unknown>();
  return {
    store,
    get: (keys?: string | string[] | null) => {
      if (keys == null) return Promise.resolve(Object.fromEntries(store));
      const list = Array.isArray(keys) ? keys : [keys];
      const out: Record<string, unknown> = {};
      for (const k of list) if (store.has(k)) out[k] = store.get(k);
      return Promise.resolve(out);
    },
    set: (items: Record<string, unknown>) => {
      for (const [k, v] of Object.entries(items)) store.set(k, v);
      return Promise.resolve();
    },
    remove: (keys: string | string[]) => {
      const list = Array.isArray(keys) ? keys : [keys];
      for (const k of list) store.delete(k);
      return Promise.resolve();
    },
  };
}

let local: ReturnType<typeof fakeArea>;
let sync: ReturnType<typeof fakeArea>;

beforeEach(() => {
  local = fakeArea();
  sync = fakeArea();
  vi.stubGlobal("browser", { storage: { local, sync } });
  wasmMock.session = true;
  invalidateLocationCache();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

interface Item {
  id: string;
  label: string;
}

function isItem(v: unknown): v is Item {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return typeof o.id === "string" && typeof o.label === "string";
}

const KEYRING: EncryptedStore<Item> = {
  storageKey: STORAGE_KEYRING,
  isValid: isItem,
  label: "keyring",
};

const CONTACTS: EncryptedStore<Item> = {
  storageKey: STORAGE_CONTACTS,
  isValid: isItem,
  label: "contacts",
};

const KEYS: Item[] = [
  { id: "AAAA1111", label: "my signing key" },
  { id: "BBBB2222", label: "my backup key" },
];

/** A blob exactly as a pre-domain-separation build wrote it: padded JSON
 *  under the shared key + shared AAD. */
function seedLegacy(store: EncryptedStore<Item>, items: Item[]): void {
  const json = new TextEncoder().encode(JSON.stringify(items));
  local.store.set(store.storageKey, legacyEnvelope(padPlaintext(json, true)));
}

describe("domain binding", () => {
  it("seals each store for its own storage key", async () => {
    await saveEncryptedArray(KEYRING, KEYS);
    await saveEncryptedArray(CONTACTS, [{ id: "CCCC", label: "alice" }]);

    expect(sealedDomain(local.store.get(STORAGE_KEYRING))).toBe(
      STORAGE_KEYRING,
    );
    expect(sealedDomain(local.store.get(STORAGE_CONTACTS))).toBe(
      STORAGE_CONTACTS,
    );
  });

  it("refuses the keyring blob when it is planted on the contacts key", async () => {
    await saveEncryptedArray(KEYRING, KEYS);
    // Positive control: the contacts store works normally first, so the
    // rejection below cannot be a store that never loaded at all.
    await saveEncryptedArray(CONTACTS, [{ id: "CCCC", label: "alice" }]);
    await expect(loadEncryptedArray(CONTACTS)).resolves.toHaveLength(1);

    // The substitution: byte-for-byte copy, no vault key needed.
    local.store.set(STORAGE_CONTACTS, local.store.get(STORAGE_KEYRING));

    // A failed tag check is a load error, NOT a silently empty list -- the
    // old behaviour returned [] and the UI could not tell the difference.
    await expect(loadEncryptedArray(CONTACTS)).rejects.toThrow();
    // The real keyring is untouched in its own slot.
    await expect(loadEncryptedArray(KEYRING)).resolves.toEqual(KEYS);
  });

  it("refuses a history segment blob planted on a store key", async () => {
    const planted = new TextEncoder().encode(
      JSON.stringify([{ id: "x", ts: 1, op: "encrypt", recipients: [] }]),
    );
    local.store.set(
      STORAGE_CONTACTS,
      domainEnvelope("pgp_history_seg_0", planted),
    );

    await expect(loadEncryptedArray(CONTACTS)).rejects.toThrow();
  });
});

describe("legacy envelope migration", () => {
  it("still loads a blob sealed by a shipped older build", async () => {
    seedLegacy(KEYRING, KEYS);
    await expect(loadEncryptedArray(KEYRING)).resolves.toEqual(KEYS);
  });

  it("does not write from the read path", async () => {
    seedLegacy(KEYRING, KEYS);
    const before = local.store.get(STORAGE_KEYRING);

    await loadEncryptedArray(KEYRING);

    // loadEncryptedArray runs both inside and outside the store's lock, so
    // it must never write -- an upgrade here could clobber a concurrent
    // mutation or deadlock. normalizePadding owns the eager upgrade.
    expect(local.store.get(STORAGE_KEYRING)).toBe(before);
  });

  it("upgrades on the next mutation, keeping every item", async () => {
    seedLegacy(KEYRING, KEYS);

    const items = await loadEncryptedArray(KEYRING);
    await saveEncryptedArray(KEYRING, [...items, { id: "CCCC", label: "new" }]);

    expect(sealedDomain(local.store.get(STORAGE_KEYRING))).toBe(
      STORAGE_KEYRING,
    );
    await expect(loadEncryptedArray(KEYRING)).resolves.toEqual([
      ...KEYS,
      { id: "CCCC", label: "new" },
    ]);
  });

  it("normalizePadding upgrades a store that is only ever read", async () => {
    seedLegacy(KEYRING, KEYS);
    // Already canonically padded, so the padding check alone would skip it:
    // this is the regression guard for "legacy envelope + canonical padding
    // never migrates".
    const stored = storedPlaintext(local.store.get(STORAGE_KEYRING) as never);
    expect(padPlaintext(unpadPlaintext(stored), true).length).toBe(
      stored.length,
    );

    await normalizePadding(KEYRING);

    expect(sealedDomain(local.store.get(STORAGE_KEYRING))).toBe(
      STORAGE_KEYRING,
    );
    await expect(loadEncryptedArray(KEYRING)).resolves.toEqual(KEYS);
  });

  it("normalizePadding is idempotent once the blob is domain-sealed", async () => {
    await saveEncryptedArray(KEYRING, KEYS);
    const before = local.store.get(STORAGE_KEYRING);

    await normalizePadding(KEYRING);

    expect(local.store.get(STORAGE_KEYRING)).toBe(before);
  });

  it("a migrated blob is no longer substitutable across stores", async () => {
    seedLegacy(KEYRING, KEYS);
    await normalizePadding(KEYRING);

    local.store.set(STORAGE_CONTACTS, local.store.get(STORAGE_KEYRING));
    await expect(loadEncryptedArray(CONTACTS)).rejects.toThrow();
  });

  it("leaves the legacy blob readable if the upgrade write fails", async () => {
    seedLegacy(KEYRING, KEYS);
    const before = local.store.get(STORAGE_KEYRING);
    local.set = () => Promise.reject(new Error("quota exceeded"));

    await expect(normalizePadding(KEYRING)).rejects.toThrow(/quota/);

    expect(local.store.get(STORAGE_KEYRING)).toBe(before);
    local.set = fakeArea().set;
    await expect(loadEncryptedArray(KEYRING)).resolves.toEqual(KEYS);
  });
});

describe("moving a blob between storage areas", () => {
  it("re-seals for the same domain, so the move survives", async () => {
    await saveEncryptedArray(KEYRING, KEYS);

    await copyEncryptedBlobRepacked(STORAGE_KEYRING, "local", "sync");

    // Same domain on both sides (the domain is the KEY, not the area), so
    // the destination copy still opens.
    expect(sealedDomain(sync.store.get(STORAGE_KEYRING))).toBe(STORAGE_KEYRING);
    sync.store.set("pgp_preferences", { storageLocation: "sync" });
    local.store.delete(STORAGE_KEYRING);
    invalidateLocationCache();
    await expect(loadEncryptedArray(KEYRING)).resolves.toEqual(KEYS);
  });

  it("upgrades a legacy blob on the way across", async () => {
    seedLegacy(KEYRING, KEYS);
    expect(isDomainSealed(local.store.get(STORAGE_KEYRING))).toBe(false);

    await copyEncryptedBlobRepacked(STORAGE_KEYRING, "local", "sync");

    expect(sealedDomain(sync.store.get(STORAGE_KEYRING))).toBe(STORAGE_KEYRING);
  });
});
