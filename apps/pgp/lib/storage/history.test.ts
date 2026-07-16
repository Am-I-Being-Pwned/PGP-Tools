import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { NewHistoryEntry } from "./history";
import {
  appendHistoryEntry,
  clearHistory,
  CONTENT_CAP,
  historyByteSize,
  loadHistory,
  recordHistory,
  requestUnlimitedHistoryStorage,
  resolveBudget,
} from "./history";

// Fake WASM contacts session: "encryption" packs a zero IV in front of
// the plaintext, "decryption" strips it. Call counters let tests prove
// the module keeps no plaintext cache (every load must decrypt anew).
const wasmMock = vi.hoisted(() => ({
  session: true,
  encryptCalls: 0,
  decryptCalls: 0,
}));

vi.mock("../pgp/wasm", () => ({
  hasContactsSession: () => Promise.resolve(wasmMock.session),
  encryptContacts: (plaintext: Uint8Array) => {
    wasmMock.encryptCalls++;
    const packed = new Uint8Array(12 + plaintext.length);
    packed.set(plaintext, 12);
    return Promise.resolve(packed);
  },
  decryptContacts: (ciphertext: Uint8Array) => {
    wasmMock.decryptCalls++;
    return Promise.resolve(new Uint8Array(ciphertext));
  },
}));

const prefsMock = vi.hoisted(() => ({
  historyEnabled: true,
  neverCacheKeys: false,
}));

vi.mock("./preferences", () => ({
  getPreferences: () => Promise.resolve({ ...prefsMock }),
}));

/** In-memory chrome.storage area (same shape as chunked.test.ts). */
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
let permissions: {
  contains: ReturnType<typeof vi.fn>;
  request: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
  local = fakeArea();
  sync = fakeArea();
  permissions = {
    contains: vi.fn().mockResolvedValue(false),
    request: vi.fn().mockResolvedValue(false),
  };
  vi.stubGlobal("chrome", { storage: { local, sync }, permissions });
  wasmMock.session = true;
  wasmMock.encryptCalls = 0;
  wasmMock.decryptCalls = 0;
  prefsMock.historyEnabled = true;
  prefsMock.neverCacheKeys = false;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function entry(content?: string): NewHistoryEntry {
  return {
    op: "encrypt",
    recipients: [{ fingerprint: "ABCD1234", name: "Alice" }],
    signed: false,
    ...(content !== undefined ? { content } : {}),
  };
}

function historyKeys(store: Map<string, unknown>): string[] {
  return [...store.keys()].filter((k) => k.startsWith("pgp_history"));
}

describe("append / load", () => {
  it("appends and returns entries newest first with id and ts", async () => {
    await appendHistoryEntry(entry("one"));
    await appendHistoryEntry(entry("two"));

    const h = await loadHistory();
    expect(h.map((e) => e.content)).toEqual(["two", "one"]);
    expect(h[0].id).toBeTruthy();
    expect(h[0].ts).toBeGreaterThan(0);
    expect(local.store.has("pgp_history")).toBe(true);
    expect(local.store.has("pgp_history_seg_0")).toBe(true);
  });

  it("seals the head segment at ~64KB and keeps newest-first across segments", async () => {
    // ~30KB per entry: seg 0 seals after 3 entries (>= 64KB), so the 4th
    // starts seg 1.
    for (let i = 0; i < 4; i++) {
      await appendHistoryEntry(entry(`${i}:${"x".repeat(30_000)}`));
    }
    expect(local.store.has("pgp_history_seg_0")).toBe(true);
    expect(local.store.has("pgp_history_seg_1")).toBe(true);

    const h = await loadHistory();
    expect(h).toHaveLength(4);
    expect(h.map((e) => e.content?.slice(0, 2))).toEqual([
      "3:",
      "2:",
      "1:",
      "0:",
    ]);
  });

  it("caps content at CONTENT_CAP and flags truncation", async () => {
    await appendHistoryEntry(entry("y".repeat(CONTENT_CAP + 5000)));
    await appendHistoryEntry(entry("z".repeat(100)));

    const [small, big] = await loadHistory();
    expect(big.content).toHaveLength(CONTENT_CAP);
    expect(big.truncated).toBe(true);
    expect(small.content).toHaveLength(100);
    expect(small.truncated).toBeUndefined();
  });

  it("strips content from decrypt/verify entries (metadata only)", async () => {
    await appendHistoryEntry({
      op: "decrypt",
      recipients: [],
      content: "secret plaintext",
      files: [{ name: "a.gpg", size: 10 }],
    });
    await appendHistoryEntry({
      op: "verify",
      recipients: [],
      content: "signed message",
    });

    const [verify, decrypt] = await loadHistory();
    expect(verify.content).toBeUndefined();
    expect(decrypt.content).toBeUndefined();
    expect(decrypt.files).toEqual([{ name: "a.gpg", size: 10 }]);
  });

  it("writes to chrome.storage.local even when storageLocation is sync", async () => {
    await sync.set({ pgp_preferences: { storageLocation: "sync" } });

    await appendHistoryEntry(entry("hello"));

    expect(historyKeys(local.store).length).toBeGreaterThan(0);
    expect(historyKeys(sync.store)).toEqual([]);
  });

  it("clearHistory removes the manifest and every segment", async () => {
    for (let i = 0; i < 4; i++) {
      await appendHistoryEntry(entry(`${i}:${"x".repeat(30_000)}`));
    }
    await clearHistory();
    expect(historyKeys(local.store)).toEqual([]);
    expect(await loadHistory()).toEqual([]);
    expect(await historyByteSize()).toBe(0);
  });
});

describe("locked behavior", () => {
  it("drops appends and loads empty when the session is gone", async () => {
    wasmMock.session = false;

    await appendHistoryEntry(entry("nope"));
    expect(historyKeys(local.store)).toEqual([]);
    expect(await loadHistory()).toEqual([]);
  });

  // RAM-after-lock guarantee: the module keeps no plaintext cache, so
  // after dropContactsSession nothing decrypted remains reachable. Proven
  // behaviorally: every load must decrypt from storage (a cache would skip
  // the second decrypt), and once locked no decryption happens at all.
  // The view-level counterpart (component state) is covered by mounting
  // HistoryPage inside the masterUnlocked-gated tree, which unmounts on
  // lock -- documented in HistoryPage.tsx; no React test lib is installed.
  it("retains no plaintext after lock: every load re-decrypts, none after", async () => {
    await appendHistoryEntry(entry("sensitive"));

    const before = wasmMock.decryptCalls;
    await loadHistory();
    const afterFirst = wasmMock.decryptCalls;
    expect(afterFirst).toBeGreaterThan(before);

    await loadHistory();
    expect(wasmMock.decryptCalls).toBeGreaterThan(afterFirst);

    wasmMock.session = false; // dropContactsSession happened
    const locked = wasmMock.decryptCalls;
    expect(await loadHistory()).toEqual([]);
    expect(wasmMock.decryptCalls).toBe(locked);
  });
});

describe("capture gating (recordHistory)", () => {
  it("skips capture when historyEnabled is false", async () => {
    prefsMock.historyEnabled = false;
    await recordHistory(entry("x"));
    expect(historyKeys(local.store)).toEqual([]);
  });

  it("skips capture when neverCacheKeys is true", async () => {
    prefsMock.neverCacheKeys = true;
    await recordHistory(entry("x"));
    expect(historyKeys(local.store)).toEqual([]);
  });

  it("captures when enabled and not in never-cache mode", async () => {
    await recordHistory(entry("x"));
    expect(await loadHistory()).toHaveLength(1);
  });
});

describe("byte budget", () => {
  it("resolveBudget picks the tier from the permission state", () => {
    expect(resolveBudget(false)).toBe(2 * 1024 * 1024);
    expect(resolveBudget(true)).toBe(50 * 1024 * 1024);
  });

  it("prunes oldest segments beyond the default budget on append", async () => {
    // ~2.5MB of entries against the 2MB budget (permission denied).
    for (let i = 0; i < 84; i++) {
      await appendHistoryEntry(entry(`${i}:${"x".repeat(30_000)}`));
    }
    expect(await historyByteSize()).toBeLessThanOrEqual(2 * 1024 * 1024);

    const h = await loadHistory();
    // Newest survives, oldest was pruned with its segment.
    expect(h[0].content?.startsWith("83:")).toBe(true);
    expect(h.some((e) => e.content?.startsWith("0:"))).toBe(false);
    // Pruned segment keys are gone from storage.
    expect(local.store.has("pgp_history_seg_0")).toBe(false);
  });

  it("keeps a granted (unlimited) store, then prunes down after revocation", async () => {
    permissions.contains.mockResolvedValue(true);
    for (let i = 0; i < 84; i++) {
      await appendHistoryEntry(entry(`${i}:${"x".repeat(30_000)}`));
    }
    const grantedSize = await historyByteSize();
    expect(grantedSize).toBeGreaterThan(2 * 1024 * 1024);

    // Permission revoked from chrome://extensions -- next load prunes.
    permissions.contains.mockResolvedValue(false);
    const h = await loadHistory();
    expect(await historyByteSize()).toBeLessThanOrEqual(2 * 1024 * 1024);
    expect(h[0].content?.startsWith("83:")).toBe(true);
    expect(h.some((e) => e.content?.startsWith("0:"))).toBe(false);
  });
});

describe("requestUnlimitedHistoryStorage", () => {
  it("returns true without prompting when already granted", async () => {
    permissions.contains.mockResolvedValue(true);
    await expect(requestUnlimitedHistoryStorage()).resolves.toBe(true);
    expect(permissions.request).not.toHaveBeenCalled();
  });

  it("prompts exactly once and reports the outcome", async () => {
    permissions.request.mockResolvedValue(true);
    await expect(requestUnlimitedHistoryStorage()).resolves.toBe(true);
    expect(permissions.request).toHaveBeenCalledTimes(1);
    expect(permissions.request).toHaveBeenCalledWith({
      permissions: ["unlimitedStorage"],
    });
  });

  it("treats a rejecting request API as not granted", async () => {
    permissions.request.mockRejectedValue(new Error("needs user gesture"));
    await expect(requestUnlimitedHistoryStorage()).resolves.toBe(false);
  });

  it("treats a missing permissions API as not granted (Firefox-safe)", async () => {
    vi.stubGlobal("chrome", { storage: { local, sync } });
    await expect(requestUnlimitedHistoryStorage()).resolves.toBe(false);
    // The budget also falls back to the conservative tier.
    await appendHistoryEntry(entry("still works"));
    expect(await loadHistory()).toHaveLength(1);
  });
});
