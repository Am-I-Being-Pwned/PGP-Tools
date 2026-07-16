import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { NewHistoryEntry } from "./history";
import {
  appendHistoryEntry,
  clearHistory,
  CONTENT_CAP,
  FILES_CAP,
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

/** Make the area's set() reject like Chrome's quota error from the
 *  `nth` call onward (1-based). Gets/removes keep working, mirroring a
 *  full-but-readable chrome.storage.local. */
function failSetFrom(area: ReturnType<typeof fakeArea>, nth: number): void {
  const original = area.set;
  let calls = 0;
  area.set = (items: Record<string, unknown>) => {
    calls++;
    if (calls >= nth) {
      return Promise.reject(new Error("Resource::kQuotaBytes quota exceeded"));
    }
    return original(items);
  };
}

describe("quota exhaustion mid-append", () => {
  it("rejects and leaves storage untouched when the segment write fails", async () => {
    failSetFrom(local, 1);

    await expect(appendHistoryEntry(entry("doomed"))).rejects.toThrow(/quota/i);
    // Nothing persisted: no manifest, no segment, no orphan.
    expect(historyKeys(local.store)).toEqual([]);
  });

  it("removes the orphaned new segment when the manifest write fails", async () => {
    // Seal segment 0 (>= 64KB after 3 x ~30KB entries) so the next
    // append must create segment 1.
    for (let i = 0; i < 3; i++) {
      await appendHistoryEntry(entry(`${i}:${"x".repeat(30_000)}`));
    }
    expect(local.store.has("pgp_history_seg_1")).toBe(false);

    // Within the next append: set #1 = segment 1 write (succeeds),
    // set #2 = manifest write (quota-fails).
    failSetFrom(local, 2);
    await expect(appendHistoryEntry(entry("lost"))).rejects.toThrow(/quota/i);

    // The freshly written segment was cleaned up, so the store matches
    // the manifest that is actually persisted.
    expect(local.store.has("pgp_history_seg_1")).toBe(false);
    const h = await loadHistory();
    expect(h).toHaveLength(3);
    expect(h.some((e) => e.content === "lost")).toBe(false);
  });

  it("keeps an existing head readable when only the manifest write fails", async () => {
    await appendHistoryEntry(entry("first"));

    // Segment 0 is rewritten in place (set #1 succeeds); the manifest
    // update (set #2) quota-fails. The entry is in the segment and the
    // stale manifest still references it, so nothing is lost.
    failSetFrom(local, 2);
    await expect(appendHistoryEntry(entry("second"))).rejects.toThrow(
      /quota/i,
    );

    const h = await loadHistory();
    expect(h.map((e) => e.content)).toEqual(["second", "first"]);
  });

  it("recordHistory reports failed on quota, saved on success, skipped when locked", async () => {
    await expect(recordHistory(entry("ok"))).resolves.toBe("saved");

    failSetFrom(local, 1);
    await expect(recordHistory(entry("full"))).resolves.toBe("failed");

    wasmMock.session = false;
    await expect(recordHistory(entry("locked"))).resolves.toBe("skipped");
  });

  it("recordHistory reports skipped when capture is disabled", async () => {
    prefsMock.historyEnabled = false;
    await expect(recordHistory(entry("off"))).resolves.toBe("skipped");
  });
});

describe("cross-context manifest divergence", () => {
  it("loadHistory recovers entries from segments the manifest lost", async () => {
    await appendHistoryEntry(entry("kept-1"));
    await appendHistoryEntry(entry("kept-2"));

    // Another context's racing manifest write clobbered ours: the
    // manifest no longer references segment 0, but the blob exists.
    await local.set({ pgp_history: { segs: [] } });
    expect(await historyByteSize()).toBe(0);

    const h = await loadHistory();
    expect(h.map((e) => e.content)).toEqual(["kept-2", "kept-1"]);
    // The stray segment was adopted back into the manifest...
    expect(await historyByteSize()).toBeGreaterThan(0);
    // ...so the next append extends it instead of clobbering it.
    await appendHistoryEntry(entry("kept-3"));
    const after = await loadHistory();
    expect(after.map((e) => e.content)).toEqual([
      "kept-3",
      "kept-2",
      "kept-1",
    ]);
  });

  it("clearHistory removes segments the manifest doesn't reference", async () => {
    await appendHistoryEntry(entry("orphan-to-be"));
    await local.set({ pgp_history: { segs: [] } });

    await clearHistory();
    expect(historyKeys(local.store)).toEqual([]);
  });
});

describe("file metadata edge cases", () => {
  it("caps a huge files[] list at FILES_CAP and flags truncation", async () => {
    const files = Array.from({ length: 1000 }, (_, i) => ({
      name: `report-${i}.pdf`,
      size: i,
    }));
    await appendHistoryEntry({ op: "encrypt", recipients: [], files });

    const [e] = await loadHistory();
    expect(e.files).toHaveLength(FILES_CAP);
    expect(e.files?.[0]).toEqual({ name: "report-0.pdf", size: 0 });
    expect(e.truncated).toBe(true);
  });

  it("caps absurdly long filenames but keeps normal ones verbatim", async () => {
    await appendHistoryEntry({
      op: "sign",
      recipients: [],
      files: [
        { name: "a".repeat(5000) + ".bin", size: 1 },
        { name: "normal.txt", size: 2 },
      ],
    });

    const [e] = await loadHistory();
    expect(e.files?.[0].name).toHaveLength(256);
    expect(e.files?.[1].name).toBe("normal.txt");
    expect(e.truncated).toBe(true);
  });

  it("round-trips zero-byte files and hostile filenames untouched", async () => {
    const files = [
      { name: "", size: 0 },
      { name: "emoji-🚀🔐.txt", size: 0 },
      { name: "rtl-‮txt.gpg", size: 12 },
      { name: "ctrl- .dat", size: 3 },
      { name: "dupe.txt", size: 1 },
      { name: "dupe.txt", size: 2 },
    ];
    await appendHistoryEntry({ op: "encrypt", recipients: [], files });

    const [e] = await loadHistory();
    expect(e.files).toEqual(files);
    expect(e.truncated).toBeUndefined();
  });

  it("keeps files and content together when both are captured", async () => {
    await appendHistoryEntry({
      op: "sign",
      recipients: [],
      signed: true,
      content: "signed zip manifest",
      files: [{ name: "bundle.zip", size: 4096 }],
    });

    const [e] = await loadHistory();
    expect(e.content).toBe("signed zip manifest");
    expect(e.files).toEqual([{ name: "bundle.zip", size: 4096 }]);
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
