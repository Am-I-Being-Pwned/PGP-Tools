import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { StoredEnvelope } from "~/lib/storage/envelope";
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
  type NewHistoryEntry,
} from "~/lib/storage/history";
import { stubChromeStorage, type FakeArea } from "./fake-area";
import {
  domainEnvelope,
  isDomainSealed,
  legacyEnvelope,
  sealedDomain,
  storedPlaintext,
} from "./fake-store-crypto";

// Fake WASM sealing (see fake-store-crypto.ts). Call counters prove there
// is no plaintext cache; `sealed`/`opened` keep the ACTUAL buffers so
// tests can assert they were zeroized.
const wasmMock = vi.hoisted(() => ({
  session: true,
  encryptCalls: 0,
  decryptCalls: 0,
  sealed: [] as Uint8Array[],
  opened: [] as Uint8Array[],
}));

vi.mock("~/lib/pgp/wasm", async () => {
  const fake = await import("./fake-store-crypto");
  return {
    hasContactsSession: () => Promise.resolve(wasmMock.session),
    encryptStore: (domain: string, plaintext: Uint8Array) => {
      wasmMock.encryptCalls++;
      wasmMock.sealed.push(plaintext);
      return Promise.resolve(fake.fakeEncryptStore(domain, plaintext));
    },
    decryptStore: (domain: string, ciphertext: Uint8Array) => {
      wasmMock.decryptCalls++;
      const out = fake.fakeDecryptStore(domain, ciphertext);
      wasmMock.opened.push(out);
      return Promise.resolve(out);
    },
    encryptContacts: (plaintext: Uint8Array) =>
      Promise.resolve(fake.fakeEncryptContacts(plaintext)),
    decryptContacts: (ciphertext: Uint8Array) => {
      wasmMock.decryptCalls++;
      const out = fake.fakeDecryptContacts(ciphertext);
      wasmMock.opened.push(out);
      return Promise.resolve(out);
    },
  };
});

const prefsMock = vi.hoisted(() => ({
  historyEnabled: true,
  neverCacheKeys: false,
}));

vi.mock("~/lib/storage/preferences", () => ({
  getPreferences: () => Promise.resolve({ ...prefsMock }),
}));

let local: FakeArea;
let sync: FakeArea;
let permissions: {
  contains: ReturnType<typeof vi.fn>;
  request: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
  permissions = {
    contains: vi.fn().mockResolvedValue(false),
    request: vi.fn().mockResolvedValue(false),
  };
  ({ local, sync } = stubChromeStorage({}, { permissions }));
  wasmMock.session = true;
  wasmMock.encryptCalls = 0;
  wasmMock.decryptCalls = 0;
  wasmMock.sealed = [];
  wasmMock.opened = [];
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
    // ~30KB per entry: two fit seg 0's 64 KB bucket, a third would pad it
    // to 128 KB, so the 3rd starts seg 1 and the 4th joins it.
    for (let i = 0; i < 4; i++) {
      await appendHistoryEntry(entry(`${i}:${"x".repeat(30_000)}`));
    }
    expect(local.store.has("pgp_history_seg_0")).toBe(true);
    expect(local.store.has("pgp_history_seg_1")).toBe(true);
    expect(local.store.has("pgp_history_seg_2")).toBe(false);

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

  // RAM-after-lock: no plaintext cache, so every load decrypts anew and none
  // happens once locked. (Component state: HistoryPage unmounts on lock.)
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
    expect(h[0].content?.startsWith("83:")).toBe(true);
    expect(h.some((e) => e.content?.startsWith("0:"))).toBe(false);
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

/** Reject set() like Chrome's quota error from the `nth` call (1-based);
 *  reads/removes keep working. */
function failSetFrom(area: FakeArea, nth: number): void {
  const original = area.set.bind(area);
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
    expect(historyKeys(local.store)).toEqual([]);
  });

  it("removes the orphaned new segment when the manifest write fails", async () => {
    // Fill segment 0 so the next append creates segment 1.
    for (let i = 0; i < 2; i++) {
      await appendHistoryEntry(entry(`${i}:${"x".repeat(30_000)}`));
    }
    expect(local.store.has("pgp_history_seg_1")).toBe(false);

    // set #1 = segment 1 write (succeeds), set #2 = manifest (fails).
    failSetFrom(local, 2);
    await expect(
      appendHistoryEntry(entry(`lost:${"x".repeat(30_000)}`)),
    ).rejects.toThrow(/quota/i);

    expect(local.store.has("pgp_history_seg_1")).toBe(false);
    const h = await loadHistory();
    expect(h).toHaveLength(2);
    expect(h.some((e) => e.content?.startsWith("lost:"))).toBe(false);
  });

  it("keeps an existing head readable when only the manifest write fails", async () => {
    await appendHistoryEntry(entry("first"));

    // Segment 0 rewrite succeeds, manifest fails: the stale manifest still
    // references the segment, so nothing is lost.
    failSetFrom(local, 2);
    await expect(appendHistoryEntry(entry("second"))).rejects.toThrow(/quota/i);

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

    // A racing context's manifest write dropped segment 0; the blob exists.
    await local.set({ pgp_history: { segs: [] } });
    expect(await historyByteSize()).toBe(0);

    const h = await loadHistory();
    expect(h.map((e) => e.content)).toEqual(["kept-2", "kept-1"]);
    expect(await historyByteSize()).toBeGreaterThan(0);
    await appendHistoryEntry(entry("kept-3"));
    const after = await loadHistory();
    expect(after.map((e) => e.content)).toEqual(["kept-3", "kept-2", "kept-1"]);
  });

  it("clearHistory removes segments the manifest doesn't reference", async () => {
    await appendHistoryEntry(entry("orphan-to-be"));
    await local.set({ pgp_history: { segs: [] } });

    await clearHistory();
    expect(historyKeys(local.store)).toEqual([]);
  });
});

// Unit counterparts of tests/e2e/history-memory.spec.ts's substitution test.
describe("segment domain binding", () => {
  it("seals every segment for its own key, never under the legacy envelope", async () => {
    for (let i = 0; i < 4; i++) {
      await appendHistoryEntry(entry(`${i}:${"x".repeat(30_000)}`));
    }
    for (const n of [0, 1]) {
      const blob = local.store.get(`pgp_history_seg_${n}`);
      expect(isDomainSealed(blob)).toBe(true);
      expect(sealedDomain(blob)).toBe(`pgp_history_seg_${n}`);
    }
  });

  it("refuses a segment blob replayed into another segment slot", async () => {
    await appendHistoryEntry(entry("original"));
    const seg0 = local.store.get("pgp_history_seg_0");

    // Positive control: a genuine seg_1 blob IS adopted, so the rejection
    // below is the domain binding, not a dead path.
    await local.set({
      pgp_history_seg_1: domainEnvelope(
        "pgp_history_seg_1",
        new TextEncoder().encode(
          JSON.stringify([
            { id: "legit", ts: 1, op: "encrypt", recipients: [] },
          ]),
        ),
      ),
    });
    expect((await loadHistory()).map((e) => e.id)).toContain("legit");

    // Attack: byte-for-byte copy of seg_0 into seg_2. Must NOT be adopted.
    await local.set({ pgp_history_seg_2: seg0 });
    const after = await loadHistory();
    expect(after.filter((e) => e.content === "original")).toHaveLength(1);
    const manifest = local.store.get("pgp_history") as {
      segs: { n: number }[];
    };
    expect(manifest.segs.map((s) => s.n)).not.toContain(2);
  });

  it("refuses a blob sealed for another store", async () => {
    for (const domain of ["pgp_public_contacts", "pgp_keyring"]) {
      await local.set({
        pgp_history_seg_0: domainEnvelope(
          domain,
          new TextEncoder().encode(
            JSON.stringify([
              { id: "planted", ts: 1, op: "encrypt", recipients: [] },
            ]),
          ),
        ),
      });
      expect(await loadHistory()).toEqual([]);
    }
  });
});

describe("legacy envelope migration", () => {
  /** Pre-domain-separation segment: shared key and AAD, no slot binding. */
  function seedLegacySegment(n: number, contents: string[]): void {
    const entries = contents.map((content, i) => ({
      id: `legacy-${n}-${i}`,
      ts: 1_700_000_000_000 + i,
      op: "encrypt",
      recipients: [],
      content,
    }));
    const json = new TextEncoder().encode(JSON.stringify(entries));
    local.store.set(`pgp_history_seg_${n}`, legacyEnvelope(json));
    local.store.set("pgp_history", { segs: [{ n, bytes: json.length }] });
  }

  it("still loads a segment sealed by a shipped older build", async () => {
    seedLegacySegment(0, ["written before the fix"]);

    const h = await loadHistory();
    expect(h.map((e) => e.content)).toEqual(["written before the fix"]);
  });

  it("re-seals it under the domain-bound scheme on that first read", async () => {
    seedLegacySegment(0, ["written before the fix"]);
    expect(isDomainSealed(local.store.get("pgp_history_seg_0"))).toBe(false);

    await loadHistory();

    const blob = local.store.get("pgp_history_seg_0");
    expect(isDomainSealed(blob)).toBe(true);
    expect(sealedDomain(blob)).toBe("pgp_history_seg_0");
    // Re-sealed byte-for-byte: byte accounting still right, nothing dropped.
    const manifest = local.store.get("pgp_history") as {
      segs: { n: number; bytes: number }[];
    };
    expect(storedPlaintext(blob as StoredEnvelope)).toHaveLength(
      manifest.segs[0].bytes,
    );
    expect((await loadHistory()).map((e) => e.content)).toEqual([
      "written before the fix",
    ]);
  });

  it("keeps appending to a migrated segment without losing its entries", async () => {
    seedLegacySegment(0, ["old-1", "old-2"]);

    await appendHistoryEntry(entry("new-1"));

    expect((await loadHistory()).map((e) => e.content)).toEqual([
      "new-1",
      "old-2",
      "old-1",
    ]);
    expect(isDomainSealed(local.store.get("pgp_history_seg_0"))).toBe(true);
  });

  it("leaves the readable legacy blob in place when the re-seal write fails", async () => {
    seedLegacySegment(0, ["precious"]);
    const before = local.store.get("pgp_history_seg_0");
    failSetFrom(local, 1);

    // The entry still loads; only the opportunistic upgrade was lost.
    expect((await loadHistory()).map((e) => e.content)).toEqual(["precious"]);
    expect(local.store.get("pgp_history_seg_0")).toBe(before);
  });

  it("a migrated segment is no longer replayable into another slot", async () => {
    seedLegacySegment(0, ["was-replayable"]);
    await loadHistory(); // migrates

    await local.set({
      pgp_history_seg_1: local.store.get("pgp_history_seg_0"),
    });
    expect((await loadHistory()).map((e) => e.content)).toEqual([
      "was-replayable",
    ]);
  });
});

// The wasm-boundary buffers are the copies we CAN clear (JSON strings are
// immutable). The mock keeps every buffer, so these assert all zeros.
describe("plaintext zeroization", () => {
  /** Asserts non-empty first, so a scan that never ran can't pass. */
  function expectAllZeroed(buffers: Uint8Array[]): void {
    expect(buffers.length).toBeGreaterThan(0);
    for (const buf of buffers) {
      expect(buf.length).toBeGreaterThan(0);
      expect(buf.every((b) => b === 0)).toBe(true);
    }
  }

  it("zeroizes the encoded segment JSON after sealing it", async () => {
    await appendHistoryEntry(entry("sensitive-on-write"));
    expectAllZeroed(wasmMock.sealed);
  });

  it("zeroizes the decrypted segment bytes after parsing them", async () => {
    await appendHistoryEntry(entry("sensitive-on-read"));
    wasmMock.opened = [];

    await loadHistory();

    expectAllZeroed(wasmMock.opened);
  });

  it("zeroizes the decrypted bytes even when the segment is unparseable", async () => {
    await local.set({
      pgp_history_seg_0: domainEnvelope(
        "pgp_history_seg_0",
        new TextEncoder().encode("not json at all"),
      ),
    });
    await local.set({ pgp_history: { segs: [{ n: 0, bytes: 15 }] } });

    expect(await loadHistory()).toEqual([]);
    expectAllZeroed(wasmMock.opened);
  });

  it("zeroizes the plaintext of a legacy segment it migrates", async () => {
    const json = new TextEncoder().encode(
      JSON.stringify([
        { id: "legacy", ts: 1, op: "encrypt", recipients: [], content: "old" },
      ]),
    );
    local.store.set("pgp_history_seg_0", legacyEnvelope(json));
    local.store.set("pgp_history", { segs: [{ n: 0, bytes: json.length }] });

    expect(await loadHistory()).toHaveLength(1);

    // Both the decrypted buffer AND the one handed to the re-seal.
    expectAllZeroed(wasmMock.opened);
    expectAllZeroed(wasmMock.sealed);
  });
});

// Cleartext manifest and blob length must move in buckets only, never
// reveal exact message lengths.
describe("length-hiding padding", () => {
  interface Manifest {
    segs: { n: number; bytes: number }[];
  }
  const manifest = () => local.store.get("pgp_history") as Manifest;
  const seg0 = () => local.store.get("pgp_history_seg_0") as StoredEnvelope;

  it("pads the segment and records only the bucket in the manifest", async () => {
    await appendHistoryEntry(entry("short"));

    expect(manifest().segs[0].bytes).toBe(2048);
    expect(storedPlaintext(seg0())).toHaveLength(2048);
    expect((await loadHistory()).map((e) => e.content)).toEqual(["short"]);
  });

  it("messages of different lengths in one bucket leave the same sizes", async () => {
    await appendHistoryEntry(entry("a"));
    const sizeA = manifest().segs[0].bytes;
    const blobA = storedPlaintext(seg0()).length;
    await clearHistory();

    await appendHistoryEntry(entry("b".repeat(1500)));
    expect(manifest().segs[0].bytes).toBe(sizeA);
    expect(storedPlaintext(seg0()).length).toBe(blobA);
  });

  it("reads an unpadded segment from an older build, then re-pads it", async () => {
    const json = new TextEncoder().encode(
      JSON.stringify([
        { id: "old", ts: 1, op: "encrypt", recipients: [], content: "kept" },
      ]),
    );
    local.store.set(
      "pgp_history_seg_0",
      domainEnvelope("pgp_history_seg_0", json),
    );
    local.store.set("pgp_history", { segs: [{ n: 0, bytes: json.length }] });

    expect((await loadHistory()).map((e) => e.content)).toEqual(["kept"]);

    expect(storedPlaintext(seg0())).toHaveLength(2048);
    expect(manifest().segs[0].bytes).toBe(2048);
    expect((await loadHistory()).map((e) => e.content)).toEqual(["kept"]);
  });

  it("does not rewrite an already padded segment on read", async () => {
    await appendHistoryEntry(entry("steady"));
    const before = seg0();
    const encrypts = wasmMock.encryptCalls;

    await loadHistory();

    expect(seg0()).toBe(before);
    expect(wasmMock.encryptCalls).toBe(encrypts);
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

// A full ~2 MB pre-padding history (64-96 KB segments) must survive
// re-padding into 128 KB buckets without pruning, and new segments must
// fit as much as before.
describe("padding upgrade keeps a full history", () => {
  interface Manifest {
    segs: { n: number; bytes: number }[];
  }
  const manifest = () => local.store.get("pgp_history") as Manifest;

  /** 28 segments of 3 x ~24 KB entries, exact sizes in the manifest, just
   *  under the 2 MB budget. */
  function seedFullPrePaddingHistory(): number {
    const segs: { n: number; bytes: number }[] = [];
    let id = 0;
    for (let n = 0; n < 28; n++) {
      const entries = [0, 1, 2].map(() => ({
        id: `old-${id}`,
        ts: 1_000 + id++,
        op: "encrypt",
        recipients: [],
        signed: false,
        content: "x".repeat(24_000),
      }));
      const json = new TextEncoder().encode(JSON.stringify(entries));
      local.store.set(
        `pgp_history_seg_${n}`,
        domainEnvelope(`pgp_history_seg_${n}`, json),
      );
      segs.push({ n, bytes: json.length });
    }
    expect(segs.reduce((a, s) => a + s.bytes, 0)).toBeLessThanOrEqual(
      2 * 1024 * 1024,
    );
    local.store.set("pgp_history", { segs });
    return id;
  }

  it("keeps every entry across the re-padding load and the loads after it", async () => {
    const total = seedFullPrePaddingHistory();

    expect(await loadHistory()).toHaveLength(total);
    // The re-pad really happened (old segments now sit in 128 KB buckets)...
    expect(manifest().segs.every((s) => s.bytes === 128 * 1024)).toBe(true);
    expect(await loadHistory()).toHaveLength(total);
    expect(await loadHistory()).toHaveLength(total);
    expect(manifest().segs).toHaveLength(28);
    expect(await historyByteSize()).toBeLessThanOrEqual(2 * 1024 * 1024);
  });

  it("keeps every old entry when new ones are appended after the upgrade", async () => {
    const total = seedFullPrePaddingHistory();
    await loadHistory();

    for (let i = 0; i < 10; i++) {
      await appendHistoryEntry(entry(`new-${i}`));
    }

    const h = await loadHistory();
    expect(h).toHaveLength(total + 10);
    expect(h[0].content).toBe("new-9");
    expect(h.at(-1)?.id).toBe("old-0");
    // A pre-padding segment past the seal size is never reopened.
    expect(manifest().segs).toHaveLength(29);
  });

  it("holds as much real content as the pre-padding budget did", async () => {
    // Past the budget: ~2 MB of real content must survive, not half.
    const size = 4_000;
    for (let i = 0; i < 700; i++) {
      await appendHistoryEntry(entry(`${i}:${"y".repeat(size)}`));
    }
    const kept = await loadHistory();
    const realBytes = kept.reduce((a, e) => a + (e.content?.length ?? 0), 0);
    expect(realBytes).toBeGreaterThan(0.9 * 2 * 1024 * 1024);
    expect(await historyByteSize()).toBeLessThanOrEqual(2 * 1024 * 1024);
    // Every multi-entry segment stays inside the 64 KB bucket.
    expect(manifest().segs.every((s) => s.bytes <= 64 * 1024)).toBe(true);
    // 700 sealed appends: past the 5 s default on a loaded CI runner.
  }, 20_000);
});
