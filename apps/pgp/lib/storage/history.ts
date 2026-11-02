/**
 * Segmented encrypted store for the opt-in operation history.
 *
 * Entries append to a head segment until its PADDED size would pass 64 KB;
 * only the head is re-encrypted on append. Segments are sealed under the
 * contacts session key with their own storage key as the domain
 * (`envelope.ts`), so a blob cannot be replayed into another slot. A
 * plaintext manifest holds segment numbers and padded bucket sizes only --
 * never entry data or exact lengths. Legacy unpadded / pre-domain segments
 * still read and are re-sealed in place on first read.
 *
 * Always chrome.storage.local: sync's quota cannot hold it, and history
 * should not leave the device.
 *
 * No plaintext is cached at module level, so dropping the session (master
 * lock) leaves nothing readable (proven in history.test.ts).
 */

import { STORAGE_HISTORY, STORAGE_HISTORY_SEGMENT_PREFIX } from "../constants";
import { hasContactsSession } from "../pgp/wasm";
import { withLock } from "./engine";
import { isStoredEnvelope, openEnvelope, sealEnvelope } from "./envelope";
import {
  bucketFor,
  isCanonicalPadding,
  padPlaintext,
  unpadPlaintext,
} from "./padding";
import { getPreferences } from "./preferences";

export type HistoryOp = "encrypt" | "sign" | "decrypt" | "verify";

export interface HistoryEntry {
  id: string;
  ts: number;
  op: HistoryOp;
  recipients: { fingerprint: string; name: string }[];
  signed?: boolean;
  /** Captured only for encrypt/sign; capped at CONTENT_CAP. */
  content?: string;
  truncated?: boolean;
  /** File ops store metadata only, never payloads. */
  files?: { name: string; size: number }[];
}

/** What callers pass to append: id/ts are assigned here. */
export type NewHistoryEntry = Omit<HistoryEntry, "id" | "ts">;

/** Max padded (bucket) size of a multi-entry segment. Sealing on the bucket,
 *  not raw JSON, keeps segments out of the 128 KB bucket. */
const SEGMENT_SEAL_BYTES = 64 * 1024;
/** Per-entry content cap (UTF-16 code units), independent of the budget. */
export const CONTENT_CAP = 32 * 1024;
/** Max files kept per entry: a huge drop must not balloon one entry. */
export const FILES_CAP = 500;
const FILE_NAME_CAP = 256;
/** Total byte budget without the optional `unlimitedStorage` permission. */
const DEFAULT_BUDGET_BYTES = 2 * 1024 * 1024;
const UNLIMITED_BUDGET_BYTES = 50 * 1024 * 1024;

interface SegmentRef {
  n: number;
  /** Padded bucket size, never exact JSON length (pre-padding manifests
   *  hold exact sizes until that segment is next read or written). */
  bytes: number;
}

/** Oldest → newest; the last element is the head segment. */
interface HistoryManifest {
  segs: SegmentRef[];
}

function isManifest(v: unknown): v is HistoryManifest {
  if (typeof v !== "object" || v === null) return false;
  const segs = (v as Record<string, unknown>).segs;
  return (
    Array.isArray(segs) &&
    segs.every(
      (s: unknown) =>
        typeof s === "object" &&
        s !== null &&
        typeof (s as Record<string, unknown>).n === "number" &&
        typeof (s as Record<string, unknown>).bytes === "number",
    )
  );
}

const HISTORY_OPS: HistoryOp[] = ["encrypt", "sign", "decrypt", "verify"];

function isValidEntry(v: unknown): v is HistoryEntry {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.id === "string" &&
    typeof o.ts === "number" &&
    HISTORY_OPS.some((op) => op === o.op) &&
    Array.isArray(o.recipients)
  );
}

function segKey(n: number): string {
  return `${STORAGE_HISTORY_SEGMENT_PREFIX}${n}`;
}

export function resolveBudget(hasUnlimited: boolean): number {
  return hasUnlimited ? UNLIMITED_BUDGET_BYTES : DEFAULT_BUDGET_BYTES;
}

/** Undefined where not exposed (Firefox); the chrome types claim otherwise. */
function permissionsApi(): typeof chrome.permissions | undefined {
  return (chrome as Partial<typeof chrome>).permissions;
}

/** Checked live, never persisted, so a revocation in chrome://extensions
 *  applies on the next append/load. Throw-safe. */
export async function hasUnlimitedStorage(): Promise<boolean> {
  try {
    const permissions = permissionsApi();
    if (!permissions) return false;
    return await permissions.contains({ permissions: ["unlimitedStorage"] });
  } catch {
    return false;
  }
}

/** Called from the history toggle's user gesture. A denial or missing API
 *  just keeps the default budget -- never block the toggle. */
export async function requestUnlimitedHistoryStorage(): Promise<boolean> {
  try {
    const permissions = permissionsApi();
    if (!permissions) return false;
    if (await hasUnlimitedStorage()) return true;
    return await permissions.request({ permissions: ["unlimitedStorage"] });
  } catch {
    return false;
  }
}

async function readManifest(): Promise<HistoryManifest> {
  const raw = (await chrome.storage.local.get(STORAGE_HISTORY))[
    STORAGE_HISTORY
  ];
  return isManifest(raw) ? raw : { segs: [] };
}

async function writeManifest(manifest: HistoryManifest): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_HISTORY]: manifest });
}

interface ReadSegment {
  entries: HistoryEntry[];
  /** Padded size after this read (incl. re-pad); 0 when unreadable. */
  bytes: number;
}

/** Decrypt one segment. Throw-safe: a missing, garbled, undecryptable or
 *  wrong-slot segment is skipped.
 *
 *  Legacy segments are re-sealed in place with the SAME data bytes; safe
 *  because every caller holds `withLock(STORAGE_HISTORY)`. Best-effort.
 *
 *  Decrypted bytes are zeroized on the way out (the decoded JS string
 *  cannot be). */
async function readSegment(n: number): Promise<ReadSegment> {
  let plaintext: Uint8Array | null = null;
  let repadded: Uint8Array | null = null;
  try {
    const blob = (await chrome.storage.local.get(segKey(n)))[segKey(n)];
    if (!isStoredEnvelope(blob)) return { entries: [], bytes: 0 };
    const opened = await openEnvelope(segKey(n), blob);
    plaintext = opened.plaintext;
    const data = unpadPlaintext(plaintext);
    const parsed: unknown = JSON.parse(new TextDecoder().decode(data));
    if (!Array.isArray(parsed)) return { entries: [], bytes: 0 };
    const entries = parsed.filter(isValidEntry);
    let bytes = plaintext.length;
    if (opened.legacy || !isCanonicalPadding(plaintext, true)) {
      // Re-seal the exact data bytes, not a re-serialisation, so nothing is lost.
      repadded = padPlaintext(data, true);
      try {
        await chrome.storage.local.set({
          [segKey(n)]: await sealEnvelope(segKey(n), repadded),
        });
        bytes = repadded.length;
      } catch {
        // best-effort; the old blob is still readable
      }
    }
    return { entries, bytes };
  } catch {
    return { entries: [], bytes: 0 };
  } finally {
    plaintext?.fill(0);
    repadded?.fill(0);
  }
}

/** Encrypt + write one segment padded to a bucket; returns the padded size
 *  (the only size the manifest learns). Zeroizes `json`; the source
 *  `JSON.stringify` string cannot be cleared (accepted). */
async function writeSegment(n: number, json: Uint8Array): Promise<number> {
  const padded = padPlaintext(json, true);
  json.fill(0);
  try {
    await chrome.storage.local.set({
      [segKey(n)]: await sealEnvelope(segKey(n), padded),
    });
    return padded.length;
  } finally {
    padded.fill(0);
  }
}

/** Budget weight: recorded size capped at the seal size, so padding into
 *  the 128 KB bucket (e.g. re-padding old segments) does not count as
 *  growth and trigger pruning. */
function budgetWeight(seg: SegmentRef): number {
  return Math.min(seg.bytes, SEGMENT_SEAL_BYTES);
}

/** Drop oldest segments to fit the budget; never the head. Mutates
 *  `manifest`; returns whether anything was pruned. */
async function pruneToBudget(manifest: HistoryManifest): Promise<boolean> {
  const budget = resolveBudget(await hasUnlimitedStorage());
  let total = manifest.segs.reduce((sum, s) => sum + budgetWeight(s), 0);
  let pruned = false;
  while (manifest.segs.length > 1 && total > budget) {
    const oldest = manifest.segs.shift();
    if (!oldest) break;
    total -= budgetWeight(oldest);
    await chrome.storage.local.remove(segKey(oldest.n));
    pruned = true;
  }
  return pruned;
}

/** Segment numbers in storage by prefix, ascending. Contexts in different
 *  windows race on the manifest (no CAS in chrome.storage), so loads union
 *  what exists instead of trusting it. Accepted residual: concurrent
 *  appends to the SAME head segment are last-write-wins. */
async function scanSegmentNumbers(): Promise<number[]> {
  const all = await chrome.storage.local.get(null);
  return Object.keys(all)
    .filter((k) => k.startsWith(STORAGE_HISTORY_SEGMENT_PREFIX))
    .map((k) => Number(k.slice(STORAGE_HISTORY_SEGMENT_PREFIX.length)))
    .filter((n) => Number.isInteger(n) && n >= 0)
    .sort((a, b) => a - b);
}

/** Fold segments missing from `manifest` back in; returns whether any were
 *  adopted. Unreadable strays are left for clearHistory's sweep. Planted or
 *  replayed blobs fail the per-slot domain and are never adopted. */
async function adoptStraySegments(manifest: HistoryManifest): Promise<boolean> {
  const known = new Set(manifest.segs.map((s) => s.n));
  let adopted = false;
  for (const n of await scanSegmentNumbers()) {
    if (known.has(n)) continue;
    const { entries, bytes } = await readSegment(n);
    if (entries.length === 0) continue;
    manifest.segs.push({ n, bytes });
    adopted = true;
  }
  if (adopted) manifest.segs.sort((a, b) => a.n - b.n);
  return adopted;
}

/** Append one entry; false while locked. Content capped at CONTENT_CAP;
 *  decrypt/verify entries are stripped to metadata. Storage failures
 *  reject so callers can tell a dropped capture from a saved one. */
export async function appendHistoryEntry(
  entry: NewHistoryEntry,
): Promise<boolean> {
  if (!(await hasContactsSession())) return false;
  return withLock(STORAGE_HISTORY, async () => {
    // Re-check inside the lock: a queued append must not run after lock.
    if (!(await hasContactsSession())) return false;

    const manifest = await readManifest();
    const last = manifest.segs.at(-1);
    const added = finalizeEntry(entry);
    let head: SegmentRef | undefined;
    let json: Uint8Array | undefined;
    // Only while the PADDED size stays within SEGMENT_SEAL_BYTES.
    if (last && last.bytes > 0 && last.bytes <= SEGMENT_SEAL_BYTES) {
      const entries = (await readSegment(last.n)).entries;
      entries.push(added);
      const candidate = encodeEntries(entries);
      if (
        entries.length === 1 ||
        bucketFor(candidate.length + 1) <= SEGMENT_SEAL_BYTES
      ) {
        head = last;
        json = candidate;
      } else {
        candidate.fill(0);
      }
    }
    const isNewSegment = head === undefined;
    if (!head || !json) {
      head = { n: last ? last.n + 1 : 0, bytes: 0 };
      manifest.segs.push(head);
      json = encodeEntries([added]);
    }

    // Segment first, manifest second: a rejected segment write persists nothing.
    head.bytes = await writeSegment(head.n, json);

    await pruneToBudget(manifest);
    try {
      await writeManifest(manifest);
    } catch (err) {
      // Remove a new segment whose manifest write failed, so it does not
      // orphan quota (best-effort). An existing head needs no cleanup.
      if (isNewSegment) {
        try {
          await chrome.storage.local.remove(segKey(head.n));
        } catch {
          // best-effort; clearHistory's prefix sweep catches leftovers
        }
      }
      throw err;
    }
    return true;
  });
}

/** The caller hands it to {@link writeSegment}, which zeroizes it. */
function encodeEntries(entries: HistoryEntry[]): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(entries));
}

function capFiles(files: NonNullable<HistoryEntry["files"]>): {
  files: NonNullable<HistoryEntry["files"]>;
  capped: boolean;
} {
  const capped =
    files.length > FILES_CAP ||
    files.some((f) => f.name.length > FILE_NAME_CAP);
  if (!capped) return { files, capped };
  return {
    files: files
      .slice(0, FILES_CAP)
      .map((f) =>
        f.name.length > FILE_NAME_CAP
          ? { ...f, name: f.name.slice(0, FILE_NAME_CAP) }
          : f,
      ),
    capped,
  };
}

function finalizeEntry(entry: NewHistoryEntry): HistoryEntry {
  const { content, truncated, files, ...rest } = entry;
  const full: HistoryEntry = {
    ...rest,
    id: crypto.randomUUID(),
    ts: Date.now(),
  };
  if (files !== undefined) {
    const result = capFiles(files);
    full.files = result.files;
    if (result.capped) full.truncated = true;
  }
  // Enforced here so no caller mistake can persist decrypted plaintext.
  if (entry.op === "decrypt" || entry.op === "verify") return full;
  if (content === undefined) return full;
  if (content.length > CONTENT_CAP) {
    return { ...full, content: content.slice(0, CONTENT_CAP), truncated: true };
  }
  return { ...full, content, ...(truncated ? { truncated } : {}) };
}

/** Newest first; empty while locked. Adopts stray segments and prunes to
 *  the live budget (so a revoked `unlimitedStorage` applies). */
export async function loadHistory(): Promise<HistoryEntry[]> {
  if (!(await hasContactsSession())) return [];
  return withLock(STORAGE_HISTORY, async () => {
    if (!(await hasContactsSession())) return [];

    const manifest = await readManifest();
    const adopted = await adoptStraySegments(manifest);
    const pruned = await pruneToBudget(manifest);

    const all: HistoryEntry[] = [];
    let resized = false;
    for (const seg of manifest.segs) {
      const { entries, bytes } = await readSegment(seg.n);
      all.push(...entries);
      if (bytes > 0 && bytes !== seg.bytes) {
        seg.bytes = bytes;
        resized = true;
      }
    }
    if (adopted || pruned || resized) await writeManifest(manifest);
    all.reverse();
    return all;
  });
}

/** Works while locked. Sweeps by key prefix, not the manifest, so segments
 *  the manifest lost are removed too. */
export async function clearHistory(): Promise<void> {
  await withLock(STORAGE_HISTORY, async () => {
    const all = await chrome.storage.local.get(null);
    const keys = Object.keys(all).filter(
      (k) =>
        k === STORAGE_HISTORY || k.startsWith(STORAGE_HISTORY_SEGMENT_PREFIX),
    );
    if (keys.length > 0) await chrome.storage.local.remove(keys);
  });
}

/** Budget usage as pruning counts it ({@link budgetWeight}). Manifest only,
 *  so it works while locked. */
export async function historyByteSize(): Promise<number> {
  const manifest = await readManifest();
  return manifest.segs.reduce((sum, s) => sum + budgetWeight(s), 0);
}

/** `skipped`: intentionally not captured (opted out, never-cache, locked).
 *  `failed`: the user expected it saved but storage rejected the write. */
export type RecordHistoryResult = "saved" | "skipped" | "failed";

/** Capture hook: appends only when opted in and not never-cache. Never
 *  throws (capture must not break an operation), but reports failure so the
 *  user is warned before trusting history with a message they delete. */
export async function recordHistory(
  entry: NewHistoryEntry,
): Promise<RecordHistoryResult> {
  try {
    const prefs = await getPreferences();
    if (!prefs.historyEnabled || prefs.neverCacheKeys) return "skipped";
    return (await appendHistoryEntry(entry)) ? "saved" : "skipped";
  } catch {
    return "failed";
  }
}
