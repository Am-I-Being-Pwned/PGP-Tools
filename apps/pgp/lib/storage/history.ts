/**
 * Segmented encrypted store for the opt-in operation history.
 *
 * Entries are appended to a "head" segment that is sealed once it grows
 * past ~64 KB, after which a fresh head starts; only the head segment is
 * ever re-encrypted on append. Each segment is an AES-256-GCM blob under
 * the in-WASM contacts session key (same scheme as the keyring/contacts
 * stores). A small plaintext manifest at `STORAGE_HISTORY` tracks segment
 * numbers and byte sizes -- never entry data -- so pruning and usage
 * reporting work without decrypting anything.
 *
 * History always lives in chrome.storage.local, regardless of the user's
 * storageLocation preference: sync's total quota (~100 KB) couldn't hold
 * it, and history shouldn't leave the device anyway.
 *
 * No plaintext is ever cached at module level -- every read decrypts on
 * demand and every local goes out of scope when the call returns, so
 * dropping the contacts session (master lock) leaves nothing readable
 * here. See history.test.ts for the behavioral proof.
 */

import { STORAGE_HISTORY, STORAGE_HISTORY_SEGMENT_PREFIX } from "../constants";
import { fromBase64, toBase64, unpackIvCiphertext } from "../encoding";
import {
  decryptContacts,
  encryptContacts,
  hasContactsSession,
} from "../pgp/wasm";
import { withLock } from "./engine";
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

/** Seal the head segment once its JSON grows past this. */
const SEGMENT_SEAL_BYTES = 64 * 1024;
/** Per-entry content cap (UTF-16 code units) -- applies in ALL cases,
 *  independent of the total byte budget. */
export const CONTENT_CAP = 32 * 1024;
/** Total byte budget without the optional `unlimitedStorage` permission. */
const DEFAULT_BUDGET_BYTES = 2 * 1024 * 1024;
/** Generous budget once `unlimitedStorage` has been granted. */
const UNLIMITED_BUDGET_BYTES = 50 * 1024 * 1024;

interface SegmentRef {
  n: number;
  /** Plaintext JSON byte size of the segment (budget accounting). */
  bytes: number;
}

/** Oldest → newest; the last element is the head segment. */
interface HistoryManifest {
  segs: SegmentRef[];
}

interface EncryptedBlob {
  iv: string;
  ciphertext: string;
}

function isEncryptedBlob(v: unknown): v is EncryptedBlob {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return typeof o.iv === "string" && typeof o.ciphertext === "string";
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

// ── budget ───────────────────────────────────────────────────────────

/** The active total byte budget for a given permission state. */
export function resolveBudget(hasUnlimited: boolean): number {
  return hasUnlimited ? UNLIMITED_BUDGET_BYTES : DEFAULT_BUDGET_BYTES;
}

/** The permission API, or undefined where it isn't exposed (Firefox
 *  behaves differently here) -- the chrome types claim it always exists,
 *  hence the widening. */
function permissionsApi(): typeof chrome.permissions | undefined {
  return (chrome as Partial<typeof chrome>).permissions;
}

/** Whether the optional `unlimitedStorage` permission is currently
 *  granted. Never persisted -- checked live so a revocation from
 *  chrome://extensions takes effect on the next append/load. Feature-
 *  detected and throw-safe (Firefox permission APIs differ). */
export async function hasUnlimitedStorage(): Promise<boolean> {
  try {
    const permissions = permissionsApi();
    if (!permissions) return false;
    return await permissions.contains({ permissions: ["unlimitedStorage"] });
  } catch {
    return false;
  }
}

/** Prompt for the optional `unlimitedStorage` permission (idempotent).
 *  Called from the history toggle's user gesture. Returns whether it is
 *  now granted; a denial or a throwing/absent API just means the
 *  conservative default budget stays active -- never block the toggle. */
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

// ── storage plumbing (always chrome.storage.local) ───────────────────

async function readManifest(): Promise<HistoryManifest> {
  const raw = (await chrome.storage.local.get(STORAGE_HISTORY))[
    STORAGE_HISTORY
  ];
  return isManifest(raw) ? raw : { segs: [] };
}

async function writeManifest(manifest: HistoryManifest): Promise<void> {
  await chrome.storage.local.set({ [STORAGE_HISTORY]: manifest });
}

/** Decrypt one segment. Throw-safe: a segment that is missing, garbled,
 *  or undecryptable is skipped rather than failing the whole load. */
async function readSegment(n: number): Promise<HistoryEntry[]> {
  try {
    const blob = (await chrome.storage.local.get(segKey(n)))[segKey(n)];
    if (!isEncryptedBlob(blob)) return [];
    const plaintext = await decryptContacts(
      fromBase64(blob.ciphertext),
      fromBase64(blob.iv),
    );
    const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isValidEntry);
  } catch {
    return [];
  }
}

/** Encrypt + write one segment; returns its plaintext JSON byte size. */
async function writeSegment(
  n: number,
  entries: HistoryEntry[],
): Promise<number> {
  const json = new TextEncoder().encode(JSON.stringify(entries));
  const packed = await encryptContacts(json);
  const { iv, ciphertext } = unpackIvCiphertext(packed);
  await chrome.storage.local.set({
    [segKey(n)]: { iv: toBase64(iv), ciphertext: toBase64(ciphertext) },
  });
  return json.length;
}

/** Drop oldest segments until the total fits the active budget. The head
 *  segment is never dropped. Mutates `manifest`; returns whether anything
 *  was pruned (i.e. the manifest needs rewriting). */
async function pruneToBudget(manifest: HistoryManifest): Promise<boolean> {
  const budget = resolveBudget(await hasUnlimitedStorage());
  let total = manifest.segs.reduce((sum, s) => sum + s.bytes, 0);
  let pruned = false;
  while (manifest.segs.length > 1 && total > budget) {
    const oldest = manifest.segs.shift();
    if (!oldest) break;
    total -= oldest.bytes;
    await chrome.storage.local.remove(segKey(oldest.n));
    pruned = true;
  }
  return pruned;
}

/** Segment numbers present in storage under the segment prefix,
 *  ascending. `withLock` only serializes within one JS context and
 *  chrome.storage has no compare-and-swap, so two extension contexts
 *  (e.g. side panels in two browser windows) appending concurrently do
 *  racing read-modify-writes on the manifest: one context's manifest
 *  write can drop a segment the other just published. Scanning by
 *  prefix lets loadHistory union what actually exists instead of
 *  trusting the manifest alone. Residual race, accepted honestly: two
 *  contexts appending to the SAME head segment blob still last-write-
 *  wins (one entry lost) -- that can't be fixed without a cross-context
 *  CAS, which chrome.storage doesn't offer. */
async function scanSegmentNumbers(): Promise<number[]> {
  const all = await chrome.storage.local.get(null);
  return Object.keys(all)
    .filter((k) => k.startsWith(STORAGE_HISTORY_SEGMENT_PREFIX))
    .map((k) => Number(k.slice(STORAGE_HISTORY_SEGMENT_PREFIX.length)))
    .filter((n) => Number.isInteger(n) && n >= 0)
    .sort((a, b) => a - b);
}

/** Fold segments that exist in storage but not in `manifest` back into
 *  it (see {@link scanSegmentNumbers} for how they arise). Mutates
 *  `manifest`; returns whether anything was adopted (i.e. the manifest
 *  needs rewriting). Unreadable strays are left for clearHistory's
 *  prefix sweep rather than adopted as empty. */
async function adoptStraySegments(manifest: HistoryManifest): Promise<boolean> {
  const known = new Set(manifest.segs.map((s) => s.n));
  let adopted = false;
  for (const n of await scanSegmentNumbers()) {
    if (known.has(n)) continue;
    const entries = await readSegment(n);
    if (entries.length === 0) continue;
    const bytes = new TextEncoder().encode(JSON.stringify(entries)).length;
    manifest.segs.push({ n, bytes });
    adopted = true;
  }
  if (adopted) manifest.segs.sort((a, b) => a.n - b.n);
  return adopted;
}

// ── public API ───────────────────────────────────────────────────────

/** Append one entry. No-op while locked (returns false). Content is
 *  capped at CONTENT_CAP (with `truncated: true`); decrypt/verify entries
 *  have any content stripped defensively -- those ops are metadata-only.
 *  Returns whether the entry was actually written; storage failures
 *  (quota exhaustion, device full) propagate as rejections so callers
 *  can tell a dropped capture from a saved one. */
export async function appendHistoryEntry(
  entry: NewHistoryEntry,
): Promise<boolean> {
  if (!(await hasContactsSession())) return false;
  return withLock(STORAGE_HISTORY, async () => {
    // Re-check inside the lock: a queued append must not run after lock.
    if (!(await hasContactsSession())) return false;

    const manifest = await readManifest();
    const last = manifest.segs.at(-1);
    let head: SegmentRef;
    let isNewSegment = false;
    if (last && last.bytes < SEGMENT_SEAL_BYTES) {
      head = last;
    } else {
      head = { n: last ? last.n + 1 : 0, bytes: 0 };
      manifest.segs.push(head);
      isNewSegment = true;
    }

    // Segment first, manifest second: if the segment write rejects
    // (quota / device full) nothing has been persisted, so the stored
    // manifest still describes exactly what exists.
    const entries = head.bytes > 0 ? await readSegment(head.n) : [];
    entries.push(finalizeEntry(entry));
    head.bytes = await writeSegment(head.n, entries);

    await pruneToBudget(manifest);
    try {
      await writeManifest(manifest);
    } catch (err) {
      // A freshly created segment whose manifest write failed would be
      // an orphaned blob eating quota that the next append at the same
      // number silently overwrites. Remove it (best-effort) so the
      // store stays consistent with the manifest that is actually
      // stored. An existing head needs no cleanup: the stale manifest
      // still references it, only with an undercounted byte size.
      if (isNewSegment) {
        try {
          await chrome.storage.local.remove(segKey(head.n));
        } catch {
          // best-effort; clearHistory's prefix scan sweeps leftovers
        }
      }
      throw err;
    }
    return true;
  });
}

function finalizeEntry(entry: NewHistoryEntry): HistoryEntry {
  const { content, truncated, ...rest } = entry;
  const full: HistoryEntry = {
    ...rest,
    id: crypto.randomUUID(),
    ts: Date.now(),
  };
  // decrypt/verify are metadata-only; enforce here so no caller mistake
  // can persist decrypted plaintext.
  if (entry.op === "decrypt" || entry.op === "verify") return full;
  if (content === undefined) return full;
  if (content.length > CONTENT_CAP) {
    return { ...full, content: content.slice(0, CONTENT_CAP), truncated: true };
  }
  return { ...full, content, ...(truncated ? { truncated } : {}) };
}

/** All entries, newest first. Empty while locked. Also adopts segments
 *  the manifest lost track of (cross-context manifest race) and prunes
 *  down to the active budget, so a revoked `unlimitedStorage`
 *  permission takes effect on the next load. */
export async function loadHistory(): Promise<HistoryEntry[]> {
  if (!(await hasContactsSession())) return [];
  return withLock(STORAGE_HISTORY, async () => {
    if (!(await hasContactsSession())) return [];

    const manifest = await readManifest();
    const adopted = await adoptStraySegments(manifest);
    const pruned = await pruneToBudget(manifest);
    if (adopted || pruned) await writeManifest(manifest);

    const all: HistoryEntry[] = [];
    for (const seg of manifest.segs) {
      all.push(...(await readSegment(seg.n)));
    }
    // Segments and entries within them are stored oldest-first.
    all.reverse();
    return all;
  });
}

/** Remove every segment and the manifest. Works while locked (deleting
 *  ciphertext needs no session). Sweeps by key prefix rather than
 *  trusting the manifest: a failed manifest write or a concurrent
 *  append from another extension context can leave segments the
 *  manifest doesn't list, and "clear history" must remove those too. */
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

/** Total plaintext byte size across all segments (manifest metadata
 *  only -- no decryption, so it also works while locked). */
export async function historyByteSize(): Promise<number> {
  const manifest = await readManifest();
  return manifest.segs.reduce((sum, s) => sum + s.bytes, 0);
}

/** Outcome of a {@link recordHistory} capture attempt. `skipped` means
 *  capture was intentionally not attempted (opted out, never-cache mode,
 *  or locked); `failed` means the user expected the entry to be recorded
 *  but storage rejected the write (quota / device full). */
export type RecordHistoryResult = "saved" | "skipped" | "failed";

/** Capture hook for the workspace operations: appends only when the user
 *  has opted in (`historyEnabled`) and isn't in never-cache mode. Never
 *  throws -- history capture must never break or delay an operation --
 *  but reports the outcome so the call site can warn the user when a
 *  capture they were relying on silently failed (they may delete the
 *  original message trusting history has it). */
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
