/**
 * Freshness for the sealed stores: rollback and deletion detection, and
 * an append-only revocation floor.
 *
 * A seal binds a blob to its slot but not to a time, so anyone who can
 * write chrome.storage (for a sync user, anyone in their Google account)
 * can write an old valid blob back: un-revoking a contact, restoring
 * deleted keys, resetting a Paranoid user's settings.
 *
 *  - Each sealed store carries a generation (`$gen`) inside its sealed
 *    plaintext; a write stamps `max(mark + 1, Date.now())`. Wall-clock, not
 *    a counter, so sync's last-write-wins also keeps the larger stamp and
 *    concurrent devices do not warn (unless their clocks disagree by more
 *    than the gap between writes -- an accepted one-off warning).
 *  - A sealed LEDGER keeps the highest generation this device has seen per
 *    store. A lower or missing store is reported and the UI WARNS rather
 *    than refuses (owner's call: a false positive must not lock users out).
 *  - The ledger holds every fingerprint seen revoked; contacts are merged
 *    against it on load and save, so a rolled-back contacts blob still
 *    reads as revoked.
 *  - The ledger is local-only, never mirrored to sync: the sync attacker
 *    cannot write `local`, and a mirror would only hand them a copy to
 *    delete. Each device knows only what it has itself seen.
 *  - A deleted or unreadable ledger is detected (a LOCAL store carrying a
 *    generation proves one existed) and its replacement is marked `lost`:
 *    the warning repeats until dismissed, settings read as the strictest
 *    preset, and the legacy-preferences migration never reruns. Only the
 *    local area is scanned -- a new sync device legitimately has no ledger.
 *
 * Not caught: a consistent rollback of everything including the ledger
 * (needs a counter outside the attacker's reach; for a sync attacker the
 * local ledger is), a store deleted before a new device first unlocks,
 * and history (local-only, own manifest, no generation).
 *
 * Pre-generation blobs read as generation 0; a device with no ledger
 * adopts what it loads, so the first upgrade never warns.
 */

import {
  STORAGE_CONTACTS,
  STORAGE_CRX_KEYS,
  STORAGE_INTEGRITY,
  STORAGE_KEYRING,
  STORAGE_MASTER_PROTECTION,
  STORAGE_SETTINGS,
} from "../constants";
import { hasContactsSession } from "../pgp/wasm";
import { getChunked, removeChunked, setChunked } from "./chunked";
import { getItem, withSharedLock } from "./engine";
import { isStoredEnvelope, openEnvelope, sealEnvelope } from "./envelope";
import { padPlaintext, unpadPlaintext } from "./padding";

/** Where a sealed store keeps its generation: a field of a settings-style
 *  object, or a lone `{ "$gen": n }` element appended to an array store.
 *  An element, not a wrapper, so an older build drops it as an invalid item
 *  instead of reading "not an array" and persisting an empty store. */
export const GEN_FIELD = "$gen";

interface Ledger {
  v: 1;
  /** storage key -> highest generation seen or written on this device. */
  marks: Partial<Record<string, number>>;
  /** Fingerprints this device has seen revoked. Append-only. */
  revoked: string[];
  /** One-time migrations settled under a session. Sealed, so an attacker
   *  cannot reset one to make it run again. */
  settled: string[];
  /** Set when this ledger replaced a deleted or unopenable one: reported on
   *  every proven read until the user dismisses the warning. */
  lost?: "missing" | "ledger-unreadable";
  /** Settings last read older than their mark: reported, and held at the
   *  strictest preset, until dismissed -- even after a newer save. Dismissing
   *  accepts `gen` if nothing was written since. */
  suspect?: Partial<Record<string, SuspectRead>>;
}

interface SuspectRead {
  kind: "rolled-back" | "no-generation";
  gen: number;
  mark: number;
}

function isSuspectRead(v: unknown): v is SuspectRead {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    (o.kind === "rolled-back" || o.kind === "no-generation") &&
    typeof o.gen === "number" &&
    typeof o.mark === "number"
  );
}

function emptyLedger(): Ledger {
  return { v: 1, marks: {}, revoked: [], settled: [] };
}

function isLedger(v: unknown): v is Ledger {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    o.v === 1 &&
    typeof o.marks === "object" &&
    o.marks !== null &&
    !Array.isArray(o.marks) &&
    Object.values(o.marks).every((n) => typeof n === "number") &&
    Array.isArray(o.revoked) &&
    o.revoked.every((s) => typeof s === "string") &&
    Array.isArray(o.settled) &&
    o.settled.every((s) => typeof s === "string") &&
    (o.lost === undefined ||
      o.lost === "missing" ||
      o.lost === "ledger-unreadable") &&
    (o.suspect === undefined ||
      (typeof o.suspect === "object" &&
        o.suspect !== null &&
        !Array.isArray(o.suspect) &&
        Object.values(o.suspect).every(isSuspectRead)))
  );
}

export type IntegrityIssueKind =
  /** The store loaded with a generation below this device's mark. */
  | "rolled-back"
  /** No generation although this device recorded one: an un-updated 2.0.x
   *  device rewriting the store, or a rollback to a pre-generation blob. */
  | "no-generation"
  | "missing"
  | "ledger-unreadable"
  /** A sealed envelope that will not open under the vault key (junk, or
   *  another store's blob moved into its slot). */
  | "unreadable";

export interface IntegrityIssue {
  store: string;
  kind: IntegrityIssueKind;
}

const issues = new Map<string, IntegrityIssue>();
const listeners = new Set<() => void>();
let snapshot: readonly IntegrityIssue[] = [];

export function reportIntegrityIssue(issue: IntegrityIssue): void {
  const id = `${issue.store}\u0000${issue.kind}`;
  if (issues.has(id)) return;
  issues.set(id, issue);
  snapshot = [...issues.values()];
  for (const fn of listeners) fn();
}

/** Stable array between reports, for `useSyncExternalStore`. */
export function integrityIssues(): readonly IntegrityIssue[] {
  return snapshot;
}

export function subscribeIntegrity(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function clearIntegrityIssues(): void {
  issues.clear();
  snapshot = [];
  for (const fn of listeners) fn();
}

/** The user dismissed the warning: clear `lost` and held stores, then the
 *  reports -- in that order, so the warning only goes once the dismissal is
 *  stored. A held store's mark drops to the generation the user accepted.
 *  Only amends a ledger that opens. True when the settings now read
 *  differently. */
export async function acknowledgeIntegrityIssues(): Promise<boolean> {
  let cleared = false;
  await bestEffort(undefined, () =>
    updateLedger((l) => {
      const held = Object.entries(l.suspect ?? {});
      if (!l.lost && held.length === 0) return false;
      delete l.lost;
      for (const [store, s] of held) {
        if (s && l.marks[store] === s.mark) l.marks[store] = s.gen;
      }
      delete l.suspect;
      cleared = true;
      return true;
    }, false),
  );
  clearIntegrityIssues();
  return cleared;
}

function genOf(v: unknown): number | undefined {
  if (typeof v !== "object" || v === null) return undefined;
  const g = (v as Record<string, unknown>)[GEN_FIELD];
  return typeof g === "number" && Number.isFinite(g) && g >= 0 ? g : undefined;
}

export function withGeneration<T>(items: readonly T[], gen: number): unknown[] {
  return [...items, { [GEN_FIELD]: gen }];
}

/** 0 when absent (a pre-generation blob). */
export function splitGeneration(parsed: unknown[]): {
  gen: number;
  items: unknown[];
} {
  let gen = 0;
  const items: unknown[] = [];
  for (const el of parsed) {
    const g = genOf(el);
    if (g === undefined) items.push(el);
    else gen = Math.max(gen, g);
  }
  return { gen, items };
}

export function objectGeneration(parsed: object): number {
  return genOf(parsed) ?? 0;
}

const local = () => chrome.storage.local;

/** Plaintext, local-only digest of the vault the ledger was started for.
 *  Outside the seal because it only matters when the seal will not open: it
 *  tells a stale ledger from an erased vault (replace quietly) from a
 *  tampered one (replace and warn). Gains a sync attacker nothing. */
const LEDGER_VAULT = `${STORAGE_INTEGRITY}_vault`;

/** Field order fixed, so it does not depend on serialisation. Null for
 *  anything that is not a master protection. */
export async function masterProtectionDigest(
  mp: unknown,
): Promise<string | null> {
  if (typeof mp !== "object" || mp === null) return null;
  const o = mp as Record<string, unknown>;
  const fields =
    o.method === "passkey"
      ? [o.method, o.credentialId, o.prfSalt, o.storedSecret]
      : o.method === "password"
        ? [o.method, o.kdfSalt, o.encryptedCanary, o.canaryIv]
        : null;
  if (!fields?.every((f) => typeof f === "string")) return null;
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(JSON.stringify(fields)),
  );
  return Array.from(new Uint8Array(digest).subarray(0, 16), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}

async function recordedLedgerVault(): Promise<string | null> {
  const v: unknown = (await local().get(LEDGER_VAULT))[LEDGER_VAULT];
  return typeof v === "string" ? v : null;
}

async function currentVaultDigest(): Promise<string | null> {
  return masterProtectionDigest(
    await getItem<unknown>(STORAGE_MASTER_PROTECTION),
  );
}

/** An unopenable ledger recorded for a DIFFERENT vault than the current
 *  master protection: left from an erased vault, replaced without warning. */
async function ledgerIsFromAnotherVault(): Promise<boolean> {
  const recorded = await recordedLedgerVault();
  if (!recorded) return false;
  const current = await currentVaultDigest();
  return current !== null && current !== recorded;
}

interface LedgerRead {
  ledger: Ledger | null;
  unreadable: boolean;
}

async function readLedger(): Promise<LedgerRead> {
  const raw: unknown = await getChunked(local(), STORAGE_INTEGRITY);
  if (raw === undefined) return { ledger: null, unreadable: false };
  if (!isStoredEnvelope(raw)) return { ledger: null, unreadable: true };
  try {
    const { plaintext } = await openEnvelope(STORAGE_INTEGRITY, raw);
    const parsed: unknown = JSON.parse(
      new TextDecoder().decode(unpadPlaintext(plaintext)),
    );
    return isLedger(parsed)
      ? { ledger: parsed, unreadable: false }
      : { ledger: null, unreadable: true };
  } catch {
    return { ledger: null, unreadable: true };
  }
}

/** Read-only; never reports an unreadable ledger, because the session key
 *  is not yet proven (a wrong-key passkey would otherwise raise a tampering
 *  warning). {@link updateLedger} reports it. */
async function peekLedger(): Promise<Ledger | null> {
  if (!(await hasContactsSession())) return null;
  return (await readLedger()).ledger;
}

/** History has no generation. */
const SEALED_STORES = [
  STORAGE_KEYRING,
  STORAGE_CONTACTS,
  STORAGE_CRX_KEYS,
  STORAGE_SETTINGS,
];

/**
 * Whether a LOCAL sealed store carries a generation > 0, i.e. a missing
 * ledger was deleted rather than never created. `skip` excludes the store
 * being written now. Unopenable stores count only with `unreadableCounts`.
 * Opens up to four blobs, so only runs when the ledger is absent.
 */
export async function localStoresCarryGenerations({
  skip,
  unreadableCounts = false,
}: { skip?: string; unreadableCounts?: boolean } = {}): Promise<boolean> {
  for (const key of SEALED_STORES) {
    if (key === skip) continue;
    let raw: unknown;
    try {
      raw = await getChunked(local(), key);
    } catch {
      if (unreadableCounts) return true;
      continue;
    }
    if (!isStoredEnvelope(raw)) continue;
    try {
      const { plaintext } = await openEnvelope(key, raw);
      const parsed: unknown = JSON.parse(
        new TextDecoder().decode(unpadPlaintext(plaintext)),
      );
      const gen = Array.isArray(parsed)
        ? splitGeneration(parsed).gen
        : typeof parsed === "object" && parsed !== null
          ? objectGeneration(parsed)
          : 0;
      if (gen > 0) return true;
    } catch {
      if (unreadableCounts) return true;
    }
  }
  return false;
}

/**
 * Read-modify-write the ledger under its own cross-window lock (a lost
 * update can drop a revocation from the floor). Never takes a store lock.
 *
 * Only a `proven` caller -- one that just opened or sealed a store under
 * the current session -- may overwrite an unreadable ledger or create a
 * missing one; otherwise a wrong-key session could replace the real ledger.
 * Such a replacement is marked `lost` (see header). `justWrote` is left out
 * of the deletion scan.
 */
async function updateLedger(
  fn: (l: Ledger) => boolean,
  proven = true,
  justWrote?: string,
): Promise<Ledger | null> {
  if (!(await hasContactsSession())) return null;
  return withSharedLock(STORAGE_INTEGRITY, async () => {
    const { ledger, unreadable } = await readLedger();
    if (!ledger && !proven) return null;
    let l = ledger;
    if (!l) {
      l = emptyLedger();
      if (unreadable) {
        if (!(await ledgerIsFromAnotherVault())) l.lost = "ledger-unreadable";
      } else if (await localStoresCarryGenerations({ skip: justWrote })) {
        l.lost = "missing";
      }
    }
    if (proven && l.lost) {
      reportIntegrityIssue({ store: STORAGE_INTEGRITY, kind: l.lost });
    }
    if (proven) {
      for (const [store, s] of Object.entries(l.suspect ?? {})) {
        if (s) reportIntegrityIssue({ store, kind: s.kind });
      }
    }
    if (!ledger || (proven && !(await recordedLedgerVault()))) {
      const digest = await currentVaultDigest();
      if (digest) await local().set({ [LEDGER_VAULT]: digest });
    }
    if (!fn(l) && ledger) return l;
    await writeLedger(l);
    return l;
  });
}

async function writeLedger(l: Ledger): Promise<void> {
  const json = new TextEncoder().encode(JSON.stringify(l));
  await setChunked(
    local(),
    STORAGE_INTEGRITY,
    await sealEnvelope(STORAGE_INTEGRITY, padPlaintext(json, true)),
    false,
  );
}

/**
 * Start a new vault's ledger with its master protection, before any store
 * is written (called inside `saveMasterProtection`'s lock). Otherwise a
 * generation-stamped store with no ledger looks like a deleted ledger and a
 * brand-new vault warns. Best-effort.
 */
export async function startIntegrityLedger(mp: unknown): Promise<void> {
  await bestEffort(undefined, async () => {
    if (!(await hasContactsSession())) return;
    await withSharedLock(STORAGE_INTEGRITY, async () => {
      await writeLedger(emptyLedger());
      const digest = await masterProtectionDigest(mp);
      if (digest) await local().set({ [LEDGER_VAULT]: digest });
    });
  });
}

/** The ledger is a detector: its failure must never fail the store op. */
async function bestEffort<T>(fallback: T, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}

export function claimGeneration(store: string): Promise<number> {
  return bestEffort(Date.now(), async () => {
    const mark = (await peekLedger())?.marks[store] ?? 0;
    return Math.max(mark + 1, Date.now());
  });
}

export function recordWrite(store: string, gen: number): Promise<void> {
  return bestEffort(undefined, async () => {
    await updateLedger(
      (l) => {
        if ((l.marks[store] ?? -1) >= gen) return false;
        l.marks[store] = gen;
        return true;
      },
      true,
      store,
    );
  });
}

/**
 * Check a generation just read against this device's mark. Lower: reported,
 * and the mark is NOT lowered (the warning repeats until rewritten). Higher
 * or unmarked: the mark rises. False when the ledger was lost and not
 * acknowledged -- the settings reader then uses the strictest preset.
 */
export function observeGeneration(
  store: string,
  gen: number,
): Promise<boolean> {
  return bestEffort(true, async () => {
    const l = await updateLedger((l) => {
      const mark = l.marks[store];
      if (mark !== undefined && gen < mark) {
        const kind = gen === 0 ? "no-generation" : "rolled-back";
        reportIntegrityIssue({ store, kind });
        if (!HELD_UNTIL_ACKNOWLEDGED.has(store)) return false;
        const held = l.suspect?.[store];
        if (held?.kind === kind && held.gen === gen && held.mark === mark) {
          return false;
        }
        l.suspect = { ...l.suspect, [store]: { kind, gen, mark } };
        return true;
      }
      if (mark === gen) return false;
      l.marks[store] = gen;
      return true;
    });
    return !l?.lost && !l?.suspect?.[store];
  });
}

/** Only the settings are held until dismissed (a rollback could raise a
 *  Paranoid user's auto-lock); other stores have the revocation floor. */
const HELD_UNTIL_ACKNOWLEDGED = new Set<string>([STORAGE_SETTINGS]);

/** Proof the session key is the vault's, before overwriting a blob that
 *  would not open. */
export function sessionOpensLedger(): Promise<boolean> {
  return bestEffort(false, async () => (await peekLedger()) !== null);
}

/**
 * `store` was found absent. Reports and returns true when this device has
 * seen it. Read-only (session unproven). Also true, unreported, when the
 * ledger is unreadable or evidently deleted -- otherwise deleting the ledger
 * AND a store would read as "never existed" (settings at defaults).
 */
export function noteAbsent(store: string): Promise<boolean> {
  return bestEffort(false, async () => {
    if (!(await hasContactsSession())) return false;
    const { ledger, unreadable } = await readLedger();
    if (ledger) {
      const seen = ledger.marks[store] !== undefined;
      if (seen) reportIntegrityIssue({ store, kind: "missing" });
      return seen || ledger.lost !== undefined;
    }
    if (unreadable) return !(await ledgerIsFromAnotherVault());
    if (await localStoresCarryGenerations({ skip: store })) {
      // Those stores opened under this session, proving the key.
      reportIntegrityIssue({ store: STORAGE_INTEGRITY, kind: "missing" });
      return true;
    }
    return false;
  });
}

export function revokedFloor(): Promise<ReadonlySet<string>> {
  return bestEffort(new Set<string>(), async () => {
    return new Set((await peekLedger())?.revoked ?? []);
  });
}

/** Add fingerprints to the revocation floor. Never removes one. */
export function recordRevoked(ids: readonly string[]): Promise<void> {
  if (ids.length === 0) return Promise.resolve();
  return bestEffort(undefined, async () => {
    await updateLedger((l) => {
      const have = new Set(l.revoked);
      const added = ids.filter((id) => !have.has(id));
      if (added.length === 0) return false;
      l.revoked = [...l.revoked, ...added];
      return true;
    });
  });
}

export function isSettled(name: string): Promise<boolean> {
  return bestEffort(false, async () => {
    return (await peekLedger())?.settled.includes(name) ?? false;
  });
}

/** Unproven, so it only amends a ledger that already opens; without one
 *  the migration re-checks, finding nothing, next time. */
export function markSettled(name: string): Promise<void> {
  return bestEffort(undefined, async () => {
    await updateLedger((l) => {
      if (l.settled.includes(name)) return false;
      l.settled = [...l.settled, name];
      return true;
    }, false);
  });
}

/** Only for a vault being created or erased: an old vault's ledger would
 *  not open under the new key and would read as tampering. */
export async function resetIntegrityLedger(): Promise<void> {
  await removeChunked(local(), STORAGE_INTEGRITY);
  await local().remove(LEDGER_VAULT);
  clearIntegrityIssues();
}
