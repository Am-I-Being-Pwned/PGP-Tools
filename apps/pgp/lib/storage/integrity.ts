/**
 * Freshness for the sealed stores: rollback and deletion detection, and
 * an append-only revocation floor.
 *
 * ## The gap this closes
 *
 * Every sealed store is bound to its slot (`envelope.ts`), but nothing in
 * a seal says WHEN it was written. Someone who can write chrome.storage
 * -- for a "sync across devices" user, anyone signed in to their Google
 * account -- can keep an old, perfectly valid blob and write it back
 * later. Demonstrated: an older contacts blob un-revokes a contact the
 * user had seen revoked, deleted keys and contacts come back, and
 * deleting `pgp_settings` silently resets a Paranoid user to defaults.
 *
 * ## What this does
 *
 *  - Each sealed store carries a GENERATION inside its sealed plaintext
 *    (`$gen`; see {@link withGeneration}), so it cannot be edited without
 *    the vault key. A write stamps `max(mark + 1, Date.now())`.
 *  - This module keeps a sealed LEDGER of the highest generation this
 *    device has seen for each store. A store that loads with a lower
 *    generation than its mark, or is absent although the ledger has a
 *    mark for it, is reported ({@link reportIntegrityIssue}) and the UI
 *    warns. It WARNS rather than refuses -- the owner's call: refusing
 *    would turn every false positive into a locked-out user.
 *  - The ledger also holds every fingerprint this device has seen
 *    revoked. Contacts are merged against it on every load and save, so a
 *    rolled-back contacts blob still reads as revoked and is never
 *    encrypted to. A rollback of the contacts blob cannot undo that,
 *    because the floor is not in the contacts blob.
 *
 * ## Why the ledger lives in `local`, whatever the vault's location
 *
 * The attacker this is for writes `chrome.storage.sync` from another
 * machine. They cannot write this device's `chrome.storage.local`. So
 * the ledger is local-only, never mirrored to sync: a mirror would only
 * hand them a copy to delete. The flip side is that every device keeps
 * its own marks, and a device only knows what it has itself seen.
 *
 * ## Multi-device sync, and the false positive it can cause
 *
 * Two devices sharing a sync vault each keep their own marks. Device B
 * loading a blob device A wrote just raises B's mark, so ordinary sync
 * is silent. The generation is a wall-clock timestamp (never below the
 * last one seen) rather than a counter for exactly this case: when two
 * devices write the same store at once, sync keeps the LATER write, and
 * the later write carries the larger stamp, so neither device warns. The
 * stamps only disagree with sync's choice when the devices' clocks are
 * further apart than the gap between the two writes -- then the device
 * whose write lost can warn once. That is the trade-off taken, and the
 * warning's copy says "two devices changing the same data at once" can
 * cause it. (The lost write itself is an existing property of sync's
 * last-write-wins, not something this adds.)
 *
 * ## A ledger that is deleted, or replaced with junk
 *
 * Without its ledger a device cannot tell a rolled-back store from the
 * real one, so deleting `pgp_integrity` used to switch every defence
 * here off at once, silently: a rollback un-revoked contacts again, and
 * the legacy-preferences migration ran again over planted values. Now a
 * missing ledger is recognised for what it is when this device's LOCAL
 * area holds a sealed store stamped with a generation (only a build that
 * keeps a ledger writes one), and an unreadable one always is. Either
 * way the fresh ledger that replaces it carries that fact (`lost`), so
 * the warning repeats on every unlock until the user dismisses it, the
 * settings read as the strictest preset meanwhile, and the legacy
 * migration never runs over it. The revocation floor the old ledger held
 * is gone; what can be rebuilt is (every contact the contacts blob itself
 * has as revoked goes straight back into the floor on its next load), and
 * the warning says revocations may need checking. Only the local area is
 * scanned: a sync vault's stores carry generations on a brand-new second
 * device too, which has every right to have no ledger.
 *
 * ## What this does NOT catch
 *
 *  - A rollback of EVERYTHING at once, including this ledger, to one
 *    consistent earlier snapshot. Deleting the ledger AND rolling every
 *    local store back to blobs from before generations existed is that
 *    same rollback. No scheme kept only in storage the
 *    attacker can write can tell that apart from the real past; it needs
 *    a counter outside their reach. For a sync attacker the local ledger
 *    IS outside their reach -- this gap is for someone with write access
 *    to the device's own profile, who can do far worse anyway.
 *  - A device that has never seen a store. A brand-new second device of
 *    a sync vault has no marks, so a store deleted before it first
 *    unlocks reads as "never existed". Its first unlock adopts what it
 *    finds, exactly as an upgrade from a build without generations does.
 *  - History. Its segments are local-only (the sync attacker cannot
 *    reach them) and have their own manifest; they carry no generation.
 *
 * ## Back-compat
 *
 * Blobs written before this carry no `$gen` and read as generation 0. A
 * device with no ledger (first run of this build) creates one from what
 * it loads, so the first upgrade never warns.
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
 *
 *  An ELEMENT rather than a `{ gen, items }` wrapper so an older build
 *  still reads every record: each store's own validator rejects an
 *  element with no id, so an older build simply drops it, where a wrapper
 *  would read as "not an array" -- an empty store whose next write
 *  persists over everything the user has. */
export const GEN_FIELD = "$gen";

interface Ledger {
  v: 1;
  /** storage key -> highest generation seen or written on this device. */
  marks: Partial<Record<string, number>>;
  /** Fingerprints this device has seen revoked. Append-only. */
  revoked: string[];
  /** One-time migrations that have been settled under a session. Sealed,
   *  so an attacker cannot reset one to make it run again. */
  settled: string[];
  /** Set when this ledger replaced one that was deleted ("missing") or
   *  would not open ("ledger-unreadable"): reported on every proven read
   *  until the user dismisses the warning. */
  lost?: "missing" | "ledger-unreadable";
  /** Stores (only the settings, see {@link HELD_UNTIL_ACKNOWLEDGED}) last
   *  read older than their mark: reported on every proven read, and the
   *  settings held at the strictest preset, until the user dismisses the
   *  warning -- even after a routine save has stamped a newer generation
   *  over the old values. `gen` is what was read and `mark` what this
   *  device had seen then; dismissing accepts `gen` if nothing was
   *  written since. */
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

// ── issue reporting ─────────────────────────────────────────────────

export type IntegrityIssueKind =
  /** The store loaded with a generation below this device's mark. */
  | "rolled-back"
  /** The store loaded with NO generation although this device has
   *  recorded one for it. The softer case of "rolled-back": a 2.0.x build
   *  on another device of a sync vault drops the generation element when
   *  it rewrites a store, so this is what an un-updated device looks like
   *  -- and also what a rollback to a pre-generation blob looks like. The
   *  banner words it as both. */
  | "no-generation"
  /** The store is gone (or replaced by something that is not a sealed
   *  envelope) although this device has seen it. */
  | "missing"
  /** The ledger itself is present but will not open. */
  | "ledger-unreadable"
  /** A sealed envelope is there, but it will not open or parse under the
   *  vault key (junk, or another store's blob moved into its slot). */
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

/** Every issue reported since the panel opened (or the last clear). A
 *  stable array between reports, for `useSyncExternalStore`. */
export function integrityIssues(): readonly IntegrityIssue[] {
  return snapshot;
}

export function subscribeIntegrity(fn: () => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

/** Forget the reported issues (the user dismissed the warning). A store
 *  still out of date reports again on the next panel open. */
export function clearIntegrityIssues(): void {
  issues.clear();
  snapshot = [];
  for (const fn of listeners) fn();
}

/** The user dismissed the warning: clear a lost ledger's flag and any
 *  held store so they stop repeating (and the settings read as stored
 *  again), then forget the reports. In that order, so the warning only
 *  goes away once the dismissal is stored. A held store whose mark has not
 *  moved since has that mark lowered to the generation it was read at:
 *  the user has accepted that copy, and without this its next read would
 *  hold it again straight away. Unproven, so it only amends a ledger that
 *  opens. Resolves true when anything was cleared (the settings now read
 *  differently, so the panel should re-read them). */
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

// ── generation in a store's plaintext ───────────────────────────────

function genOf(v: unknown): number | undefined {
  if (typeof v !== "object" || v === null) return undefined;
  const g = (v as Record<string, unknown>)[GEN_FIELD];
  return typeof g === "number" && Number.isFinite(g) && g >= 0 ? g : undefined;
}

/** An array store's items with its generation element appended. */
export function withGeneration<T>(items: readonly T[], gen: number): unknown[] {
  return [...items, { [GEN_FIELD]: gen }];
}

/** Split a decrypted array store into its generation (0 when absent: a
 *  blob written before generations existed) and its items. */
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

/** The generation carried by an object store (settings). */
export function objectGeneration(parsed: object): number {
  return genOf(parsed) ?? 0;
}

// ── the ledger ──────────────────────────────────────────────────────

const local = () => chrome.storage.local;

/** Plaintext, local-only record of WHICH vault the ledger was started
 *  for: a digest of that vault's master protection. Kept outside the
 *  seal because its one job is the case where the seal will not open: a
 *  ledger sealed under a vault that has since been erased and recreated
 *  (on another device of a sync vault, say) is stale, not tampered with,
 *  and is replaced quietly. It only ever decides between "replace
 *  quietly" and "replace and warn" for a ledger that ALREADY fails to
 *  open under a session the stores have proven, so writing it gains a
 *  sync attacker nothing (it is local, out of their reach anyway). */
const LEDGER_VAULT = `${STORAGE_INTEGRITY}_vault`;

/** A short, stable digest of a master protection (field order fixed, so
 *  it does not depend on how the record was serialised). Null for
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

/** A ledger that will not open, recorded as started for a DIFFERENT
 *  vault than the one whose master protection is stored now: left over
 *  from an erased vault, so it is replaced without a warning. */
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

/** Read-only view of the ledger. Never writes, and never reports an
 *  unreadable ledger either: these paths have not yet proven the session
 *  key opens the vault, and a passkey that installs the wrong key would
 *  otherwise raise a tampering warning over what is really the "vault
 *  could not be read" screen. {@link updateLedger} reports it instead. */
async function peekLedger(): Promise<Ledger | null> {
  if (!(await hasContactsSession())) return null;
  return (await readLedger()).ledger;
}

/** The sealed stores whose generation shows a ledger-keeping build wrote
 *  them. History has no generation. */
const SEALED_STORES = [
  STORAGE_KEYRING,
  STORAGE_CONTACTS,
  STORAGE_CRX_KEYS,
  STORAGE_SETTINGS,
];

/**
 * Whether a sealed store in this device's LOCAL area carries a
 * generation above 0 -- that is, a build that keeps a ledger wrote it, so
 * a missing ledger was deleted rather than never created. `skip` leaves
 * out the store whose own write is being recorded (its stamp is this very
 * write, not evidence). A store that will not open counts only when
 * `unreadableCounts` (the migration gate errs towards "sealed data is
 * here"; detection errs towards silence, since that store's own loader
 * reports it). Needs the session, and opens up to four blobs, so it only
 * runs when the ledger is absent.
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
 * Read-modify-write the ledger under its own lock. `fn` returns whether
 * it changed anything; a ledger that did not exist is written too.
 *
 * `proven` says the caller has just opened, or sealed, a store blob under
 * the current session -- which proves the session key is the vault's.
 * Only then may an unreadable ledger be overwritten (it was sealed under
 * some other key, or is junk: it is reported and replaced rather than
 * left to disable detection forever) or a missing one created. An
 * unproven caller (a passkey that installed the wrong key, say) must not
 * be able to replace the real ledger with one sealed under that key.
 *
 * A replacement for an unreadable ledger, or for a missing one this
 * device evidently had ({@link localStoresCarryGenerations}), is marked
 * `lost`, and a proven read of a `lost` ledger reports it every time --
 * see "A ledger that is deleted" in the header. `justWrote` is the store
 * whose write is being recorded, left out of that scan.
 *
 * Returns the ledger as it now stands (null when nothing was read or
 * written). Holds a lock shared by every panel window, since a lost
 * update here can drop a revocation from the floor. Never takes a store
 * lock, so it can be called while holding one.
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
    // A fresh ledger, or one from before the vault was recorded: note
    // which vault it is for (see LEDGER_VAULT).
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
 * Start the ledger of a vault being created, together with its master
 * protection and before any store is written: called inside
 * `saveMasterProtection`'s lock, with the new vault's session installed.
 *
 * Without it the ledger was created by the first store write's
 * `recordWrite`, after that write. A panel closed in between, or two
 * stores' first writes racing, left a sealed store with a generation and
 * no ledger -- which is exactly what a deleted ledger looks like, so the
 * brand-new vault warned "ledger lost" and ran on the strictest preset.
 * Best-effort like the rest of this module: without a session (it cannot
 * seal) or on a failed write, the first proven write creates it as before.
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

/** Best-effort: the ledger is a detector, so a failure to read or write
 *  it (quota, a torn read) must never fail the store operation itself. */
async function bestEffort<T>(fallback: T, fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}

/** The generation a write to `store` should carry. */
export function claimGeneration(store: string): Promise<number> {
  return bestEffort(Date.now(), async () => {
    const mark = (await peekLedger())?.marks[store] ?? 0;
    return Math.max(mark + 1, Date.now());
  });
}

/** Record that `store` was just written at `gen`. */
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
 * Check a generation just read from `store` against this device's mark.
 * Lower: reported as rolled back, and the mark is NOT lowered (so the
 * warning repeats until the store is written again). Higher, or no mark
 * yet: the mark rises -- another device's write, or the first run.
 *
 * Resolves false when the ledger was lost (deleted or unreadable, and not
 * yet acknowledged): nothing can then say whether this copy is current,
 * and the settings reader falls back to the strictest preset.
 */
export function observeGeneration(
  store: string,
  gen: number,
): Promise<boolean> {
  return bestEffort(true, async () => {
    const l = await updateLedger((l) => {
      const mark = l.marks[store];
      if (mark !== undefined && gen < mark) {
        // No generation at all, where one was recorded: the softer kind
        // (an older build on another device drops it; see the kind).
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

/** Stores whose rolled-back (or generation-less) copy is not just
 *  reported but held until the user dismisses the warning. Only the
 *  settings: a rolled-back settings blob is a way to turn a Paranoid
 *  user's auto-lock back up, so it reads as the strictest preset
 *  meanwhile, the same as a lost ledger. The other stores have their own
 *  defence (the revocation floor) and keep warning until rewritten. */
const HELD_UNTIL_ACKNOWLEDGED = new Set<string>([STORAGE_SETTINGS]);

/** Whether the current session opens this device's ledger: proof the
 *  session key is the vault's, for a caller about to overwrite a blob
 *  that would not open. */
export function sessionOpensLedger(): Promise<boolean> {
  return bestEffort(false, async () => (await peekLedger()) !== null);
}

/**
 * `store` was found absent (or not a sealed envelope). Reports it, and
 * returns true, when this device has seen the store before. Read-only:
 * nothing has proven the session key yet.
 *
 * With no ledger to ask, it also returns true (without a report of its
 * own) when the ledger is unreadable or was evidently deleted: the
 * caller must then assume the worst. Otherwise deleting the ledger AND a
 * store would read as "never existed" -- settings at their defaults.
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
      // The stores that carried a generation opened under this session,
      // which proves the key: the deleted ledger can be reported here.
      reportIntegrityIssue({ store: STORAGE_INTEGRITY, kind: "missing" });
      return true;
    }
    return false;
  });
}

/** Every fingerprint this device has seen revoked. */
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

/** Whether a one-time migration has been settled on this device. */
export function isSettled(name: string): Promise<boolean> {
  return bestEffort(false, async () => {
    return (await peekLedger())?.settled.includes(name) ?? false;
  });
}

/** Record a one-time migration as settled. Unproven (it can run before
 *  any store has opened), so it only ever amends a ledger that already
 *  opens; on a device with none yet, the next proven write creates it and
 *  the migration simply re-checks, finding nothing, next time. */
export function markSettled(name: string): Promise<void> {
  return bestEffort(undefined, async () => {
    await updateLedger((l) => {
      if (l.settled.includes(name)) return false;
      l.settled = [...l.settled, name];
      return true;
    }, false);
  });
}

/** Drop the ledger. Only for a vault that is being created from nothing
 *  or erased: a ledger left over from an earlier vault would not open
 *  under the new one's key, and would read as tampering. */
export async function resetIntegrityLedger(): Promise<void> {
  await removeChunked(local(), STORAGE_INTEGRITY);
  await local().remove(LEDGER_VAULT);
  clearIntegrityIssues();
}
