/**
 * Who a key claims to be, and whether another contact already claims it.
 * Binding a name/address to a key is never decided for the user: key files
 * are attacker-supplied, so every key an import adds is checked against
 * held contacts and the rest of the import, and the Review asks first.
 */

import {
  CONFUSABLE,
  DOT_LOOKALIKES,
  markLookalikes,
  stripInvisible,
} from "../utils/lookalike";

const ADDRESS = /[^\s<>()[\]"',;:]+@[^\s<>()[\]"',;:]+/g;

/** Read `"carol"@corp.com` (and `carol"@corp.com`) as the bare local part:
 *  compared on what it shows, or it would claim no address and pass. */
function unquoteLocalParts(text: string): string {
  return text.replace(/"([^"\s<>@]*)"(?=@)/g, "$1").replace(/"(?=@)/g, "");
}

/**
 * A User ID as it READS, which is what two are compared on: NFKC-folded,
 * with every character that draws nothing (`INVISIBLE`) removed. Catches
 * what the engine's own stripping missed (older records, other text).
 */
export function readableForm(text: string): string {
  return stripInvisible(text.normalize("NFKC"));
}

/** Every address a User ID shows, anywhere in it (readable form,
 *  lower-cased, trailing dots dropped): any displayed address is claimed. */
export function emailsOf(userId: string): string[] {
  return [...new Set(addressesOf(userId).map((a) => a.toLowerCase()))];
}

/** Before lower-casing: address skeletons need to know which was a capital I. */
function addressesOf(userId: string): string[] {
  return (unquoteLocalParts(readableForm(userId)).match(ADDRESS) ?? []).map(
    (a) => a.replace(/[.。]+$/u, ""),
  );
}

export function emailOf(userId: string): string | null {
  return emailsOf(userId)[0] ?? null;
}

/** The name part of a User ID, every bracketed group and address
 *  removed wherever it sits, in readable form. */
export function nameOf(userId: string): string {
  return namePart(readableForm(userId));
}

/** `nameOf` without the readable form. */
function namePart(text: string): string {
  return unquoteLocalParts(text)
    .replace(/<[^<>]*>?/g, " ")
    .replace(/\([^()]*\)?/g, " ")
    .replace(ADDRESS, " ")
    .replace(/\s+/g, " ")
    .trim();
}

const PAIRS: [RegExp, string][] = [
  [/rn/g, "m"],
  [/vv/g, "w"],
];

/**
 * The "skeleton" of a name (after UTS #39): what it looks like. Same
 * skeleton = reads the same on screen. `capitalI` is what a capital I
 * reads as ("l" in sans-serif); names clash when any pair matches.
 */
export function nameSkeleton(name: string, capitalI: "i" | "l" = "i"): string {
  return skeleton(name, capitalI, NAME_DROPS);
}

/** What a name skeleton leaves out: accents (as marks, once decomposed),
 *  invisible characters, punctuation, symbols and spaces. */
const NAME_DROPS =
  /[\p{M}\p{Cf}\p{Default_Ignorable_Code_Point}\p{P}\p{S}\p{Z}\s]/u;

/** Accents and invisibles only: punctuation is meaningful in an address. */
const ADDRESS_DROPS = /[\p{M}\p{Cf}\p{Default_Ignorable_Code_Point}\s]/u;

function skeleton(
  text: string,
  capitalI: "i" | "l",
  drops: RegExp,
  dots = false,
): string {
  let out = "";
  const fold = (letter: string) => (letter === "I" ? capitalI : letter);
  for (const ch of readableForm(text).normalize("NFKD")) {
    const mapped =
      (dots && DOT_LOOKALIKES.has(ch) ? "." : undefined) ??
      CONFUSABLE.get(ch) ??
      (ch === "I" || ch === WILD ? ch : undefined);
    if (mapped !== undefined) {
      out += fold(mapped);
      continue;
    }
    if (drops.test(ch)) continue;
    const lower = ch.toLowerCase();
    out += fold(CONFUSABLE.get(lower) ?? lower);
  }
  for (const [pair, letter] of PAIRS) out = out.replace(pair, letter);
  return out;
}

/** What an address LOOKS like, with both capital-I readings: lookalike
 *  letters/dots mapped, accents dropped, case ignored. An address-only
 *  User ID has no name to fall back on. */
export function addressSkeletons(address: string): string[] {
  return [
    ...new Set([
      skeleton(address, "i", ADDRESS_DROPS, true),
      skeleton(address, "l", ADDRESS_DROPS, true),
    ]),
  ].filter(Boolean);
}

export function nameSkeletons(name: string): string[] {
  return [
    ...new Set([nameSkeleton(name, "i"), nameSkeleton(name, "l")]),
  ].filter(Boolean);
}

/** Wildcard letter in a skeleton (private-use, never dropped). */
const WILD = "";

function isMapped(c: string): boolean {
  return CONFUSABLE.has(c) || CONFUSABLE.has(c.toLowerCase());
}

/** `text` with unexplained out-of-script letters replaced by {@link WILD},
 *  or null when it has none. */
function withWildcards(
  text: string,
  keep: (c: string) => boolean,
): string | null {
  let wild = 0;
  const out = markLookalikes(text)
    .map((run) =>
      run.odd && !run.invisible
        ? [...run.text]
            .map((c) => {
              if (keep(c)) return c;
              wild++;
              return WILD;
            })
            .join("")
        : run.text,
    )
    .join("");
  return wild === 0 ? null : out;
}

/** At least two real letters, and no more wildcards than real letters. */
function boundedWild(skeletons: string[]): string[] {
  return [...new Set(skeletons)].filter((k) => {
    const real = [...k].filter((c) => c !== WILD).length;
    const wilds = [...k].length - real;
    return wilds > 0 && real >= 2 && wilds <= real;
  });
}

/**
 * Skeletons with unexplained out-of-script letters as wildcards. CONFUSABLE
 * can never be complete; a mixed-script word is not how anyone writes their
 * own name (the engine flags it `lookalike` too), so a name that would read
 * as a holder's at those letters is treated as a lookalike.
 */
function wildSkeletons(name: string): string[] {
  const text = withWildcards(name, isMapped);
  return text === null
    ? []
    : boundedWild([nameSkeleton(text, "i"), nameSkeleton(text, "l")]);
}

/** The same for an address; a look-alike dot is already mapped. */
function wildAddressSkeletons(address: string): string[] {
  const text = withWildcards(
    address,
    (c) => isMapped(c) || DOT_LOOKALIKES.has(c),
  );
  return text === null
    ? []
    : boundedWild([
        skeleton(text, "i", ADDRESS_DROPS, true),
        skeleton(text, "l", ADDRESS_DROPS, true),
      ]);
}

function wildMatch(pattern: string, plain: string): boolean {
  const p = [...pattern];
  const q = [...plain];
  return p.length === q.length && p.every((c, i) => c === WILD || c === q[i]);
}

/** An accent: a mark that draws something (CGJ is a hidden difference). */
const ACCENT = /^(?!\p{Default_Ignorable_Code_Point})\p{M}$/u;
const PLAIN_DROPS = /^[\p{P}\p{S}\p{Z}\s]$/u;
/** Marks a character kept whole so it never equals its folded letter. */
const KEPT = "";

/**
 * A name as plainly WRITTEN: accents, spacing, punctuation, symbols and
 * case dropped; nothing mapped or folded. NFD singletons (Kelvin, Ohm,
 * Angstrom signs) are kept whole and marked: they are lookalikes, not accents.
 *
 * Equal plain names are two people sharing a name (warning on every
 * "Alex Smith" trains click-through), so a lookalike is skeleton-equal but
 * plain-different -- except the same name with NO address on one side,
 * which nothing tells apart.
 */
function plainName(userId: string): string {
  let out = "";
  for (const ch of namePart(userId)) {
    if (ch.normalize("NFC") !== ch) {
      out += KEPT + ch;
      continue;
    }
    for (const d of ch.normalize("NFD").toLowerCase().normalize("NFD")) {
      if (ACCENT.test(d) || PLAIN_DROPS.test(d)) continue;
      out += d;
    }
  }
  return out;
}

/** Names that LOOK alike without being the same name. */
export function namesLookAlike(a: string, b: string): boolean {
  const na = nameFormOf(a);
  const nb = nameFormOf(b);
  return na !== null && nb !== null && nameLooksAlike(na, nb);
}

export interface IdentityHolder {
  keyId: string;
  userIds: string[];
  /** The user's own name for it; compared as one more name. */
  alias?: string;
  revoked?: boolean;
  /** The user's own key: flagged, but no contact to replace. */
  own?: boolean;
  /** Another key in the same import: nothing to replace. */
  incoming?: boolean;
}

export interface IdentityConflict {
  /** "address": same (or same-reading) email. "name": lookalike name, or the
   *  same name with no address to tell them apart. "key": an SSH import
   *  carries a key someone already holds (set only by `withIdentityConflicts`). */
  kind: "address" | "name" | "key";
  /** Revoked holders only when no live key holds it (`includeRevoked`). */
  holders: IdentityHolder[];
  /** The addresses only READ the same: never a rotation, never offer replace. */
  lookalike?: true;
  /** Same plain name and one side has no address: not a lookalike. */
  sameName?: true;
}

interface NameForm {
  plain: string;
  skeletons: string[];
  wild: string[];
}

interface HolderForm {
  emails: string[];
  looks: string[];
  wildLooks: string[];
  names: NameForm[];
  hasAddress: boolean;
}

function nameFormOf(userId: string): NameForm | null {
  const name = nameOf(userId);
  const skeletons = nameSkeletons(name);
  if (skeletons.length === 0) return null;
  return { plain: plainName(userId), skeletons, wild: wildSkeletons(name) };
}

function nameLooksAlike(a: NameForm, b: NameForm): boolean {
  const alike =
    a.skeletons.some((k) => b.skeletons.includes(k)) ||
    a.wild.some((w) => b.skeletons.some((k) => wildMatch(w, k))) ||
    b.wild.some((w) => a.skeletons.some((k) => wildMatch(w, k)));
  return alike && a.plain !== b.plain;
}

/** Cached per User ID array (stable until the record changes) -- the
 *  picker re-renders on every keystroke. */
const FORMS = new WeakMap<
  readonly string[],
  { alias: string | undefined; form: HolderForm }
>();

function formOf(holder: IdentityHolder): HolderForm {
  const hit = FORMS.get(holder.userIds);
  if (hit && hit.alias === holder.alias) return hit.form;
  const addresses = holder.userIds.flatMap(addressesOf);
  const emails = [...new Set(addresses.map((a) => a.toLowerCase()))];
  const names = [
    ...holder.userIds,
    ...(holder.alias ? [holder.alias] : []),
  ].flatMap((u) => nameFormOf(u) ?? []);
  const form: HolderForm = {
    emails,
    looks: [...new Set(addresses.flatMap(addressSkeletons))],
    wildLooks: [...new Set(addresses.flatMap(wildAddressSkeletons))],
    names,
    hasAddress: emails.length > 0,
  };
  FORMS.set(holder.userIds, { alias: holder.alias, form });
  return form;
}

interface Entry {
  at: number;
  id: string;
  holder: IdentityHolder;
  form: HolderForm;
}

const codePoints = (s: string) => [...s].length;

function push<K, V>(map: Map<K, V[]>, key: K, value: V) {
  const list = map.get(key);
  if (list) list.push(value);
  else map.set(key, [value]);
}

/**
 * Rivals indexed by every compared form, so clash checks are not
 * quadratic (was 24s at 1000 contacts). Wildcard skeletons are bucketed
 * by length.
 */
class HolderIndex {
  readonly email = new Map<string, Entry[]>();
  readonly look = new Map<string, Entry[]>();
  readonly lookByLength = new Map<number, [string, Entry][]>();
  readonly wildLookByLength = new Map<number, [string, Entry][]>();
  readonly name = new Map<string, [Entry, NameForm][]>();
  readonly nameByLength = new Map<number, [string, Entry, NameForm][]>();
  readonly wildNameByLength = new Map<number, [string, Entry, NameForm][]>();
  readonly plain = new Map<string, Entry[]>();

  constructor(holders: readonly IdentityHolder[]) {
    holders.forEach((holder, at) => {
      const form = formOf(holder);
      const entry = { at, id: holder.keyId.toUpperCase(), holder, form };
      for (const e of form.emails) push(this.email, e, entry);
      for (const k of form.looks) {
        push(this.look, k, entry);
        push(this.lookByLength, codePoints(k), [k, entry]);
      }
      for (const w of form.wildLooks)
        push(this.wildLookByLength, codePoints(w), [w, entry]);
      for (const n of form.names) {
        for (const k of n.skeletons) {
          push(this.name, k, [entry, n]);
          push(this.nameByLength, codePoints(k), [k, entry, n]);
        }
        for (const w of n.wild)
          push(this.wildNameByLength, codePoints(w), [w, entry, n]);
        if (n.plain) push(this.plain, n.plain, entry);
      }
    });
  }
}

function holdersOf(hits: Iterable<Entry>, exclude: string): IdentityHolder[] {
  const seen = new Map<number, Entry>();
  for (const e of hits) if (e.id !== exclude) seen.set(e.at, e);
  return [...seen.values()].sort((a, b) => a.at - b.at).map((e) => e.holder);
}

function claims(
  incoming: HolderForm,
  index: HolderIndex,
  exclude: string,
): IdentityConflict | null {
  const byAddress = holdersOf(
    incoming.emails.flatMap((e) => index.email.get(e) ?? []),
    exclude,
  );
  if (byAddress.length > 0) return { kind: "address", holders: byAddress };

  const looks: Entry[] = incoming.looks.flatMap((k) => index.look.get(k) ?? []);
  for (const w of incoming.wildLooks)
    for (const [k, e] of index.lookByLength.get(codePoints(w)) ?? [])
      if (wildMatch(w, k)) looks.push(e);
  for (const k of incoming.looks)
    for (const [w, e] of index.wildLookByLength.get(codePoints(k)) ?? [])
      if (wildMatch(w, k)) looks.push(e);
  const byLookalike = holdersOf(looks, exclude);
  if (byLookalike.length > 0) {
    return { kind: "address", lookalike: true, holders: byLookalike };
  }

  // Same plain name is two people unless one side has no address.
  const alike: Entry[] = [];
  const same: Entry[] = [];
  for (const mine of incoming.names) {
    for (const k of mine.skeletons) {
      for (const [e, theirs] of index.name.get(k) ?? [])
        if (theirs.plain !== mine.plain) alike.push(e);
      for (const [w, e, theirs] of index.wildNameByLength.get(codePoints(k)) ??
        [])
        if (theirs.plain !== mine.plain && wildMatch(w, k)) alike.push(e);
    }
    for (const w of mine.wild)
      for (const [k, e, theirs] of index.nameByLength.get(codePoints(w)) ?? [])
        if (theirs.plain !== mine.plain && wildMatch(w, k)) alike.push(e);
    if (mine.plain)
      for (const e of index.plain.get(mine.plain) ?? [])
        if (!incoming.hasAddress || !e.form.hasAddress) same.push(e);
  }
  const lookalikes = holdersOf(alike, exclude);
  const byName = holdersOf([...alike, ...same], exclude);
  if (byName.length === 0) return null;
  return lookalikes.length > 0
    ? { kind: "name", holders: byName }
    : { kind: "name", sameName: true, holders: byName };
}

/**
 * Whether `incoming` claims an identity another key holds: an address, a
 * same-reading address, a lookalike name, or the same name where one side
 * has no address. Same fingerprint is an update, never a conflict.
 *
 * With `includeRevoked`, a revoked holder is still reported when no live
 * key claims it: that is how a rotation looks, and how an impostor would
 * time it.
 */
export function identityConflict(
  incoming: IdentityHolder,
  others: readonly IdentityHolder[],
  { includeRevoked = false }: { includeRevoked?: boolean } = {},
): IdentityConflict | null {
  const id = incoming.keyId.toUpperCase();
  const form = formOf(incoming);
  return (
    claims(form, new HolderIndex(others.filter((o) => !o.revoked)), id) ??
    (includeRevoked
      ? claims(form, new HolderIndex(others.filter((o) => o.revoked)), id)
      : null)
  );
}

/** Per holder, the identity it shares with another (the contact list's
 *  marks). Only `ofInterest` (default all) get an entry. */
export function identityClashes(
  holders: readonly IdentityHolder[],
  ofInterest: (h: IdentityHolder) => boolean = () => true,
): Map<string, IdentityConflict> {
  const out = new Map<string, IdentityConflict>();
  const live = new HolderIndex(holders.filter((h) => !h.revoked));
  for (const h of holders) {
    if (h.revoked || !ofInterest(h)) continue;
    const conflict = claims(formOf(h), live, h.keyId.toUpperCase());
    if (conflict) out.set(h.keyId, conflict);
  }
  return out;
}

/** Same array, so its forms stay cached. */
function asOwn(k: IdentityHolder): IdentityHolder {
  return {
    keyId: k.keyId,
    userIds: k.userIds,
    ...(k.alias ? { alias: k.alias } : {}),
    own: true as const,
  };
}

/** Each contact against the others and the user's own keys. */
export function contactClashes(
  contacts: readonly IdentityHolder[],
  ownKeys: readonly IdentityHolder[],
): Map<string, IdentityConflict> {
  return identityClashes([...contacts, ...ownKeys.map(asOwn)], (h) => !h.own);
}

/** {@link contactClashes} for ONE contact, without building the whole map. */
export function contactClash(
  keyId: string,
  contacts: readonly IdentityHolder[],
  ownKeys: readonly IdentityHolder[],
): IdentityConflict | undefined {
  const contact = contacts.find((c) => c.keyId === keyId);
  if (!contact || contact.revoked) return undefined;
  return (
    identityConflict(contact, [...contacts, ...ownKeys.map(asOwn)]) ?? undefined
  );
}

/** 16-hex OpenPGP id, or an SSH fingerprint whole (case-sensitive). */
export function displayKeyId(keyId: string): string {
  return keyId.startsWith("SHA256:") ? keyId : keyId.slice(-16).toUpperCase();
}

const SSH_ID_SHOWN = 12;

/** Shortens an SSH fingerprint (unwrappable base64) for use in a sentence. */
export function noteKeyId(keyId: string): string {
  const id = displayKeyId(keyId);
  const prefix = "SHA256:";
  return id.startsWith(prefix) && id.length > prefix.length + SSH_ID_SHOWN
    ? `${id.slice(0, prefix.length + SSH_ID_SHOWN)}\u2026`
    : id;
}
