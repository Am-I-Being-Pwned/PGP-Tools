/**
 * Who a key claims to be, and whether another contact already claims it.
 *
 * Binding a name or an address to a key is the decision this app must
 * never make for the user. A key file is attacker-supplied text: it can
 * carry a key that copies a contact's name and email exactly, or one
 * whose name only LOOKS the same ("Саrol" with Cyrillic letters). So
 * every key an import would add is checked here against the contacts
 * already held -- and against the other keys in the same import -- and
 * the import screen asks before anything that collides is saved.
 */

import {
  CONFUSABLE,
  DOT_LOOKALIKES,
  markLookalikes,
  stripInvisible,
} from "../utils/lookalike";

/** Anything shaped like an address, wherever it sits in a User ID. */
const ADDRESS = /[^\s<>()[\]"',;:]+@[^\s<>()[\]"',;:]+/g;

/**
 * A quoted local part (`"carol"@corp.com`, RFC 5322) read as the bare
 * one. The quotes draw as two marks around the same letters, and an
 * address is compared on what it shows: left in, the quote stopped the
 * address match, so `"carol"@corp.com` claimed no address at all and
 * passed the check against carol@corp.com. A stray quote right before
 * the "@" (`carol"@corp.com`) is dropped the same way. Only a quoted
 * part with no space or bracket in it is read as one -- anything else
 * is not an address anyone types.
 */
function unquoteLocalParts(text: string): string {
  return text.replace(/"([^"\s<>@]*)"(?=@)/g, "$1").replace(/"(?=@)/g, "");
}

/**
 * A User ID as it READS, which is what two of them are compared on:
 * compatibility forms folded (NFKC: fullwidth "ａｌｉｃｅ＠" is "alice@")
 * and every character that draws nothing taken out (`INVISIBLE`: zero-
 * width and format characters, variation selectors, tag characters, the
 * Hangul fillers). "alice@corp.com" followed by U+FE0F is not a
 * different address to anyone looking at it, so it must not be a
 * different address to the conflict check either -- the engine strips
 * these from new keys, and this catches what it did not (records stored
 * before it did, text from anywhere else).
 */
export function readableForm(text: string): string {
  return stripInvisible(text.normalize("NFKC"));
}

/**
 * Every address a User ID shows, in its readable form (see
 * `readableForm`), lower-cased, trailing dots dropped. Not just the
 * canonical trailing "<a@b>": "Alice alice@x", "Alice <alice@x> (work)"
 * and "Alice <alice@x" display that address just as plainly, so they
 * claim it just as much. An address-only User ID whose name is nothing
 * but an invisible character is caught here, by its address.
 */
export function emailsOf(userId: string): string[] {
  return [...new Set(addressesOf(userId).map((a) => a.toLowerCase()))];
}

/** `emailsOf` before lower-casing: an address skeleton needs to know
 *  which letters were a capital I (see `addressSkeletons`). */
function addressesOf(userId: string): string[] {
  return (unquoteLocalParts(readableForm(userId)).match(ADDRESS) ?? []).map(
    (a) => a.replace(/[.。]+$/u, ""),
  );
}

/** The first address in a User ID (see `emailsOf`), or null. */
export function emailOf(userId: string): string | null {
  return emailsOf(userId)[0] ?? null;
}

/** The name part of a User ID: "Carol Lane" from "Carol Lane <c@d>",
 *  "Carol Lane c@d" or "Carol Lane (work) <c@d>" -- every bracketed
 *  group and address taken out, wherever it is, in its readable form
 *  (see `readableForm`), so an address hidden behind an invisible
 *  character is taken out like any other. */
export function nameOf(userId: string): string {
  return namePart(readableForm(userId));
}

/** `nameOf` without the readable form: what the User ID literally says
 *  around its addresses and brackets. */
function namePart(text: string): string {
  return unquoteLocalParts(text)
    .replace(/<[^<>]*>?/g, " ")
    .replace(/\([^()]*\)?/g, " ")
    .replace(ADDRESS, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/** Letter pairs that read as one letter at a glance ("rn" as "m"). */
const PAIRS: [RegExp, string][] = [
  [/rn/g, "m"],
  [/vv/g, "w"],
];

/**
 * The "skeleton" of a name (after UTS #39): what it looks like rather
 * than what it is. Two names with the same skeleton read the same on
 * screen. Compatibility forms are folded (fullwidth, mathematical
 * letters), accents, invisible and blank-looking characters, spaces,
 * punctuation and symbols dropped, look-alike letters mapped to Latin,
 * case ignored.
 *
 * `capitalI` says what a capital I reads as: "l" in a sans-serif face
 * ("AIice"), "i" otherwise. A name has a skeleton for each, and two
 * names clash when any pair matches (see `nameSkeletons`).
 */
export function nameSkeleton(name: string, capitalI: "i" | "l" = "i"): string {
  return skeleton(name, capitalI, NAME_DROPS);
}

/** What a name skeleton leaves out: accents (as marks, once decomposed),
 *  invisible characters, punctuation, symbols and spaces. */
const NAME_DROPS =
  /[\p{M}\p{Cf}\p{Default_Ignorable_Code_Point}\p{P}\p{S}\p{Z}\s]/u;

/** What an address skeleton leaves out: accents and invisible characters
 *  only. Its punctuation is part of what it says -- "a.lice" and "alice"
 *  are two addresses that do not read the same. */
const ADDRESS_DROPS = /[\p{M}\p{Cf}\p{Default_Ignorable_Code_Point}\s]/u;

function skeleton(
  text: string,
  capitalI: "i" | "l",
  drops: RegExp,
  dots = false,
): string {
  let out = "";
  // The same readable form addresses are compared in, then decomposed so
  // accents fall away as marks.
  // A letter drawn as a capital I (the real one, or a CONFUSABLE entry
  // mapped to "I") reads as `capitalI`.
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

/**
 * What an address LOOKS like, the way `nameSkeletons` is for a name:
 * look-alike letters mapped to Latin (and look-alike dots to a dot),
 * accents dropped, case ignored, and
 * both readings of a capital I -- local part and domain alike, so
 * "alıce@corp.com" (dotless ı) and "alice@cοrp.com" (Greek ο) both read
 * as alice@corp.com. Addresses used to be compared only exactly, and an
 * address-only User ID has no name to fall back on, so a lookalike of
 * one passed every check.
 */
export function addressSkeletons(address: string): string[] {
  return [
    ...new Set([
      skeleton(address, "i", ADDRESS_DROPS, true),
      skeleton(address, "l", ADDRESS_DROPS, true),
    ]),
  ].filter(Boolean);
}

/** Both readings of a name's capital I (see `nameSkeleton`). */
export function nameSkeletons(name: string): string[] {
  return [
    ...new Set([nameSkeleton(name, "i"), nameSkeleton(name, "l")]),
  ].filter(Boolean);
}

/** Stands in, inside a skeleton, for a letter that matches any one
 *  letter (see {@link wildSkeletons}). A private-use code point: no
 *  name contains one that means anything, and nothing drops it. */
const WILD = "";

/** A letter the CONFUSABLE table already maps: it keeps its mapping
 *  rather than going wild. */
function isMapped(c: string): boolean {
  return CONFUSABLE.has(c) || CONFUSABLE.has(c.toLowerCase());
}

/** `text` with every unexplained out-of-script letter (see
 *  `markLookalikes`) replaced by {@link WILD}, or null when it has none.
 *  `keep` says which odd letters are explained. */
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

/** Wildcard skeletons that cannot match on next to nothing: at least two
 *  real letters, and no more wildcards than real letters. */
function boundedWild(skeletons: string[]): string[] {
  return [...new Set(skeletons)].filter((k) => {
    const real = [...k].filter((c) => c !== WILD).length;
    const wilds = [...k].length - real;
    return wilds > 0 && real >= 2 && wilds <= real;
  });
}

/**
 * A name's skeletons with every unexplained out-of-script letter left
 * as a wildcard -- or none, when it has no such letter.
 *
 * The CONFUSABLE table can never be complete: Unicode has thousands of
 * letters, and one it does not list ("Ꭿlice", a Cherokee letter in a
 * Latin word) slips past the skeleton. But the highlighter already
 * points at that letter (`markLookalikes`: a word whose letters come
 * from two scripts -- ANY two, by their Unicode Script property), and a
 * word like that is not how anyone writes their own name -- the engine
 * flags such a User ID `lookalike` for the same reason. So a name that
 * would read as a holder's IF its odd letters were the holder's letters
 * at those places is treated as the lookalike it almost certainly is,
 * rather than as a stranger. Letters the table does map keep their
 * mapping; only the unexplained ones are wild.
 */
function wildSkeletons(name: string): string[] {
  const text = withWildcards(name, isMapped);
  return text === null
    ? []
    : boundedWild([nameSkeleton(text, "i"), nameSkeleton(text, "l")]);
}

/** The same for an address: "dan@corp.cⴰm" (a Tifinagh letter no table
 *  lists) reads as dan@corp.com. A look-alike dot is explained -- the
 *  address skeleton maps it to a dot. */
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

/** Whether a skeleton with wildcards (see {@link wildSkeletons}) reads
 *  as a plain one. */
function wildMatch(pattern: string, plain: string): boolean {
  const p = [...pattern];
  const q = [...plain];
  return p.length === q.length && p.every((c, i) => c === WILD || c === q[i]);
}

/** A mark that draws something (an accent): the combining grapheme
 *  joiner is a mark too, but it draws nothing, so it is not dropped as
 *  an accent -- it is a hidden difference (see `plainName`). */
const ACCENT = /^(?!\p{Default_Ignorable_Code_Point})\p{M}$/u;
const PLAIN_DROPS = /^[\p{P}\p{S}\p{Z}\s]$/u;
/** Marks a character kept whole in a plain name (see `plainName`), so it
 *  can never equal the letter it folds to. */
const KEPT = "";

/**
 * A name as it is plainly WRITTEN: accents, spacing, punctuation and
 * symbols dropped, case ignored. Nothing is mapped, no compatibility
 * form is folded, and nothing invisible is taken out.
 *
 * Accents come off by canonical decomposition (NFD): "José" is "Jose",
 * written with an accent. But NFD also REPLACES some characters
 * outright -- a "singleton" decomposition: the Kelvin sign K (U+212A)
 * becomes a plain K, the Ohm sign Ω the Greek Omega, the Angstrom sign
 * the Latin Å. Those are not accents taken off a letter; they are a
 * different character that draws like the letter, which is exactly a
 * lookalike. So a character that canonical composition does not keep
 * (NFC changes it on its own) is kept whole and marked, and a name
 * written with one is never "plainly the same" as one without.
 *
 * Two names that are equal in this form are the same name, and two
 * people may well share one: their addresses tell them apart, and a
 * warning on every "Alex Smith" would teach the user to click past the
 * one that matters. So a name only counts as a lookalike (see `claims`)
 * when its skeleton matches and this form does NOT -- when it reads as
 * the holder's name only because of a lookalike letter, a fullwidth or
 * mathematical form, a capital I standing in for an l, "rn" for "m", or
 * a character that draws nothing. The same name with NO address on one
 * side is a clash of its own: nothing tells those two apart.
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

/**
 * Whether two User IDs carry names that LOOK alike without being the
 * same name: the skeletons match (exactly, or through an out-of-script
 * letter -- see {@link wildSkeletons}) but the names as written differ
 * (see {@link plainName}).
 */
export function namesLookAlike(a: string, b: string): boolean {
  const na = nameFormOf(a);
  const nb = nameFormOf(b);
  return na !== null && nb !== null && nameLooksAlike(na, nb);
}

export interface IdentityHolder {
  keyId: string;
  userIds: string[];
  /** The user's own name for it (`PublicContactKey.alias`, a key's
   *  alias). Compared as one more name: a comment-less SSH contact the
   *  user called "Alice" is Alice to them, and a `.pub` commented
   *  "Аlice" is claiming her. */
  alias?: string;
  /** A revoked key no longer holds its address. */
  revoked?: boolean;
  /** One of the user's own keys: claimed, it is flagged like a
   *  contact's, but there is no contact to replace. */
  own?: boolean;
  /** Another key in the same import, not a stored one: nothing to
   *  replace either. */
  incoming?: boolean;
}

export interface IdentityConflict {
  /** "address": the same email as another key. "name": a different
   *  address under a name that only LOOKS like the holder's (see
   *  `namesLookAlike`), or the very same name where one side has no
   *  address to tell the two apart (`sameName`). "key": an SSH import
   *  carries a key that a contact (or the user) already holds -- it
   *  would add keys to that person, or group theirs with others. Only
   *  the import sets it (`withIdentityConflicts`); the contact list and
   *  the picker compare names and addresses. */
  kind: "address" | "name" | "key";
  /** Who already holds it -- revoked keys only when nobody live does
   *  (see `includeRevoked`). */
  holders: IdentityHolder[];
  /** For "address": the two addresses only READ the same (the same
   *  `addressSkeletons`) -- they are not one address. Never a rotation,
   *  so nothing offers to replace the holder with it. */
  lookalike?: true;
  /** For "name": every holder has the SAME name, plainly written, and
   *  this key or the holder has no address at all -- so nothing on
   *  screen tells them apart. Not a lookalike, so it is said in its own
   *  words. */
  sameName?: true;
}

/** One name a holder goes by, in every form it is compared in. */
interface NameForm {
  plain: string;
  skeletons: string[];
  wild: string[];
}

/** Everything a holder is compared on, worked out once. */
interface HolderForm {
  emails: string[];
  looks: string[];
  wildLooks: string[];
  names: NameForm[];
  /** Any address at all, on any User ID: what tells two holders of one
   *  name apart. */
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

/** Forms by User ID list: a contact list re-renders with the same
 *  records, and working every skeleton out again on each keystroke was
 *  most of what made the picker slow. Keyed on the array, which a stored
 *  record keeps until it changes, so an own key wrapped afresh for each
 *  call (see `contactClashes`) still hits. */
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
 * The rivals, indexed by every form they are compared on, so a holder is
 * checked against a list in roughly the time it takes to look its own
 * forms up -- not by comparing it with every other holder. That was
 * quadratic, and the contact list and the picker run it over every
 * contact: two seconds at 300 contacts, twenty-four at 1000.
 *
 * Wildcard skeletons (see {@link wildSkeletons}) can't be looked up by
 * value, so they are bucketed by length and matched within the bucket.
 * Only a name with an unexplained out-of-script letter has one.
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

/** The rivals hit, each once, in the order they were listed. */
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

  // A name when it LOOKS like the holder's without being it. The same
  // name, plainly written, is two people sharing one, and their
  // addresses (checked above) already tell them apart -- unless one of
  // them has no address, and then nothing does.
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
 * Whether `incoming` claims an identity another key already holds: an
 * address (case-insensitive, anywhere in a User ID) first, then an
 * address that reads the same (`addressSkeletons`), else a name that
 * looks the same without being the same (`namesLookAlike`), or the same
 * name where one of the two has no address. A holder's alias counts as
 * one of its names. The same fingerprint is never a conflict -- that is
 * an update of the same key.
 *
 * Revoked keys don't hold an identity -- unless `includeRevoked`, where
 * one is still reported when no live key claims it: a new key for the
 * address of a revoked contact is how a rotation looks, and also how an
 * impostor would time it, so the import still asks.
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

/** For each holder, the identity it shares with another: what the
 *  contact list marks on each card, so two keys that claim one person
 *  never sit side by side looking like two people (or like one). Only
 *  `ofInterest` (default: all) get an entry; every holder counts as a
 *  rival. One index for the lot (see {@link HolderIndex}). */
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

/** An own key as a rival: same User IDs (and the same array, so its
 *  forms are cached -- see `formOf`). */
function asOwn(k: IdentityHolder): IdentityHolder {
  return {
    keyId: k.keyId,
    userIds: k.userIds,
    ...(k.alias ? { alias: k.alias } : {}),
    own: true as const,
  };
}

/** The clashes the contact list and the recipient picker mark: each
 *  contact against the other contacts and the user's own keys (a
 *  contact wearing the user's own name is the classic one). */
export function contactClashes(
  contacts: readonly IdentityHolder[],
  ownKeys: readonly IdentityHolder[],
): Map<string, IdentityConflict> {
  return identityClashes([...contacts, ...ownKeys.map(asOwn)], (h) => !h.own);
}

/** {@link contactClashes} for ONE contact, by key id: what a details
 *  page or a signature card shows, without working out the whole map to
 *  read one entry of it. */
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

/** A key id as the panel shows it beside a name: the 16-hex OpenPGP key
 *  id, or an SSH fingerprint (`SHA256:` + base64) whole -- it is
 *  case-sensitive, and its tail alone is not what `ssh-keygen -l`
 *  prints. */
export function displayKeyId(keyId: string): string {
  return keyId.startsWith("SHA256:") ? keyId : keyId.slice(-16).toUpperCase();
}

/** How much of an SSH fingerprint a sentence keeps after "SHA256:". */
const SSH_ID_SHOWN = 12;

/**
 * A key id inside a sentence. An SSH fingerprint is 50 characters of
 * unbroken base64 that no line can wrap, so it pushed the rest of a
 * warning out of its row; in a sentence it is shortened, and the row
 * still shows it whole (under the name, and on hover over the note).
 */
export function noteKeyId(keyId: string): string {
  const id = displayKeyId(keyId);
  const prefix = "SHA256:";
  return id.startsWith(prefix) && id.length > prefix.length + SSH_ID_SHOWN
    ? `${id.slice(0, prefix.length + SSH_ID_SHOWN)}\u2026`
    : id;
}
