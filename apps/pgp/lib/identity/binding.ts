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

import { CONFUSABLE, DOT_LOOKALIKES, stripInvisible } from "../utils/lookalike";

/** Anything shaped like an address, wherever it sits in a User ID. */
const ADDRESS = /[^\s<>()[\]"',;:]+@[^\s<>()[\]"',;:]+/g;

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
  return (readableForm(userId).match(ADDRESS) ?? []).map((a) =>
    a.replace(/\.+$/, ""),
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
  return readableForm(userId)
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
  for (const ch of readableForm(text).normalize("NFKD")) {
    const mapped =
      (dots && DOT_LOOKALIKES.has(ch) ? "." : undefined) ??
      CONFUSABLE.get(ch) ??
      (ch === "I" ? capitalI : undefined);
    if (mapped !== undefined) {
      out += mapped;
      continue;
    }
    if (drops.test(ch)) continue;
    const lower = ch.toLowerCase();
    out += CONFUSABLE.get(lower) ?? lower;
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

export interface IdentityHolder {
  keyId: string;
  userIds: string[];
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
   *  address under a name that reads the same. "key": an SSH import
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
}

function claims(
  incoming: IdentityHolder,
  rivals: readonly IdentityHolder[],
): IdentityConflict | null {
  const emails = new Set(incoming.userIds.flatMap(emailsOf));
  const byAddress = rivals.filter((o) =>
    o.userIds.some((u) => emailsOf(u).some((e) => emails.has(e))),
  );
  if (byAddress.length > 0) return { kind: "address", holders: byAddress };

  const looks = new Set(
    incoming.userIds.flatMap((u) => addressesOf(u).flatMap(addressSkeletons)),
  );
  const byLookalike = rivals.filter((o) =>
    o.userIds.some((u) =>
      addressesOf(u).some((a) => addressSkeletons(a).some((k) => looks.has(k))),
    ),
  );
  if (byLookalike.length > 0) {
    return { kind: "address", lookalike: true, holders: byLookalike };
  }

  const skeletons = new Set(
    incoming.userIds.flatMap((u) => nameSkeletons(nameOf(u))),
  );
  const byName = rivals.filter((o) =>
    o.userIds.some((u) =>
      nameSkeletons(nameOf(u)).some((k) => skeletons.has(k)),
    ),
  );
  return byName.length > 0 ? { kind: "name", holders: byName } : null;
}

/**
 * Whether `incoming` claims an identity another key already holds: an
 * address (case-insensitive, anywhere in a User ID) first, then an
 * address that reads the same (`addressSkeletons`), else a name with the
 * same skeleton. The same fingerprint is never a conflict --
 * that is an update of the same key.
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
  const rivals = others.filter(
    (o) => o.keyId.toUpperCase() !== incoming.keyId.toUpperCase(),
  );
  return (
    claims(
      incoming,
      rivals.filter((o) => !o.revoked),
    ) ??
    (includeRevoked
      ? claims(
          incoming,
          rivals.filter((o) => o.revoked),
        )
      : null)
  );
}

/** For each holder, the identity it shares with another: what the
 *  contact list marks on each card, so two keys that claim one person
 *  never sit side by side looking like two people (or like one). Only
 *  `ofInterest` (default: all) get an entry; every holder counts as a
 *  rival. */
export function identityClashes(
  holders: readonly IdentityHolder[],
  ofInterest: (h: IdentityHolder) => boolean = () => true,
): Map<string, IdentityConflict> {
  const out = new Map<string, IdentityConflict>();
  for (const h of holders) {
    if (h.revoked || !ofInterest(h)) continue;
    const conflict = identityConflict(h, holders);
    if (conflict) out.set(h.keyId, conflict);
  }
  return out;
}

/** The clashes the contact list and the recipient picker mark: each
 *  contact against the other contacts and the user's own keys (a
 *  contact wearing the user's own name is the classic one). */
export function contactClashes(
  contacts: readonly IdentityHolder[],
  ownKeys: readonly IdentityHolder[],
): Map<string, IdentityConflict> {
  return identityClashes(
    [
      ...contacts,
      ...ownKeys.map((k) => ({
        keyId: k.keyId,
        userIds: k.userIds,
        own: true as const,
      })),
    ],
    (h) => !h.own,
  );
}

/** A key id as the panel shows it beside a name: the 16-hex OpenPGP key
 *  id, or an SSH fingerprint (`SHA256:` + base64) whole -- it is
 *  case-sensitive, and its tail alone is not what `ssh-keygen -l`
 *  prints. */
export function displayKeyId(keyId: string): string {
  return keyId.startsWith("SHA256:") ? keyId : keyId.slice(-16).toUpperCase();
}
