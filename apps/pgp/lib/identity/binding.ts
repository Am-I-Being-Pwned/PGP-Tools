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

/** Anything shaped like an address, wherever it sits in a User ID. */
const ADDRESS = /[^\s<>()[\]"',;:]+@[^\s<>()[\]"',;:]+/g;

/**
 * Every address a User ID shows, lower-cased. Not just the canonical
 * trailing "<a@b>": "Alice alice@x", "Alice <alice@x> (work)" and
 * "Alice <alice@x" display that address just as plainly, so they claim
 * it just as much.
 */
export function emailsOf(userId: string): string[] {
  return [
    ...new Set(
      (userId.match(ADDRESS) ?? []).map((a) =>
        a.replace(/\.+$/, "").toLowerCase(),
      ),
    ),
  ];
}

/** The first address in a User ID (see `emailsOf`), or null. */
export function emailOf(userId: string): string | null {
  return emailsOf(userId)[0] ?? null;
}

/** The name part of a User ID: "Carol Lane" from "Carol Lane <c@d>",
 *  "Carol Lane c@d" or "Carol Lane (work) <c@d>" -- every bracketed
 *  group and address taken out, wherever it is. */
export function nameOf(userId: string): string {
  return userId
    .replace(/<[^<>]*>?/g, " ")
    .replace(/\([^()]*\)?/g, " ")
    .replace(ADDRESS, " ")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Letters that render like a Latin letter without being one, mapped to
 * it -- a hand-picked subset of the Unicode confusables data (UTS #39)
 * covering the scripts that imitate Latin names in practice: Cyrillic,
 * Greek, and the Latin look-alikes. Digits and pipes that pass for
 * letters ("Car0l", "|ane") are folded the same way.
 */
const CONFUSABLE = new Map<string, string>([
  ["\u0030", "o"],
  ["\u0031", "l"],
  ["\u007c", "l"],
  ["\u0131", "i"],
  ["\u01c0", "l"],
  ["\u0251", "a"],
  ["\u0261", "g"],
  ["\u0269", "i"],
  ["\u0391", "a"],
  ["\u0392", "b"],
  ["\u0395", "e"],
  ["\u0396", "z"],
  ["\u0397", "h"],
  ["\u0399", "i"],
  ["\u039a", "k"],
  ["\u039c", "m"],
  ["\u039d", "n"],
  ["\u039f", "o"],
  ["\u03a1", "p"],
  ["\u03a4", "t"],
  ["\u03a5", "y"],
  ["\u03a7", "x"],
  ["\u03b1", "a"],
  ["\u03b9", "i"],
  ["\u03ba", "k"],
  ["\u03bd", "v"],
  ["\u03bf", "o"],
  ["\u03c1", "p"],
  ["\u03c4", "t"],
  ["\u03c5", "u"],
  ["\u03c7", "x"],
  ["\u0405", "s"],
  ["\u0406", "i"],
  ["\u0408", "j"],
  ["\u0410", "a"],
  ["\u0412", "b"],
  ["\u0415", "e"],
  ["\u041a", "k"],
  ["\u041c", "m"],
  ["\u041d", "h"],
  ["\u041e", "o"],
  ["\u0420", "p"],
  ["\u0421", "c"],
  ["\u0422", "t"],
  ["\u0423", "y"],
  ["\u0425", "x"],
  ["\u0430", "a"],
  ["\u0432", "b"],
  ["\u0435", "e"],
  ["\u043a", "k"],
  ["\u043c", "m"],
  ["\u043d", "h"],
  ["\u043e", "o"],
  ["\u0440", "p"],
  ["\u0441", "c"],
  ["\u0442", "t"],
  ["\u0443", "y"],
  ["\u0445", "x"],
  ["\u0455", "s"],
  ["\u0456", "i"],
  ["\u0457", "i"],
  ["\u0458", "j"],
  ["\u0491", "r"],
  ["\u04c0", "l"],
  ["\u04cf", "l"],
  ["\u0501", "d"],
  ["\u051b", "q"],
  ["\u051d", "w"],
  ["\u1d00", "a"],
  ["\u0262", "g"],
  ["\u0274", "n"],
  ["\u0280", "r"],
  ["\u028f", "y"],
  ["\u0299", "b"],
  ["\u029c", "h"],
  ["\u029f", "l"],
  ["\u026a", "i"],
  ["\u1d04", "c"],
  ["\u1d05", "d"],
  ["\u1d07", "e"],
  ["\u1d0a", "j"],
  ["\u1d0b", "k"],
  ["\u1d0d", "m"],
  ["\u1d0f", "o"],
  ["\u1d18", "p"],
  ["\u1d1b", "t"],
  ["\u1d1c", "u"],
  ["\u1d20", "v"],
  ["\u1d21", "w"],
  ["\u1d22", "z"],
  ["\ua731", "s"],
  ["\u212a", "k"],
  ["\u212b", "a"],
]);

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
  let out = "";
  for (const ch of name.normalize("NFKD")) {
    const mapped = CONFUSABLE.get(ch) ?? (ch === "I" ? capitalI : undefined);
    if (mapped !== undefined) {
      out += mapped;
      continue;
    }
    if (
      /[\p{M}\p{Cf}\p{Default_Ignorable_Code_Point}\p{P}\p{S}\p{Z}\s]/u.test(ch)
    )
      continue;
    const lower = ch.toLowerCase();
    out += CONFUSABLE.get(lower) ?? lower;
  }
  for (const [pair, letter] of PAIRS) out = out.replace(pair, letter);
  return out;
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
   *  address under a name that reads the same. */
  kind: "address" | "name";
  /** Who already holds it -- revoked keys only when nobody live does
   *  (see `includeRevoked`). */
  holders: IdentityHolder[];
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
 * address (case-insensitive, anywhere in a User ID) first, else a name
 * with the same skeleton. The same fingerprint is never a conflict --
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
