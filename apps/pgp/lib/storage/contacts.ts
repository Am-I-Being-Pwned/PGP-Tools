import type { KindDiscriminated, StoredKeyKind } from "./key-kind";
import { STORAGE_CONTACTS } from "../constants";
import { AppError } from "../errors/app-error";
import { hasContactsSession } from "../pgp/wasm";
import {
  activeRecipients,
  contactRecipients,
  contactSource,
  hasActiveRecipient,
  isRecipientDisabled,
} from "./contact-recipients";
import {
  loadEncryptedArray,
  normalizePadding,
  saveEncryptedArray,
} from "./encrypted-store";
import { withLock } from "./engine";
import { recordRevoked, revokedFloor } from "./integrity";
import { isSshRecord, storedKeyKind } from "./key-kind";

// Pure readers of a contact record, kept in a module with no store (and
// so no wasm) behind it: the reader tab renders ContactCard, and must not
// pull the store in to do it. Re-exported so callers keep importing them
// from here.
export {
  activeRecipients,
  contactRecipients,
  contactSource,
  hasActiveRecipient,
  isRecipientDisabled,
};

/**
 * One key belonging to a contact.
 *
 * A person is not a key. A GitHub user commonly has three SSH keys --
 * laptop, desktop, phone -- and you cannot know which of them is on the
 * machine they happen to be reading from. age encrypts to N recipients
 * natively and any one identity decrypts, so the correct behaviour is to
 * encrypt to ALL of a contact's keys (~100 bytes of stanza each), not to
 * guess one. There is deliberately no primary/default recipient anywhere
 * in this design: nothing to store, nothing to migrate, no UI to change
 * it, and no wrong-key failure mode.
 */
export interface ContactRecipient {
  /** Fingerprint of THIS key (not of the contact record). */
  keyId: string;
  /** The exact bytes handed to the engine as a recipient. */
  armored: string;
  algorithm: string;
  /** The user has turned this key OFF: it stays on the record, stays
   *  listed in the UI, and is skipped when assembling recipients (an old
   *  key they no longer trust, say).
   *
   *  ABSENT MEANS ENABLED -- the same convention as `kind` and
   *  `recipients`. `false` is NEVER written: a contact with nothing
   *  disabled must serialise byte-for-byte the way it did before this
   *  field existed, so no record is rewritten and an older build reads
   *  every one of them. Read it through {@link isRecipientDisabled},
   *  write it through {@link disabledField}, and never touch the
   *  property directly -- the discipline `storedKeyKind` enforces for
   *  `kind`.
   *
   *  A downgrade to an older build simply ignores it and encrypts to
   *  every key, which is the pre-feature behaviour: degraded, not
   *  broken -- and never the reverse (encrypting to nobody). */
  disabled?: true;
}

/**
 * Where a multi-key contact came from, when it was fetched rather than
 * hand-supplied. This is the contact's IDENTITY for upsert purposes --
 * see {@link sameSource}.
 */
export interface ContactSource {
  /** Which lookup produced this contact. Part of the composite identity
   *  `sameSource` compares, so a keyserver query and a GitHub account
   *  name that happen to read the same are never the same person. */
  type: "github" | "keyserver";
  /** The lookup's own identity for this person: a GitHub account name,
   *  or the canonical keyserver query (a lowercased address, or an
   *  uppercase fingerprint). NOT a fingerprint for either -- see
   *  `sameSource` for why the key is the wrong identity here. */
  user: string;
  fetchedAt: number;
}

/** Bumped when the engine changes what a contact's identity fields mean.
 *  1: `userIds` are bound, unrevoked User IDs only (an unsigned User ID
 *  appended to a real cert used to be listed, and named the contact);
 *  `revoked` and `lookalike` are recorded. Older records are re-derived
 *  once by the contacts hook. */
export const IDENTITY_VERSION = 1;

export interface PublicContactKey extends KindDiscriminated {
  /** Id of the contact RECORD: the picker's selection id, the store's
   *  upsert key, the fingerprint history references. It happens to equal
   *  `recipients[0].keyId`, but it is NOT "the key we encrypt to" -- a
   *  contact may hold several. Read the encryption targets through
   *  {@link contactRecipients}, never from this field.
   *
   *  For a single-key contact (every contact that exists today) it is the
   *  OpenPGP fingerprint, or the OpenSSH `SHA256:...` fingerprint for an
   *  `ssh` contact. */
  keyId: string;
  /** OpenPGP User IDs. An SSH recipient has none -- its key comment
   *  (`user@host`) is stored as the sole element, or the list is empty
   *  when the key carries no comment. */
  userIds: string[];
  /** Local, user-set display name -- the contact sibling of
   *  `ProtectedKeyBlob.alias`. Never touches the key: the User IDs (or
   *  the SSH comment) remain the identity, this is only what the UI
   *  shows.
   *
   *  ABSENT MEANS "fall back to the derived name", the same convention
   *  as `kind`, `recipients` and `disabled`. `""` is NEVER written -- a
   *  contact with no alias must serialise byte-for-byte the way it did
   *  before this field existed, so no record is rewritten and an older
   *  build reads every one of them. Read it through `displayUserId`
   *  (`lib/utils/key-naming.ts`), which every name this app shows goes
   *  through, and write it through {@link aliasField} /
   *  {@link withAlias}. */
  alias?: string;
  algorithm: string;
  /** Armored cert for a `pgp` contact; the canonical `<type> <base64>`
   *  recipient line for an `ssh` one. Either way, the exact bytes handed
   *  to the engine as a recipient. */
  armoredPublicKey: string;
  addedAt: number;
  lastUsedAt: number;
  expiresAt?: number | null;
  /** Whether this contact can be encrypted to (has a usable encryption
   *  key). False for sign-only keys, which are still valid contacts for
   *  signature verification but must not appear as encryption recipients.
   *  `undefined` on legacy records until backfilled -- treat as `true`. */
  usableForEncryption?: boolean;
  /** Non-blocking flag from key parsing (e.g. relies on a SHA-1 binding
   *  signature). Shown as a warning badge; the key is still usable. */
  securityWarning?: string;
  /** The owner revoked this key. Kept, so the revocation sticks against a
   *  later stale re-import, but shown as revoked and never encrypted to.
   *  WRITTEN ONLY WHEN TRUE. */
  revoked?: boolean;
  /** A User ID mixes lookalike alphabets (`securityWarning` says so).
   *  WRITTEN ONLY WHEN TRUE. */
  lookalike?: boolean;
  /** Which {@link IDENTITY_VERSION} last derived
   *  `userIds` / `revoked` / `lookalike`. Absent on older records, which
   *  the contacts hook re-derives once. */
  identityVersion?: number;
  /** The user compared this key's fingerprint with its owner and marked
   *  it verified. WRITTEN ONLY WHEN TRUE; dropped when the key changes. */
  verified?: true;
  /** When it was marked verified (ms since epoch). */
  verifiedAt?: number;
  /** Fingerprints this contact used before its key was replaced on the
   *  import Review, newest first. */
  previousKeyIds?: string[];
  /** Every key this contact holds -- WRITTEN ONLY WHEN THERE IS MORE
   *  THAN ONE. Absent means "the single key in the top-level fields",
   *  exactly the way an absent `kind` means `"pgp"` (see `key-kind.ts`).
   *  Read it through {@link contactRecipients}, never directly, and
   *  write it through {@link recipientsField}.
   *
   *  When present, `recipients[0]` MUST agree with `keyId` and
   *  `armoredPublicKey` -- `repairContact` restores that on every load,
   *  rather than the store rejecting (and so deleting) the record. That is
   *  what makes the migration two-directional: an older build ignores
   *  this field, sees one valid fingerprint and one valid recipient
   *  line, and encrypts to the person's first key. Degraded, not
   *  broken. */
  recipients?: ContactRecipient[];
  /** Absent on a hand-supplied contact, which is every contact written
   *  before this field existed. Read through {@link contactSource}. */
  source?: ContactSource;
}

/** True when `v` looks like a stored {@link ContactRecipient}.
 *
 *  `disabled` is deliberately NOT validated: a record carrying a stray
 *  `disabled: false` (which this build never writes) is a contact the
 *  user still wants, and rejecting it here would silently drop the whole
 *  person. `isRecipientDisabled` reads strictly instead, so anything
 *  that is not exactly `true` means enabled. */
function isContactRecipient(v: unknown): v is ContactRecipient {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.keyId === "string" &&
    typeof o.armored === "string" &&
    typeof o.algorithm === "string"
  );
}

function isValidContact(v: unknown): v is PublicContactKey {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  if (
    typeof o.keyId !== "string" ||
    typeof o.armoredPublicKey !== "string" ||
    !Array.isArray(o.userIds)
  ) {
    return false;
  }
  // `recipients` is deliberately NOT validated here, for the same reason
  // `isContactRecipient` ignores a stray `disabled: false`: this
  // predicate is the filter `loadEncryptedArray` applies, so a `false`
  // returned here does not mean "ignore this field" -- it means the whole
  // PERSON disappears from the list, and the next write persists that
  // filtered array. Silent, permanent deletion of a record whose `keyId`
  // and `armoredPublicKey` were independently fine.
  //
  // The head-agreement invariant still has to hold (an older build reads
  // only the top-level fields, so a disagreeing head would silently
  // encrypt to a key this build never lists) -- it is enforced by
  // REPAIRING the record on the way out of storage instead. See
  // {@link repairContact}.
  return true;
}

/**
 * A loaded record with its `recipients` list forced back into agreement
 * with the top-level fields -- the read-side half of the head-agreement
 * invariant, and the reason `isValidContact` does not enforce it.
 *
 * Repair rather than reject. Every way a `recipients` list can be wrong
 * (a junk entry, an empty array, a head that names some other key) leaves
 * `keyId` and `armoredPublicKey` independently valid, so the record is
 * still a contact the user knows -- and dropping it would take the whole
 * person with it, permanently, on the next write.
 *
 * The top-level fields WIN, because they are what an older build (and
 * every downgrade path) reads. A list whose head merely sits in the wrong
 * position is re-headed, keeping every key; otherwise the record's own
 * key is put at the head and any entry claiming that fingerprint with
 * different bytes is dropped, since exactly one of the two can be right
 * and the top-level copy is the one already in use.
 *
 * Returns the record UNTOUCHED when there is nothing to repair, so a
 * healthy contact is never rewritten (and never re-serialised).
 */
function repairContact(contact: PublicContactKey): PublicContactKey {
  const stored: unknown = contact.recipients;
  if (stored === undefined) return contact;

  const raw: unknown[] = Array.isArray(stored) ? stored : [];
  const list = raw.filter(isContactRecipient);
  const agrees = (r: ContactRecipient) =>
    r.keyId === contact.keyId && r.armored === contact.armoredPublicKey;

  // Already sound, and nothing was filtered out: leave it exactly as it
  // was read.
  if (list.length === raw.length && list.length > 0 && agrees(list[0])) {
    return contact;
  }

  const restored = list.find(agrees) ?? {
    keyId: contact.keyId,
    armored: contact.armoredPublicKey,
    algorithm: contact.algorithm,
  };
  return withRecipients(contact, [
    restored,
    ...list.filter((r) => r !== restored && r.keyId !== contact.keyId),
  ]);
}

/**
 * The `recipients` field as it should be WRITTEN, spread into a new
 * record -- the counterpart to `kindField`.
 *
 * Returns `{}` for a single key, so a one-key contact serialises
 * byte-for-byte as it does today: zero migration, zero rewrite, and an
 * older build still reads every record. The caller is responsible for
 * `list[0]` matching the record's `keyId`/`armoredPublicKey`.
 *
 * Except a single key the user turned OFF: the top-level fields have
 * nowhere to say so, and dropping the flag would turn the key back on
 * (a refresh that left only that key used to do exactly this). An older
 * build reads the one-entry list and ignores the flag, which is the
 * pre-feature behaviour, as for every other disabled key.
 */
export function recipientsField(list: readonly ContactRecipient[]): {
  recipients?: ContactRecipient[];
} {
  return list.length > 1 || list.some(isRecipientDisabled)
    ? { recipients: [...list] }
    : {};
}

/**
 * A contact record carrying exactly `list` as its keys.
 *
 * The safe way to apply {@link recipientsField} to an EXISTING record.
 * Spreading the helper over one is not: it returns `{}` at length 1, so a
 * record that shrinks back to a single key would keep its old
 * `recipients` array verbatim -- the field would say two keys while the
 * top-level fields say one. Nothing shrinks a list today, which is
 * exactly why the contract has to be enforced somewhere rather than
 * remembered.
 *
 * The field is dropped and re-appended rather than assigned in place, so
 * a single-key record comes out byte-identical to one that never had the
 * field at all.
 */
export function withRecipients(
  contact: PublicContactKey,
  list: readonly ContactRecipient[],
): PublicContactKey {
  const { recipients: _dropped, ...rest } = contact;
  return { ...rest, ...recipientsField(list) };
}

/**
 * The `alias` field as it should be WRITTEN, spread into a new record --
 * the counterpart to `recipientsField` and `disabledField`.
 *
 * Trimmed, and `{}` when what is left is empty, so clearing a name
 * REMOVES the field rather than storing `""`: a contact with no alias
 * serialises byte-for-byte as it did before the field existed. The same
 * trim-to-undefined rule `updateAlias` keeps for the user's own keys.
 */
export function aliasField(alias: string): { alias?: string } {
  const trimmed = alias.trim();
  return trimmed ? { alias: trimmed } : {};
}

/**
 * A contact record carrying `alias` as its display name, or none.
 *
 * The safe way to apply {@link aliasField} to an EXISTING record, for
 * the same reason {@link withRecipients} exists: spreading the helper
 * over one returns `{}` when the name is cleared, so the old alias would
 * simply survive. The field is dropped and re-appended rather than
 * assigned, so a cleared record comes out identical to one that never
 * had a name.
 */
export function withAlias(
  contact: PublicContactKey,
  alias: string,
): PublicContactKey {
  const { alias: _dropped, ...rest } = contact;
  return { ...rest, ...aliasField(alias) };
}

/**
 * The `disabled` flag as it should be WRITTEN, spread into a new
 * recipient -- the counterpart to `recipientsField` and `kindField`.
 *
 * Returns `{}` when the key is enabled, so a contact with nothing turned
 * off serialises byte-for-byte as it did before this field existed:
 * zero migration, zero rewrite, and an older build still reads every
 * record. `disabled: false` is never written.
 */
export function disabledField(disabled: boolean): { disabled?: true } {
  return disabled ? { disabled: true } : {};
}

/**
 * The recipient list with one key turned on or off, ready to store.
 *
 * Rebuilds the touched entry field-by-field rather than spreading over
 * it, so re-enabling REMOVES `disabled` instead of writing `false` --
 * the byte-identity rule above only holds if there is no way to leave
 * the field behind. Order is preserved, so `recipients[0]` keeps
 * agreeing with the record's `keyId`/`armoredPublicKey`
 * ({@link isValidContact}).
 */
export function withRecipientDisabled(
  list: readonly ContactRecipient[],
  keyId: string,
  disabled: boolean,
): ContactRecipient[] {
  return list.map((r) =>
    r.keyId === keyId
      ? {
          keyId: r.keyId,
          armored: r.armored,
          algorithm: r.algorithm,
          ...disabledField(disabled),
        }
      : r,
  );
}

/**
 * Whether two contacts denote the same fetched person.
 *
 * False whenever either side has no source: an absent source means
 * "hand-supplied", which is not an identity and must never collide --
 * two source-less contacts are two contacts, full stop.
 *
 * This exists because `keyId` alone is not a stable identity for a
 * fetched contact. Delete your first GitHub key and `recipients[0]`
 * changes, so `keyId` changes, and a keyId-only upsert would file the
 * next fetch as a SECOND contact for the same person.
 */
export function sameSource(
  a: Pick<PublicContactKey, "source">,
  b: Pick<PublicContactKey, "source">,
): boolean {
  const sa = contactSource(a);
  const sb = contactSource(b);
  if (sa === null || sb === null) return false;
  // Compared as one composite key rather than field-by-field so a second
  // source type can never silently collide with a github user of the
  // same name. NUL cannot occur in either half.
  return `${sa.type}\u0000${sa.user}` === `${sb.type}\u0000${sb.user}`;
}

// AES-256-GCM encrypted blob via WASM contacts session key.
// Same scheme as the keyring — see encrypted-store.ts.
const CONTACTS_STORE = {
  storageKey: STORAGE_CONTACTS,
  isValid: isValidContact,
  label: "contacts",
};

export async function loadContacts(): Promise<PublicContactKey[]> {
  // Repaired on the way out, never rejected -- see `repairContact`. This
  // is the ONLY read path: every mutation below re-loads through it, so
  // nothing writes back a record it has not first put in order.
  const contacts = (await loadEncryptedArray(CONTACTS_STORE)).map(
    repairContact,
  );
  return applyRevocationFloor(contacts);
}

/**
 * `contacts` with every record this device has ever seen revoked put back
 * to revoked -- and unusable for encryption -- and any newly revoked
 * record added to the floor.
 *
 * The floor lives in the integrity ledger, NOT in this blob, which is the
 * point: writing back an older, validly sealed contacts blob (from before
 * the revocation) used to un-revoke the contact, and the pre-revocation
 * armor it carries still encrypts. Both flags are forced, because the
 * encrypt path filters on `usableForEncryption` and the stale armor
 * would otherwise still read as usable. Records already marked revoked
 * are returned untouched, so a healthy record is never rewritten. See
 * `integrity.ts`.
 */
async function applyRevocationFloor(
  contacts: PublicContactKey[],
): Promise<PublicContactKey[]> {
  if (contacts.length === 0) return contacts;
  const floor = await revokedFloor();
  await recordRevoked(
    contacts
      .filter((c) => c.revoked && !floor.has(c.keyId))
      .map((c) => c.keyId),
  );
  return contacts.map((c) =>
    !c.revoked && floor.has(c.keyId)
      ? { ...c, revoked: true, usableForEncryption: false }
      : c,
  );
}

/** The contacts belonging to one engine. Legacy records carry no `kind`
 *  and are PGP by definition -- see `key-kind.ts`. A caller that needs
 *  recipients for an encrypt MUST narrow this way: age and OpenPGP
 *  recipients cannot be combined in one message (see
 *  `lib/encrypt-recipients.ts`). */
export function contactsOfKind(
  contacts: readonly PublicContactKey[],
  kind: StoredKeyKind,
): PublicContactKey[] {
  return contacts.filter((c) => storedKeyKind(c) === kind);
}

/** Seal the whole list. The revocation floor is applied on the way IN
 *  as well as out, so a mutation that rebuilds a record from a stale copy
 *  (a re-import of the pre-revocation cert) can't persist it unrevoked. */
async function saveAll(contacts: PublicContactKey[]): Promise<void> {
  await saveEncryptedArray(
    CONTACTS_STORE,
    await applyRevocationFloor(contacts),
  );
}

/** One-time upgrade of a contacts blob to canonical padding and to the
 *  domain-bound sealing envelope. */
export function normalizeContactsPadding(): Promise<void> {
  return normalizePadding(CONTACTS_STORE);
}

/**
 * Serialize a read-modify-write of the whole blob, with the session
 * checked INSIDE the lock, immediately before the read.
 *
 * Both halves are load-bearing, and contacts had neither until they
 * destroyed data:
 *
 *  - the GUARD, because `loadEncryptedArray` returns `[]` with no
 *    contacts session -- indistinguishable from an empty store. An
 *    unguarded delete computes "nothing left", takes the empty-store
 *    shortcut and `removeItem`s the sealed blob: every contact the user
 *    has, gone, without the vault ever being opened. That is reachable
 *    on the ordinary auto-lock path, because `doMasterLock` drops the
 *    contacts session without awaiting it, so a mutation already queued
 *    behind the UI's mutex runs after the session is gone. Identical in
 *    shape to the keyring bug -- see `keyring.ts`'s `removeKey` -- and
 *    to the `requireSession` the CRX store has always carried.
 *  - the LOCK, because load+save rewrites the entire array, so two
 *    interleaved mutations silently drop one side's write. The UI's own
 *    mutex does not cover this: the recipient toggle reaches the store
 *    from a different component entirely.
 *
 * Checked inside the lock rather than before it so the vault cannot lock
 * between the check and the write. `MutationGuard` in
 * `protected-store.ts` is the same idea for the generic stores.
 */
async function mutateContacts<T>(
  fn: (contacts: PublicContactKey[]) => Promise<T>,
): Promise<T> {
  return withLock(STORAGE_CONTACTS, async () => {
    if (!(await hasContactsSession())) {
      throw new AppError(
        "vault-locked",
        "Cannot change contacts: the vault is locked",
      );
    }
    return fn(await loadContacts());
  });
}

/**
 * The stored list after upserting `incoming` -- pure, and the SINGLE
 * definition of the upsert rules.
 *
 * Shared with `useContacts`, whose optimistic update has to reach the
 * same answer this does: the list on screen is what the recipient picker
 * offers, so a weaker rule there does not merely look wrong.
 *
 * Three rules, each of which exists because getting it wrong loses
 * something:
 *
 *  - identity is the SOURCE when there is one, the record id otherwise
 *    (see `sameSource`). Dropping by keyId alone would leave a stale
 *    duplicate whenever a fetched contact's first key was deleted
 *    upstream, because its keyId moves to the next key.
 *  - a source-less contact NEVER supersedes a fetched one it merely
 *    collides with by keyId. Pasting one of a GitHub contact's keys by
 *    hand is not a reason to replace that person's record and silently
 *    drop their other keys; the key is already a recipient of that
 *    contact, so the richer record simply stands.
 *  - `disabled` survives a refresh, for every member still present. It
 *    is the one field on a contact carrying a SECURITY decision, and a
 *    re-fetch builds its record purely from what GitHub just returned --
 *    so without this, refreshing a contact silently starts encrypting to
 *    a key the user deliberately turned off. Making it a storage
 *    invariant rather than a caller's responsibility is the point: no
 *    fetch path can forget it. `addedAt` is carried forward with it,
 *    which is merely cosmetic -- "known since" should not restart
 *    because the contact was refreshed.
 */
/** `record` with the key material and the fields derived from it taken
 *  from `incoming`; its identity (source, alias, recipients) kept. */
function withKeyFrom(
  record: PublicContactKey,
  incoming: PublicContactKey,
): PublicContactKey {
  const {
    revoked: _revoked,
    lookalike: _lookalike,
    securityWarning: _warning,
    ...rest
  } = record;
  return {
    ...rest,
    armoredPublicKey: incoming.armoredPublicKey,
    userIds: incoming.userIds,
    expiresAt: incoming.expiresAt,
    usableForEncryption: incoming.usableForEncryption,
    ...(incoming.securityWarning
      ? { securityWarning: incoming.securityWarning }
      : {}),
    ...(incoming.revoked ? { revoked: true } : {}),
    ...(incoming.lookalike ? { lookalike: true } : {}),
    ...(incoming.identityVersion !== undefined
      ? { identityVersion: incoming.identityVersion }
      : {}),
  };
}

export function upsertContacts(
  existing: readonly PublicContactKey[],
  incoming: PublicContactKey,
): PublicContactKey[] {
  const superseded = existing.filter(
    (c) => c.keyId === incoming.keyId || sameSource(c, incoming),
  );

  // A hand-pasted key that happens to be a fetched contact's head: keep
  // the person intact. But a newer copy of that SAME PGP key -- its
  // owner's revocation, an extended expiry -- still lands on the record:
  // callers hand in the merge of the stored and the incoming copy, so
  // this only ever adds what the owner signed. Without it, a revocation
  // sent by email could never reach a contact found on a keyserver.
  if (
    contactSource(incoming) === null &&
    superseded.some((c) => contactSource(c) !== null)
  ) {
    const fetched = superseded.find(
      (c) =>
        c.keyId === incoming.keyId &&
        contactSource(c) !== null &&
        !isSshRecord(c) &&
        !isSshRecord(incoming),
    );
    if (!fetched) return [...existing];
    return existing.map((c) =>
      c === fetched ? withKeyFrom(fetched, incoming) : c,
    );
  }

  const record =
    superseded.length > 0 ? carryForward(superseded[0], incoming) : incoming;
  return [...existing.filter((c) => !superseded.includes(c)), record];
}

/** The fingerprints a record holds, as one comparable string. */
function keySet(contact: PublicContactKey): string {
  return contactRecipients(contact)
    .map((r) => r.keyId)
    .sort()
    .join(" ");
}

/** `incoming`, with the user's decisions from the record it replaces:
 *  `disabled` for every key still present, and the original `addedAt`.
 *
 *  Only from the SAME record -- the same source, or two source-less
 *  records upserting by key. Two different GitHub accounts publishing
 *  one key collide here by keyId alone, and neither a disable decision
 *  nor a "known since" date should cross between them.
 *
 *  And the NAME and "verified" only from the same PERSON, which a key id
 *  alone does not establish. A record's id is its first key, so a pasted
 *  `.pub` file pairing Alice's key with Mallory's lands on Alice by id;
 *  carrying her alias across made "Alice" a contact that encrypts to
 *  Mallory as well. So, matched by id, the user's name for the record
 *  survives only when the incoming key SET is the one they named. Matched
 *  by source -- a re-fetch of the same account, which is what they named
 *  -- it survives a change of keys, as it always has. "Verified" needs
 *  the same head and the same set either way: what the user compared was
 *  those keys. (A set that grew by id only reaches here through the
 *  import Review, which says so and starts that row on Skip.) */
function carryForward(
  previous: PublicContactKey,
  incoming: PublicContactKey,
): PublicContactKey {
  const bySource = sameSource(previous, incoming);
  const sameRecord =
    bySource ||
    (contactSource(previous) === null && contactSource(incoming) === null);
  if (!sameRecord) return incoming;
  const sameKeys = keySet(previous) === keySet(incoming);
  const samePerson = bySource || sameKeys;

  const off = new Set(
    contactRecipients(previous)
      .filter(isRecipientDisabled)
      .map((r) => r.keyId),
  );
  // Untouched when nothing was off, so a refreshed contact with no
  // disable decision on it serialises exactly as the fetch built it.
  // Every remaining key can be one the user turned off -- the account
  // deleted the ones they kept -- and then that is what is saved: a
  // contact with nothing to encrypt to (see `activeRecipients`), never
  // one quietly encrypting to the keys they ruled out. A contact down to
  // one such key keeps a one-entry list to carry the flag
  // (`recipientsField`). The import Review asks before it gets here
  // (`allKeysOff`).
  const merged =
    off.size === 0
      ? incoming
      : withRecipients(
          incoming,
          contactRecipients(incoming).map((r) => ({
            keyId: r.keyId,
            armored: r.armored,
            algorithm: r.algorithm,
            ...disabledField(isRecipientDisabled(r) || off.has(r.keyId)),
          })),
        );
  // The same KEY refreshed keeps what the user decided about it: its
  // local name, and that they verified it. A different key never
  // inherits "verified" -- nor does a group that gained or lost a key:
  // what the user compared was the old set.
  const sameKey = previous.keyId === incoming.keyId && sameKeys;
  return {
    ...merged,
    addedAt: previous.addedAt,
    ...(samePerson && previous.alias && merged.alias === undefined
      ? { alias: previous.alias }
      : {}),
    ...(sameKey && previous.verified
      ? { verified: true as const, verifiedAt: previous.verifiedAt }
      : {}),
  };
}

export async function saveContact(contact: PublicContactKey): Promise<void> {
  await mutateContacts(async (existing) => {
    await saveAll(upsertContacts(existing, contact));
  });
}

/**
 * Who hears about a record changed in place.
 *
 * `useContacts` holds the list the Keys tab and the recipient picker
 * render, and most writes go through it. The recipient toggle does not:
 * it is reached from the details page, which can be opened from places
 * that have no handle on the hook (the workspace's picker, the details
 * button). Without this, the list on screen kept the record as it was
 * before the toggle -- so the card showed every key on, a GitHub refresh
 * was classified against keys that were no longer off (and never asked
 * about an account down to only those), and the refreshed record put on
 * screen dropped the flag the store had just carried forward. Fired
 * after the write commits, with the record as it is on disk.
 */
type ContactUpdateListener = (contact: PublicContactKey) => void;
const updateListeners = new Set<ContactUpdateListener>();

/** Hear about every in-place change to one record ({@link updateContact},
 *  {@link updateContactAsync} and everything built on them). Returns the
 *  unsubscribe. */
export function onContactUpdated(listener: ContactUpdateListener): () => void {
  updateListeners.add(listener);
  return () => {
    updateListeners.delete(listener);
  };
}

function notifyUpdated(contact: PublicContactKey | undefined): void {
  if (!contact) return;
  for (const listener of updateListeners) listener(contact);
}

/**
 * Mutate one stored contact in place and save.
 *
 * `apply` runs INSIDE the lock, on the record as it is on disk right
 * now, so a caller can never write back a snapshot it captured earlier
 * (and with it, whatever else has changed on that record since).
 * Returns the updated record, or undefined when no contact has that id.
 */
export async function updateContact(
  keyId: string,
  apply: (contact: PublicContactKey) => PublicContactKey,
): Promise<PublicContactKey | undefined> {
  const updated = await mutateContacts(async (existing) => {
    const index = existing.findIndex((c) => c.keyId === keyId);
    if (index === -1) return undefined;
    const updated = apply(existing[index]);
    const next = [...existing];
    next[index] = updated;
    await saveAll(next);
    return updated;
  });
  notifyUpdated(updated);
  return updated;
}

/**
 * {@link updateContact} for a change that has to await -- a merge in the
 * engine. Still applied INSIDE the lock to the record as it is on disk,
 * so a write that started from an older copy (a keyserver check that
 * took a while) can never put that copy back. Resolves undefined, and
 * writes nothing, when the contact no longer exists.
 */
export async function updateContactAsync(
  keyId: string,
  apply: (contact: PublicContactKey) => Promise<PublicContactKey>,
): Promise<PublicContactKey | undefined> {
  const updated = await mutateContacts(async (existing) => {
    const index = existing.findIndex((c) => c.keyId === keyId);
    if (index === -1) return undefined;
    const updated = await apply(existing[index]);
    const next = [...existing];
    next[index] = updated;
    await saveAll(next);
    return updated;
  });
  notifyUpdated(updated);
  return updated;
}

/**
 * Turn one of a contact's keys on or off.
 *
 * A whole-record `saveContact` would do it too, and that is exactly what
 * this exists to stop: the caller is a details page holding a contact
 * captured when it mounted, so saving the spread of that snapshot
 * republishes every other field as it was at mount. Re-reading inside
 * the lock touches `recipients` and nothing else.
 */
export async function setContactRecipientDisabled(
  contactKeyId: string,
  recipientKeyId: string,
  disabled: boolean,
): Promise<void> {
  await updateContact(contactKeyId, (contact) =>
    withRecipients(
      contact,
      withRecipientDisabled(
        contactRecipients(contact),
        recipientKeyId,
        disabled,
      ),
    ),
  );
}

/** Mark a contact's key verified (the user compared its fingerprint with
 *  the owner), or clear that. Only the flag and its date change. */
export async function setContactVerified(
  keyId: string,
  verified: boolean,
): Promise<void> {
  await updateContact(keyId, (contact) => {
    const { verified: _v, verifiedAt: _at, ...rest } = contact;
    return verified
      ? { ...rest, verified: true, verifiedAt: Date.now() }
      : rest;
  });
}

/**
 * Set (or clear, with an empty/blank value) a contact's local display
 * alias.
 *
 * Through `updateContact` rather than `saveContact` for the reason
 * `setContactRecipientDisabled` is: the caller is a rename page holding
 * the contact as it was when the page opened, and saving that snapshot
 * would republish every other field with it -- reverting, say, a
 * recipient the user turned off in between.
 */
export async function updateContactAlias(
  keyId: string,
  alias: string,
): Promise<void> {
  await updateContact(keyId, (contact) => withAlias(contact, alias));
}

export async function removeContact(keyId: string): Promise<void> {
  await mutateContacts(async (existing) => {
    // An emptied list is saved as a sealed empty array, never removed: a
    // store that is simply gone is what a deletion attack looks like
    // (`integrity.ts`). Only reachable with a live session, so an empty
    // result really is an empty store -- see `mutateContacts`.
    await saveAll(existing.filter((c) => c.keyId !== keyId));
  });
}
