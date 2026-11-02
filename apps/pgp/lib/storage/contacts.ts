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

// Pure readers live in a store-free (wasm-free) module so the reader tab
// can render ContactCard without pulling the store in.
export {
  activeRecipients,
  contactRecipients,
  contactSource,
  hasActiveRecipient,
  isRecipientDisabled,
};

/**
 * One key belonging to a contact. An encrypt targets ALL of a contact's
 * active keys (age/OpenPGP both support N recipients); there is
 * deliberately no primary/default recipient.
 */
export interface ContactRecipient {
  /** Fingerprint of THIS key (not of the contact record). */
  keyId: string;
  /** The exact bytes handed to the engine as a recipient. */
  armored: string;
  algorithm: string;
  /** The user turned this key OFF: kept and listed, skipped as a recipient.
   *  Absent means enabled; `false` is NEVER written, so untouched records
   *  stay byte-identical for older builds. Read via
   *  {@link isRecipientDisabled}, write via {@link disabledField}. */
  disabled?: true;
}

/** Where a fetched multi-key contact came from: its upsert identity
 *  ({@link sameSource}). */
export interface ContactSource {
  type: "github" | "keyserver";
  /** GitHub account name, or canonical keyserver query (lowercased
   *  address / uppercase fingerprint). Not a key fingerprint. */
  user: string;
  fetchedAt: number;
}

/** Bumped when the engine changes what a contact's identity fields mean.
 *  1: `userIds` are bound, unrevoked User IDs only; `revoked` and
 *  `lookalike` are recorded. Older records are re-derived once. */
export const IDENTITY_VERSION = 1;

export interface PublicContactKey extends KindDiscriminated {
  /** Id of the contact RECORD (picker selection, upsert key, history
   *  reference). Equals `recipients[0].keyId` but is NOT "the key we
   *  encrypt to" -- read targets through {@link contactRecipients}. */
  keyId: string;
  /** OpenPGP User IDs; for SSH, the key comment as the sole element (or
   *  empty). */
  userIds: string[];
  /** Local display name; never touches the key. Absent means fall back to
   *  the derived name; `""` is NEVER written. Read via `displayUserId`,
   *  write via {@link aliasField} / {@link withAlias}. */
  alias?: string;
  algorithm: string;
  /** Armored cert (`pgp`) or `<type> <base64>` line (`ssh`): the exact
   *  recipient bytes handed to the engine. */
  armoredPublicKey: string;
  addedAt: number;
  lastUsedAt: number;
  expiresAt?: number | null;
  /** False for sign-only keys: valid for verification, never an encryption
   *  recipient. `undefined` on legacy records until backfilled -- treat as
   *  `true`. */
  usableForEncryption?: boolean;
  /** Non-blocking parse warning (e.g. SHA-1 binding); key still usable. */
  securityWarning?: string;
  /** Owner revoked this key. Kept so the revocation sticks against a stale
   *  re-import; never encrypted to. WRITTEN ONLY WHEN TRUE. */
  revoked?: boolean;
  /** A User ID mixes lookalike alphabets (`securityWarning` says so).
   *  WRITTEN ONLY WHEN TRUE. */
  lookalike?: boolean;
  /** Which {@link IDENTITY_VERSION} last derived the identity fields. */
  identityVersion?: number;
  /** User verified the fingerprint with its owner. WRITTEN ONLY WHEN TRUE;
   *  dropped when the key changes. */
  verified?: true;
  /** When it was marked verified (ms since epoch). */
  verifiedAt?: number;
  /** Fingerprints used before a key replacement, newest first. */
  previousKeyIds?: string[];
  /** Every key -- WRITTEN ONLY WHEN MORE THAN ONE (absent = the single
   *  top-level key). Read via {@link contactRecipients}, write via
   *  {@link recipientsField}. When present, `recipients[0]` MUST agree with
   *  `keyId`/`armoredPublicKey` (restored by `repairContact`), so an older
   *  build reading only the top-level fields encrypts to the first key. */
  recipients?: ContactRecipient[];
  /** Absent on hand-supplied contacts. Read via {@link contactSource}. */
  source?: ContactSource;
}

/** `disabled` is deliberately NOT validated: rejecting a stray
 *  `disabled: false` would silently drop the whole contact. */
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
  // `recipients` is deliberately NOT validated: a `false` here drops the
  // whole PERSON from the list, permanently on the next write. The
  // head-agreement invariant is enforced by {@link repairContact} instead.
  return true;
}

/**
 * Force `recipients` back into agreement with the top-level fields.
 * Repair, never reject (rejecting deletes the person on the next write).
 * The top-level fields WIN, since older builds read them. Returns the
 * record untouched when healthy, so it is never rewritten.
 */
function repairContact(contact: PublicContactKey): PublicContactKey {
  const stored: unknown = contact.recipients;
  if (stored === undefined) return contact;

  const raw: unknown[] = Array.isArray(stored) ? stored : [];
  const list = raw.filter(isContactRecipient);
  const agrees = (r: ContactRecipient) =>
    r.keyId === contact.keyId && r.armored === contact.armoredPublicKey;

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
 * The `recipients` field as it should be WRITTEN. `{}` for a single key so
 * one-key contacts stay byte-identical -- except a single DISABLED key,
 * whose flag would otherwise be lost (turning it back on). Caller ensures
 * `list[0]` matches the record's `keyId`/`armoredPublicKey`.
 */
export function recipientsField(list: readonly ContactRecipient[]): {
  recipients?: ContactRecipient[];
} {
  return list.length > 1 || list.some(isRecipientDisabled)
    ? { recipients: [...list] }
    : {};
}

/** A record carrying exactly `list` as its keys. Use this, not a spread of
 *  {@link recipientsField}, on an existing record: the spread would keep a
 *  stale `recipients` array when the list shrinks to one. */
export function withRecipients(
  contact: PublicContactKey,
  list: readonly ContactRecipient[],
): PublicContactKey {
  const { recipients: _dropped, ...rest } = contact;
  return { ...rest, ...recipientsField(list) };
}

/** The `alias` field as it should be WRITTEN: trimmed, `{}` when empty
 *  (clearing removes the field; `""` is never stored). */
export function aliasField(alias: string): { alias?: string } {
  const trimmed = alias.trim();
  return trimmed ? { alias: trimmed } : {};
}

/** A record with `alias` set or cleared. Use this, not a spread of
 *  {@link aliasField}, which would leave the old alias on clear. */
export function withAlias(
  contact: PublicContactKey,
  alias: string,
): PublicContactKey {
  const { alias: _dropped, ...rest } = contact;
  return { ...rest, ...aliasField(alias) };
}

/** The `disabled` flag as it should be WRITTEN: `{}` when enabled;
 *  `disabled: false` is never written. */
export function disabledField(disabled: boolean): { disabled?: true } {
  return disabled ? { disabled: true } : {};
}

/** The recipient list with one key turned on or off. Rebuilt
 *  field-by-field so re-enabling REMOVES `disabled`; order is preserved so
 *  `recipients[0]` keeps agreeing with the record. */
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
 * Whether two contacts denote the same fetched person. False when either
 * has no source (hand-supplied contacts never collide). Needed because a
 * fetched contact's `keyId` moves when its first key is deleted upstream.
 */
export function sameSource(
  a: Pick<PublicContactKey, "source">,
  b: Pick<PublicContactKey, "source">,
): boolean {
  const sa = contactSource(a);
  const sb = contactSource(b);
  if (sa === null || sb === null) return false;
  // One composite key so source types never collide; NUL can't occur in
  // either half.
  return `${sa.type}\u0000${sa.user}` === `${sb.type}\u0000${sb.user}`;
}

// AES-256-GCM sealed blob; same scheme as the keyring (encrypted-store.ts).
const CONTACTS_STORE = {
  storageKey: STORAGE_CONTACTS,
  isValid: isValidContact,
  label: "contacts",
};

export async function loadContacts(): Promise<PublicContactKey[]> {
  // Repaired, never rejected (`repairContact`). The ONLY read path: every
  // mutation re-loads through it.
  const contacts = (await loadEncryptedArray(CONTACTS_STORE)).map(
    repairContact,
  );
  return applyRevocationFloor(contacts);
}

/**
 * Re-apply the revocation floor (kept in the integrity ledger, not this
 * blob): any contact ever seen revoked is forced revoked AND unusable for
 * encryption, so writing back an older sealed blob can't un-revoke it.
 * Healthy records are returned untouched. See `integrity.ts`.
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

/** Contacts of one engine (absent `kind` = PGP). Encrypt callers MUST
 *  narrow this way: age and OpenPGP recipients can't mix in one message. */
export function contactsOfKind(
  contacts: readonly PublicContactKey[],
  kind: StoredKeyKind,
): PublicContactKey[] {
  return contacts.filter((c) => storedKeyKind(c) === kind);
}

/** Seal the whole list. The revocation floor is applied on the way IN too,
 *  so a rebuild from a stale copy can't persist a record unrevoked. */
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
 * checked INSIDE the lock, immediately before the read. Both are
 * load-bearing:
 *  - GUARD: with no session `loadEncryptedArray` returns `[]`, and an
 *    unguarded delete would `removeItem` every contact (reachable on
 *    auto-lock, which drops the session without awaiting queued work).
 *  - LOCK: load+save rewrites the array, so interleaved mutations drop
 *    one side's write.
 * Same idea as `MutationGuard` in `protected-store.ts`.
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
 * Upsert rules (each prevents a loss):
 *  - identity is the SOURCE when present (`sameSource`), else the id;
 *  - a source-less contact never supersedes a fetched one it collides
 *    with by keyId (that would drop the person's other keys);
 *  - `disabled` (a SECURITY decision) and `addedAt` survive a refresh,
 *    enforced here so no fetch path can forget it.
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

  // A hand-pasted key that is a fetched contact's head: keep the person,
  // but still land a newer copy of that same PGP key (e.g. its revocation).
  // Callers pass the merge of stored+incoming, so this only adds.
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

/** `incoming`, with the user's decisions from the record it replaces.
 *  `disabled` and `addedAt` carry only within the SAME record (same
 *  source, or source-less by key). The alias carries only for the same
 *  PERSON: matched by id, only when the key SET is unchanged (a `.pub`
 *  pairing Alice's key with Mallory's must not inherit "Alice"); matched
 *  by source, across key changes. "Verified" needs the same head and the
 *  same set either way. */
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
  // Untouched when nothing was off. If every remaining key is one the user
  // disabled, save a contact with nothing to encrypt to -- never one quietly
  // encrypting to keys they ruled out.
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
  // "Verified" and the alias carry only for the same key and the same set.
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

/** Mutate one stored contact and save. `apply` runs inside the lock on the
 *  on-disk record, so a caller never writes back an earlier snapshot.
 *  Resolves undefined, writing nothing, for an unknown id. */
export async function updateContact(
  keyId: string,
  apply: (
    contact: PublicContactKey,
  ) => PublicContactKey | Promise<PublicContactKey>,
): Promise<PublicContactKey | undefined> {
  return mutateContacts(async (existing) => {
    const index = existing.findIndex((c) => c.keyId === keyId);
    if (index === -1) return undefined;
    const updated = await apply(existing[index]);
    const next = [...existing];
    next[index] = updated;
    await saveAll(next);
    return updated;
  });
}

/** Turn one of a contact's keys on or off. Re-reads inside the lock rather
 *  than `saveContact`ing a page's mount-time snapshot. */
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

/** Mark a contact's key verified, or clear that. */
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

/** Set (or clear, with a blank value) a contact's alias. Via
 *  `updateContact`, so a stale snapshot never republishes other fields. */
export async function updateContactAlias(
  keyId: string,
  alias: string,
): Promise<void> {
  await updateContact(keyId, (contact) => withAlias(contact, alias));
}

export async function removeContact(keyId: string): Promise<void> {
  await mutateContacts(async (existing) => {
    // Saved as a sealed empty array, never removed: a missing store looks like
    // a deletion attack (`integrity.ts`).
    await saveAll(existing.filter((c) => c.keyId !== keyId));
  });
}
