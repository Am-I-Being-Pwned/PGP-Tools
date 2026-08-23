import type { KindDiscriminated, StoredKeyKind } from "./key-kind";
import { STORAGE_CONTACTS } from "../constants";
import {
  loadEncryptedArray,
  normalizePadding,
  saveEncryptedArray,
} from "./encrypted-store";
import { removeItem } from "./engine";
import { storedKeyKind } from "./key-kind";

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
  type: "github";
  user: string;
  fetchedAt: number;
}

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
  /** Every key this contact holds -- WRITTEN ONLY WHEN THERE IS MORE
   *  THAN ONE. Absent means "the single key in the top-level fields",
   *  exactly the way an absent `kind` means `"pgp"` (see `key-kind.ts`).
   *  Read it through {@link contactRecipients}, never directly, and
   *  write it through {@link recipientsField}.
   *
   *  When present, `recipients[0]` MUST agree with `keyId` and
   *  `armoredPublicKey` ({@link isValidContact} enforces it). That is
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
  // `recipients` stays optional -- absent is the legacy (and the
  // single-key) shape. When it IS present the head-agreement invariant is
  // load-bearing rather than cosmetic: an older build reads only the
  // top-level fields, so a record whose head disagrees would silently
  // encrypt to a key this build never lists. Reject it here instead.
  if (o.recipients !== undefined) {
    if (!Array.isArray(o.recipients) || o.recipients.length === 0) return false;
    if (!o.recipients.every(isContactRecipient)) return false;
    const head = o.recipients[0];
    if (head.keyId !== o.keyId || head.armored !== o.armoredPublicKey) {
      return false;
    }
  }
  return true;
}

/**
 * Every key an encrypt to this contact must target.
 *
 * The ONLY way anything reads `recipients` -- the discipline
 * `storedKeyKind` enforces for `kind`. A record with the field absent
 * (every contact on a user's disk today) synthesises the single-key list
 * from the top-level fields, so no call site has to know which shape it
 * was handed.
 */
export function contactRecipients(
  contact: PublicContactKey,
): ContactRecipient[] {
  return (
    contact.recipients ?? [
      {
        keyId: contact.keyId,
        armored: contact.armoredPublicKey,
        algorithm: contact.algorithm,
      },
    ]
  );
}

/**
 * Whether the user has turned this key off. The ONLY way anything reads
 * `disabled`.
 *
 * Strict `=== true`, so absent -- and anything else that ever ends up
 * there -- means ENABLED. Defaulting the other way would let a typo, or
 * a record written by some future build, silently stop encrypting to a
 * key.
 */
export function isRecipientDisabled(recipient: ContactRecipient): boolean {
  return recipient.disabled === true;
}

/**
 * The keys an encrypt to this contact should ACTUALLY target: every
 * recipient the user has not turned off.
 *
 * The display list stays {@link contactRecipients} -- a disabled key
 * must remain visible, or the user cannot turn it back on. This is the
 * list `toSelectedRecipient` expands, and the only place the two differ.
 */
export function activeRecipients(
  contact: PublicContactKey,
): ContactRecipient[] {
  const all = contactRecipients(contact);
  const active = all.filter((r) => !isRecipientDisabled(r));
  // SAFETY NET, not a normal path: the UI refuses to disable the last
  // enabled key, so this state cannot be reached through it. But a
  // hand-edited blob, or a record from some future build, could still
  // arrive with everything off -- and returning [] there would encrypt
  // the message to NOBODY, silently and unrecoverably. Falling back to
  // the full list is the failure that is merely wrong-in-the-safe-
  // direction: the user gets the pre-feature behaviour instead of an
  // unreadable file.
  return active.length > 0 ? active : all;
}

/** Where this contact came from, or null when it was hand-supplied.
 *  The only way anything reads `source`. */
export function contactSource(
  contact: Pick<PublicContactKey, "source">,
): ContactSource | null {
  return contact.source ?? null;
}

/**
 * The `recipients` field as it should be WRITTEN, spread into a new
 * record -- the counterpart to `kindField`.
 *
 * Returns `{}` for a single key, so a one-key contact serialises
 * byte-for-byte as it does today: zero migration, zero rewrite, and an
 * older build still reads every record. The caller is responsible for
 * `list[0]` matching the record's `keyId`/`armoredPublicKey`.
 */
export function recipientsField(list: readonly ContactRecipient[]): {
  recipients?: ContactRecipient[];
} {
  return list.length > 1 ? { recipients: [...list] } : {};
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
  return loadEncryptedArray(CONTACTS_STORE);
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

function saveAll(contacts: PublicContactKey[]): Promise<void> {
  return saveEncryptedArray(CONTACTS_STORE, contacts);
}

/** One-time upgrade of a contacts blob to canonical padding and to the
 *  domain-bound sealing envelope. */
export function normalizeContactsPadding(): Promise<void> {
  return normalizePadding(CONTACTS_STORE);
}

export async function saveContact(contact: PublicContactKey): Promise<void> {
  const existing = await loadContacts();
  // Upsert identity is the SOURCE when there is one, the record id
  // otherwise -- see `sameSource`. Dropping by keyId alone would leave a
  // stale duplicate behind whenever a fetched contact's first key was
  // deleted upstream (its keyId moves to the next key).
  const updated = [
    ...existing.filter(
      (c) => c.keyId !== contact.keyId && !sameSource(c, contact),
    ),
    contact,
  ];
  await saveAll(updated);
}

export async function removeContact(keyId: string): Promise<void> {
  const existing = await loadContacts();
  const updated = existing.filter((c) => c.keyId !== keyId);
  if (updated.length === 0) {
    await removeItem(STORAGE_CONTACTS);
  } else {
    await saveAll(updated);
  }
}
