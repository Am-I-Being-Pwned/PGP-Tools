/**
 * Pure readers of a contact record: which keys it holds, which are
 * active, where it came from. No store behind them (and so no wasm), so
 * a page that only DISPLAYS a contact -- Reply's reader tab, via
 * ContactCard -- can use them without loading the vault's machinery.
 * `lib/storage/contacts.ts` re-exports all of them.
 */

import type {
  ContactRecipient,
  ContactSource,
  PublicContactKey,
} from "./contacts";

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
