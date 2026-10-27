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
 *
 * EMPTY when every key is off, and that state is reachable: the UI
 * refuses to turn off the last enabled key, but a refresh can take the
 * enabled ones away (a GitHub account that deleted the keys the user
 * kept, leaving the ones they turned off -- `carryForward` keeps those
 * flags). This used to fall back to every key, which quietly encrypted
 * to exactly the keys the user had said not to use. Empty means the
 * contact cannot be encrypted to until a key is turned back on: the
 * picker blocks it with a reason (`recipientBlockReason`), and
 * `buildEncryptRecipients` refuses an empty key list rather than
 * encrypting to nobody (see {@link hasActiveRecipient}).
 */
export function activeRecipients(
  contact: PublicContactKey,
): ContactRecipient[] {
  return contactRecipients(contact).filter((r) => !isRecipientDisabled(r));
}

/** Whether there is anything left to encrypt to this contact with. */
export function hasActiveRecipient(contact: PublicContactKey): boolean {
  return activeRecipients(contact).length > 0;
}

/** Where this contact came from, or null when it was hand-supplied.
 *  The only way anything reads `source`. */
export function contactSource(
  contact: Pick<PublicContactKey, "source">,
): ContactSource | null {
  return contact.source ?? null;
}
