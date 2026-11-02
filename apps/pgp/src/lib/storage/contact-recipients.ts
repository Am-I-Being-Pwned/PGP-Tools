/**
 * Pure readers of a contact record, with no store (or wasm) behind them,
 * so display-only pages (the reader tab's ContactCard) can use them.
 * Re-exported by `lib/storage/contacts.ts`.
 */

import type {
  ContactRecipient,
  ContactSource,
  PublicContactKey,
} from "./contacts";

/** Every key on this contact. The ONLY reader of `recipients`; an absent
 *  field yields the single top-level key. */
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

/** Whether the user turned this key off. The ONLY reader of `disabled`.
 *  Strict `=== true`: anything else means enabled, so a stray value can't
 *  silently stop encrypting to a key. */
export function isRecipientDisabled(recipient: ContactRecipient): boolean {
  return recipient.disabled === true;
}

/**
 * The keys an encrypt should ACTUALLY target: those not turned off (the
 * display list stays {@link contactRecipients}). EMPTY when every key is
 * off -- reachable after a refresh -- and never falls back to all keys:
 * the picker blocks it and `buildEncryptRecipients` refuses an empty list.
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

/** Where this contact came from, or null when hand-supplied. The only
 *  reader of `source`. */
export function contactSource(
  contact: Pick<PublicContactKey, "source">,
): ContactSource | null {
  return contact.source ?? null;
}
