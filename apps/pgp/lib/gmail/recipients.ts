import type { PublicContactKey } from "../storage/contacts";
import { parseUserId } from "../utils/key-naming";
import { isEmailAddress } from "./protocol";

export interface RecipientMatch {
  /** Contact record ids to preselect, in the order the addresses came. */
  ids: string[];
  /** Addresses no usable contact claims -- the panel says so, because a
   *  draft silently encrypted to fewer people than it is addressed to
   *  is a message someone on the To line cannot read. */
  missing: string[];
}

/** The email part of each User ID, lowercased. A bare `x@y` User ID (no
 *  name, no angle brackets) counts too. */
function emailsOf(userIds: string[]): string[] {
  return userIds
    .map((uid) => {
      const { email } = parseUserId(uid);
      if (email) return email;
      return uid.includes("@") && !/\s/.test(uid.trim()) ? uid.trim() : "";
    })
    .filter(Boolean)
    .map((e) => e.toLowerCase());
}

/**
 * Map compose-window addresses to contacts the user can encrypt to.
 *
 * Only contacts usable for encryption are offered (per-key "disabled" is
 * applied later, when recipients are assembled) --
 * the same filter the recipient picker applies -- so a preselection can
 * never contain a row the picker would refuse. Where two contacts claim
 * one address, the most recently used wins: that is the key the user
 * last chose for this person.
 */
export function matchRecipients(
  addresses: string[],
  contacts: PublicContactKey[],
  /** The user's own addresses (from their own keys). Covered by "Also
   *  encrypt to me", so neither preselected nor reported missing --
   *  Gmail puts the sender on a reply-all's Cc line all the time. */
  ownUserIds: string[] = [],
): RecipientMatch {
  const own = new Set(emailsOf(ownUserIds));
  const usable = contacts
    .filter((c) => c.usableForEncryption !== false)
    .slice()
    .sort((a, b) => b.lastUsedAt - a.lastUsedAt);

  const ids: string[] = [];
  const missing: string[] = [];
  for (const raw of addresses) {
    const address = raw.toLowerCase();
    if (own.has(address)) continue;
    const hit = usable.find((c) => emailsOf(c.userIds).includes(address));
    if (!hit) missing.push(address);
    else if (!ids.includes(hit.keyId)) ids.push(hit.keyId);
  }
  return { ids, missing };
}

/**
 * The draft's addresses that the CURRENT selection does not cover --
 * what the strip warns about, derived live rather than remembered from
 * the first match. So the warning follows the user: picking a key (by
 * hand, or by importing one) clears an address, and removing a
 * recipient brings it back. An address counts as covered when any
 * selected key -- a contact's or the user's own -- carries it in a User
 * ID, or when it is the user's own address (encrypt-to-self covers it).
 */
export function uncoveredRecipients(
  addresses: string[],
  selected: { userIds: string[] }[],
  ownUserIds: string[] = [],
): string[] {
  const covered = new Set([
    ...emailsOf(ownUserIds),
    ...selected.flatMap((k) => emailsOf(k.userIds)),
  ]);
  return addresses.map((a) => a.toLowerCase()).filter((a) => !covered.has(a));
}

/**
 * The address to put on Gmail's To line for a key the user picked in the
 * panel: its first User ID that carries one. Null for a key with no
 * address (an SSH key, a name-only User ID) -- there is nothing to type.
 */
export function primaryEmailOf(userIds: string[]): string | null {
  return emailsOf(userIds)[0] ?? null;
}

/**
 * Picked recipients the draft does not address yet: for each selected
 * key that none of the draft's addresses belongs to, its primary
 * address. The user's own keys are skipped (encrypt-to-self is not a
 * recipient), and so is anyone already on the line under any of their
 * addresses.
 */
export function addressesToAdd(
  draftAddresses: string[],
  selected: { userIds: string[] }[],
): string[] {
  const onDraft = new Set(draftAddresses.map((a) => a.toLowerCase()));
  const out: string[] = [];
  for (const key of selected) {
    // Only addresses the content script will accept: an SSH comment
    // (`deploy@host`) is not one, and one bad entry fails the request.
    const emails = emailsOf(key.userIds).filter(isEmailAddress);
    if (emails.length === 0 || emails.some((e) => onDraft.has(e))) continue;
    if (!out.includes(emails[0])) out.push(emails[0]);
  }
  return out;
}
