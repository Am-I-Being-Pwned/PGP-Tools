import type {
  KindDiscriminated,
  StoredKeyKind,
} from "../../lib/storage/key-kind";
import {
  mixedEngineReason,
  sshPasswordReason,
} from "../../lib/encrypt-recipients";
import { storedKeyKind } from "../../lib/storage/key-kind";

/**
 * Which engine the recipient picker is currently committed to, and which
 * of the remaining options that rules out.
 *
 * OpenPGP and age are different file formats: one message cannot address
 * both (see `lib/encrypt-recipients.ts`). The picker prevents that by
 * DISABLING the other engine's options with a reason, rather than
 * letting the selection be made and refusing it at encrypt time -- the
 * same rule the action registry states for its own disabled actions: a
 * dimmed option with a reason is discoverable, a vanished one looks like
 * it doesn't exist.
 *
 * Split out of the component (and kept free of JSX) so the indexing rule
 * below can be tested directly.
 */

/** The engine the current selection commits the message to, or null when
 *  nothing is selected and either engine is still open. The selection can
 *  never be mixed -- that is what this module prevents -- so the first
 *  entry decides. */
export function selectionEngine(
  selected: readonly KindDiscriminated[],
): StoredKeyKind | null {
  return selected.length === 0 ? null : storedKeyKind(selected[0]);
}

/** True when `key` belongs to the other engine and therefore cannot join
 *  this message. Nothing is blocked while no engine is committed. */
export function blockedByEngine(
  key: KindDiscriminated,
  engine: StoredKeyKind | null,
): boolean {
  return engine !== null && storedKeyKind(key) !== engine;
}

/**
 * WHY `key` cannot join this message, or null when it can.
 *
 * Two different refusals, and they are kept apart on purpose. A mixed
 * selection is the user's own doing and the fix is to pick differently;
 * a password rules out age entirely and the fix is to drop the password.
 * Telling someone they have "mixed" recipients when they have selected
 * one sends them hunting for a second.
 *
 * The password rule is checked FIRST: with a password set, an SSH key is
 * out whatever else is selected, and "you can't mix engines" would be
 * the less useful of two true statements.
 */
export function recipientBlockReason(
  key: KindDiscriminated,
  engine: StoredKeyKind | null,
  passwordArmed: boolean,
): string | null {
  if (passwordArmed && storedKeyKind(key) === "ssh") {
    return sshPasswordReason();
  }
  return blockedByEngine(key, engine) ? mixedEngineReason() : null;
}

/**
 * The options a keyboard gesture may actually land on.
 *
 * Render order and pick order are NOT the same list once some rows are
 * disabled: if digit `3` indexed into what is rendered, a dimmed row
 * sitting third would swallow the keystroke and nothing would happen.
 * Both the digit shortcuts and the Enter-picks-the-top-match fallback
 * index into this, so a blocked row is invisible to the keyboard while
 * staying visible (and explained) on screen.
 */
export function pickableKeys<T extends KindDiscriminated>(
  visible: readonly T[],
  engine: StoredKeyKind | null,
  passwordArmed = false,
): T[] {
  return visible.filter(
    (k) => recipientBlockReason(k, engine, passwordArmed) === null,
  );
}

/**
 * Split the keys a search matched into the picker's Contacts and My Keys
 * sections, offering each key once.
 *
 * The same key is easy to hold twice: your own key imported again as a
 * contact (PGP or SSH), or your SSH key that is also one of the keys a
 * GitHub lookup fetched for you. So:
 *
 *  - Contacts are the contact RECORDS. An own key is never placed there
 *    just because its fingerprint matches a contact's -- that is how it
 *    used to show up a second time under Contacts.
 *  - An own key a contact already holds is left out of My Keys.
 *  - A single-key contact whose key is already one of a bigger contact's
 *    keys is left out: picking the bigger one covers it.
 *
 * `keysOf` lists a contact's key fingerprints (`contactRecipients`).
 */
export function splitRecipientSections<
  C extends { keyId: string },
  O extends { keyId: string },
>(
  available: readonly (C | O)[],
  contacts: readonly C[],
  keysOf: (contact: C) => readonly string[],
): { contacts: C[]; own: O[] } {
  const contactRecords = new Set<unknown>(contacts);
  const isContact = (k: C | O): k is C => contactRecords.has(k);
  // Only contacts IN these results can cover a key: hiding a row because
  // of a contact the search filtered out would make it unfindable.
  const held = new Map<string, number>(); // fingerprint -> most keys holding it
  for (const c of available.filter(isContact)) {
    const ids = keysOf(c);
    for (const id of ids) held.set(id, Math.max(held.get(id) ?? 0, ids.length));
  }

  return {
    contacts: available.filter(isContact).filter((c) => {
      const ids = keysOf(c);
      return !(ids.length === 1 && (held.get(ids[0]) ?? 0) > 1);
    }),
    own: available.filter((k): k is O => !isContact(k) && !held.has(k.keyId)),
  };
}
