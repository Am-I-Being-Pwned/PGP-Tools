import {
  mixedEngineReason,
  noActiveKeyReason,
  sshPasswordReason,
} from "~/lib/encrypt-recipients";
import { hasActiveRecipient } from "~/lib/storage/contact-recipients";
import type { PublicContactKey } from "~/lib/storage/contacts";
import {
  storedKeyKind,
  type KindDiscriminated,
  type StoredKeyKind,
} from "~/lib/storage/key-kind";

/**
 * Engine commitment for the recipient picker. One message cannot address
 * both OpenPGP and age (`lib/encrypt-recipients.ts`), so the other engine's
 * options are DISABLED with a reason, never hidden or refused at encrypt
 * time.
 */

/** The selection's engine (never mixed, so the first entry decides), or
 *  null while nothing is selected. */
export function selectionEngine(
  selected: readonly KindDiscriminated[],
): StoredKeyKind | null {
  return selected.length === 0 ? null : storedKeyKind(selected[0]);
}

export function blockedByEngine(
  key: KindDiscriminated,
  engine: StoredKeyKind | null,
): boolean {
  return engine !== null && storedKeyKind(key) !== engine;
}

/**
 * WHY `key` cannot join this message, or null when it can. Order matters:
 * no-active-key first, then password-rules-out-SSH (the more useful of two
 * true statements), then mixed engines. Kept distinct so a single-recipient
 * user is never told they have "mixed" recipients.
 */
export function recipientBlockReason(
  key: KindDiscriminated,
  engine: StoredKeyKind | null,
  passwordArmed: boolean,
): string | null {
  if (
    "armoredPublicKey" in key &&
    !hasActiveRecipient(key as unknown as PublicContactKey)
  ) {
    return noActiveKeyReason();
  }
  if (passwordArmed && storedKeyKind(key) === "ssh") {
    return sshPasswordReason();
  }
  return blockedByEngine(key, engine) ? mixedEngineReason() : null;
}

/**
 * The options a keyboard gesture may land on. Digit shortcuts and
 * Enter-picks-top index into THIS, not the rendered list, so a dimmed row
 * never swallows a keystroke.
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
 * Split matched keys into Contacts and My Keys. Security rules:
 *  - Own keys are ALWAYS offered under My Keys; a contact holding one must
 *    never hide it (a pasted file could otherwise swap "You" for a contact
 *    that also encrypts to an attacker).
 *  - A contact whose id IS one of your keys is dropped: selection is by id
 *    and that id means your key (`resolveSelectedRecipients`).
 *  - Every other contact is offered, even if its key is also in a bigger
 *    contact. Two rows for one key is a duplicate; one hidden row is a
 *    takeover.
 */
export function splitRecipientSections<
  C extends { keyId: string },
  O extends { keyId: string },
>(
  available: readonly (C | O)[],
  contacts: readonly C[],
  ownKeyIds: ReadonlySet<string>,
): { contacts: C[]; own: O[] } {
  const contactRecords = new Set<unknown>(contacts);
  const isContact = (k: C | O): k is C => contactRecords.has(k);
  return {
    contacts: available
      .filter(isContact)
      .filter((c) => !ownKeyIds.has(c.keyId)),
    own: available.filter((k): k is O => !isContact(k)),
  };
}
