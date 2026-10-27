import type { PublicContactKey } from "../storage/contacts";
import type { IncomingKey } from "./types";
import { parseRecipient } from "../age/operations";
import { groupContact, sshContact } from "../age/protect-flow";
import { IDENTITY_VERSION } from "../storage/contacts";

/**
 * The one way a contact gets written: through the import Review.
 *
 * A contact binds a name and address to a key, and that is the user's
 * decision to make, never the app's -- a key file is attacker-supplied
 * text, and a bundle used to be saved without anyone seeing it. So the
 * store only accepts a `ReviewedContact`, and `reviewed()` is called from
 * the import flows after the user has seen the keys (and from undoing a
 * delete they just made). `scripts/audit-invariants.mjs` fails the build
 * if any other file calls it.
 */
declare const reviewedBrand: unique symbol;
export type ReviewedContact = PublicContactKey & {
  readonly [reviewedBrand]: true;
};

export function reviewed(contact: PublicContactKey): ReviewedContact {
  return contact as ReviewedContact;
}

/** What the user chose for one key on the Review screen. */
export type ReviewDecision =
  /** Leave it out. */
  | "skip"
  /** Save it. For a key in conflict: keep it as a separate contact. */
  | "import"
  /** Save it in place of the contact it conflicts with by address. */
  | "replace";

/** Keys the Review lists with a choice: new keys and updates. A
 *  duplicate changes nothing and a rejected key can't be saved. */
export function needsDecision(key: IncomingKey): boolean {
  return key.status === "new" || key.status === "update";
}

/** A key claiming someone else's identity starts unticked -- and so
 *  does an update that would leave only keys the user turned off. */
export function defaultDecision(key: IncomingKey): ReviewDecision {
  return key.conflict || key.allKeysOff ? "skip" : "import";
}

/** The contact record an incoming key becomes. */
export async function contactFromIncoming(
  key: IncomingKey,
): Promise<PublicContactKey> {
  if (key.group) {
    // A person with several keys is ONE contact holding all of them (see
    // storage/contacts), built by the age engine's own constructor.
    return groupContact(key.group);
  }
  if (key.kind === "ssh-public") {
    // `sshContact` decides an SSH contact's shape; `expiresAt: null`
    // because SSH keys have no expiry and `undefined` would send the
    // contacts backfill off to parse a recipient line as PGP armor.
    const info = await parseRecipient(key.publicArmored);
    return { ...sshContact(info), expiresAt: null };
  }
  return {
    keyId: key.keyId,
    userIds: key.userIds,
    algorithm: key.info?.algorithm ?? "",
    armoredPublicKey: key.publicArmored,
    addedAt: Date.now(),
    lastUsedAt: Date.now(),
    expiresAt: key.info?.expiresAt ?? null,
    // Spread, never `source: undefined`: an absent source is what
    // `sameSource` reads to mean "hand-supplied".
    ...(key.source ? { source: key.source } : {}),
    // Sign-only keys are valid contacts (for verification) but can't be
    // offered as encryption recipients.
    usableForEncryption: key.info?.usableForEncryption ?? true,
    securityWarning: key.securityWarning,
    ...(key.info?.revoked ? { revoked: true } : {}),
    ...(key.info?.lookalike ? { lookalike: true } : {}),
    ...(key.info ? { identityVersion: IDENTITY_VERSION } : {}),
  };
}

export interface ReviewOutcome {
  added: number;
  updated: number;
  replaced: number;
  /** Fingerprints written, to reveal in the list. */
  keyIds: string[];
}

/**
 * Save what the user chose on the Review screen.
 *
 * "replace" puts the new key in the place of the contact it conflicts
 * with by address: the contact keeps its local name, the old key is
 * remembered in `previousKeyIds`, and the old record goes. Nothing about
 * the new key is marked verified -- it is a different key.
 */
export async function applyReview(
  keys: readonly IncomingKey[],
  decisions: ReadonlyMap<string, ReviewDecision>,
  store: {
    contacts: readonly PublicContactKey[];
    add: (contact: ReviewedContact) => Promise<void>;
    remove: (keyId: string) => Promise<void>;
  },
): Promise<ReviewOutcome> {
  const outcome: ReviewOutcome = {
    added: 0,
    updated: 0,
    replaced: 0,
    keyIds: [],
  };
  for (const key of keys) {
    if (!needsDecision(key)) continue;
    const decision = decisions.get(key.keyId) ?? defaultDecision(key);
    if (decision === "skip") continue;
    const contact = await contactFromIncoming(key);

    const old =
      decision === "replace" &&
      key.status === "new" &&
      key.conflict?.kind === "address" &&
      // A lookalike address is never the holder's to hand over (see
      // `canReplace` in ImportReview): saved beside it, not over it.
      !key.conflict.lookalike
        ? store.contacts.find((c) =>
            key.conflict?.holders.some((h) => h.keyId === c.keyId),
          )
        : undefined;
    if (old) {
      await store.add(
        reviewed({
          ...contact,
          ...(old.alias ? { alias: old.alias } : {}),
          previousKeyIds: [old.keyId, ...(old.previousKeyIds ?? [])],
        }),
      );
      await store.remove(old.keyId);
      outcome.replaced++;
    } else {
      await store.add(reviewed(contact));
      if (key.status === "update") outcome.updated++;
      else outcome.added++;
    }
    outcome.keyIds.push(contact.keyId);
  }
  return outcome;
}
