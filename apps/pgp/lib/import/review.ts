import type { PublicContactKey } from "../storage/contacts";
import type { IncomingKey } from "./types";
import { parseRecipient } from "../age/operations";
import { groupContact, sshContact } from "../age/protect-flow";
import { IDENTITY_VERSION } from "../storage/contacts";
import { claimedIds } from "./prepare";

/**
 * The one way a contact gets written: binding a name/address to an
 * attacker-supplied key is the user's decision, so the store only accepts a
 * `ReviewedContact`. `reviewed()` is called only after the user has seen the
 * keys; `scripts/audit-invariants.mjs` fails the build on any other caller.
 */
declare const reviewedBrand: unique symbol;
export type ReviewedContact = PublicContactKey & {
  readonly [reviewedBrand]: true;
};

export function reviewed(contact: PublicContactKey): ReviewedContact {
  return contact as ReviewedContact;
}

export type ReviewDecision =
  | "skip"
  /** Save it. For a key in conflict: keep it as a separate contact. */
  | "import"
  /** Save it in place of the contact it conflicts with by address. */
  | "replace";

/** New keys and updates; duplicates change nothing and rejects can't be saved. */
export function needsDecision(key: IncomingKey): boolean {
  return key.status === "new" || key.status === "update";
}

/** A key claiming someone else's identity starts unticked -- and so
 *  does an update that would leave only keys the user turned off. */
export function defaultDecision(key: IncomingKey): ReviewDecision {
  return key.conflict || key.allKeysOff ? "skip" : "import";
}

export async function contactFromIncoming(
  key: IncomingKey,
): Promise<PublicContactKey> {
  if (key.group) {
    return groupContact(key.group);
  }
  if (key.kind === "ssh-public") {
    // `expiresAt: null`, not `undefined`, or the backfill parses the line as PGP.
    // Keep the comment the Review showed and the identity check compared: the
    // canonical line has none, and a nameless contact can't be checked against.
    const info = await parseRecipient(key.publicArmored);
    const [comment = ""] = claimedIds(key);
    return { ...sshContact({ ...info, comment }), expiresAt: null };
  }
  return {
    keyId: key.keyId,
    userIds: key.userIds,
    algorithm: key.info?.algorithm ?? "",
    armoredPublicKey: key.publicArmored,
    addedAt: Date.now(),
    lastUsedAt: Date.now(),
    expiresAt: key.info?.expiresAt ?? null,
    // Never `source: undefined`: absent means "hand-supplied" to `sameSource`.
    ...(key.source ? { source: key.source } : {}),
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
  keyIds: string[];
}

/**
 * Save what the user chose. "replace" keeps the conflicting contact's local
 * name, records its old key in `previousKeyIds`, and removes the old record.
 * The new key is never marked verified.
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

    // Replace only when exactly ONE stored contact holds the address: never guess
    // between several or delete people the Review never named (`canReplace`).
    const replaced =
      decision === "replace" &&
      key.status === "new" &&
      (key.kind === "pgp-public" || key.kind === "ssh-public") &&
      key.conflict?.kind === "address" &&
      // A lookalike address is never the holder's to hand over.
      !key.conflict.lookalike
        ? store.contacts.filter((c) =>
            key.conflict?.holders.some(
              (h) => !h.own && !h.incoming && h.keyId === c.keyId,
            ),
          )
        : [];
    const old = replaced.length === 1 ? replaced[0] : undefined;
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
