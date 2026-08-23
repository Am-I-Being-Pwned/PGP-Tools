import type { KeyDetails, KeyInfo } from "../pgp/types";
import type { ContactRecipient, ContactSource } from "../storage/contacts";

/**
 * What the import UI is written against. `prepareImport` turns
 * pasted/dropped text into these; the preview panel only ever renders
 * them, so the two halves can be built and tested independently.
 */

/** How an incoming key relates to what's already stored. */
export type ImportStatus =
  /** Fingerprint we've never seen. */
  | "new"
  /** Same fingerprint as a stored key, but the cert has moved on --
   *  extended expiry, new user IDs, new subkeys. */
  | "update"
  /** Same fingerprint, byte-identical cert: importing is a no-op. */
  | "duplicate"
  /** Expired, revoked, or otherwise unusable -- can't be imported. */
  | "rejected";

/**
 * Which engine a key belongs to, and which half of it arrived.
 *
 * Named `<engine>-<half>` rather than plain "public"/"private" because
 * the half alone stopped being enough the moment a second engine
 * appeared: what the flow does with a key -- where it's stored, what it's
 * compared against, whether it needs the protect step -- follows from the
 * pair. A new engine adds its own pair and the switches below tell you
 * exactly what has to answer for it; `ssh-public` / `ssh-private` (the
 * age engine) is that rule being used as intended.
 *
 * "crx" has no public half to import: a Chrome extension signing key is
 * only ever handed over as its RSA private key.
 */
export type KeyKind =
  | "pgp-public"
  | "pgp-private"
  | "ssh-public"
  | "ssh-private"
  | "crx";

/** The kinds that are somebody else's public half: stored as a contact,
 *  importable in bulk, and never routed through the protect step. Every
 *  other kind carries secret material.
 *
 *  `ssh-public` is a genuine public half -- an `ssh-ed25519` /
 *  `ssh-rsa` line off a `.pub` file, exactly as public as a PGP
 *  certificate -- so it belongs here. `ssh-private` is an OpenSSH
 *  private key container and does not. */
const PUBLIC_KINDS = new Set<KeyKind>(["pgp-public", "ssh-public"]);

/** True for a public half -- imported straight away as a contact. */
export function isPublicKind(kind: KeyKind): boolean {
  return PUBLIC_KINDS.has(kind);
}

/** True when the import carries secret material, so it must go through
 *  the protect step and its source text must stay in a ref. */
export function isSecretKind(kind: KeyKind): boolean {
  return !isPublicKind(kind);
}

/**
 * Placeholder id for a key whose real identifier does not exist yet.
 *
 * A CRX signing key is identified by its extension ID, which is a hash of
 * the PUBLIC half -- and that half is only derived inside the protect
 * step, from key material the preview deliberately never sees. Until then
 * this stands in as the flow's map key. It never reaches storage.
 */
export const PENDING_KEY_ID = "pending";

/**
 * Several public keys that belong to ONE person.
 *
 * A GitHub user commonly publishes three SSH keys and every one of them
 * has to be encrypted to (see `storage/contacts.ts`), so what arrives
 * from a lookup is a person, not a key. A pasted `authorized_keys` block
 * is the same situation without the lookup, and reaches storage as the
 * same record through the same constructor.
 *
 * Deliberately an optional field on the existing `ssh-public`
 * {@link IncomingKey} rather than a {@link KeyKind} of its own: a new
 * kind is a routing decision, and every switch that routes by kind --
 * `PUBLIC_KINDS`, the protect step, the preview's chip table, the facts
 * adapter -- would have to answer for it, to reach exactly the same
 * answers `ssh-public` already gives. The group's FIRST member is the
 * key's `keyId`/`publicArmored`, which is also the stored record's head
 * (see `recipientsField`), so every comparison and preview path works on
 * a group unchanged and simply shows less than it could.
 */
export interface ContactGroup {
  /** Display name for the whole group, e.g. "octocat (GitHub)". This is
   *  the contact's `userIds[0]` -- auto-derived when the keys say what
   *  it should be (a lookup's account name, a shared key comment), and
   *  otherwise supplied by the user, because grouping keys that do not
   *  agree is never something to guess at. */
  label: string;
  /** Where it was fetched from -- the contact's upsert identity.
   *
   *  ABSENT MEANS HAND-SUPPLIED, exactly as it does on the stored record
   *  (see `PublicContactKey.source`): a pasted group has no identity
   *  beyond its keys, and two source-less contacts must never collide.
   *  Read it through `contactSource`, never directly. */
  source?: ContactSource;
  /** Every usable key, in the order the source listed them. Empty only
   *  when every line was refused, which is a `rejected` import. */
  members: ContactRecipient[];
  /** Lines the engine refused, with its own reason for each. Carried,
   *  not dropped: an ECDSA or FIDO key silently missing from someone's
   *  recipient list is exactly the failure this flow must not have. */
  rejected: RejectedLine[];
}

/** One line the engine refused, and why. */
export interface RejectedLine {
  /** The line as fetched, so the user can see WHICH key was refused. */
  line: string;
  /** The engine's own message ("ECDSA keys are not supported ..."). */
  reason: string;
}

export interface IncomingKey {
  /** Fingerprint; also the list key. {@link PENDING_KEY_ID} for an engine
   *  whose identifier is only known once the key has been imported. */
  keyId: string;
  kind: KeyKind;
  status: ImportStatus;
  /** Parsed OpenPGP facts. Null for any other engine -- a CRX signing key
   *  is a raw RSA PEM with no certificate to parse, and an SSH key has no
   *  user IDs, no created date, no expiry and no subkeys to report. */
  info: KeyInfo | null;
  details: KeyDetails | null;
  userIds: string[];
  /** For `update`: what differs from the stored key, e.g.
   *  "new expiry: 4 Jan 2027". */
  changes: string[];
  /** For `update`/`duplicate`: when the stored key was added. */
  existingAddedAt?: number | null;
  /** For `rejected`: the human-readable reason. */
  rejection?: string;
  /** Allowed, but flagged (e.g. SHA-1 binding signature). */
  securityWarning?: string;
  /**
   * The cert's own PUBLIC armor -- what gets stored for a contact, and
   * what the preview parses. Empty for an engine with no public half to
   * show before import (CRX). Private key material never travels in this
   * object: it stays in `PreparedImport.secrets`, is copied into the
   * import panel's ref, and goes straight to the protect step (see
   * ImportKeyPage's secretArmorRef and SECURITY.md's zeroization table).
   */
  publicArmored: string;
  /** Present when this "key" is really a person with several keys (a
   *  GitHub lookup). `keyId`/`publicArmored` stay the FIRST member's, so
   *  nothing that reads them needs to know. */
  group?: ContactGroup;
}
