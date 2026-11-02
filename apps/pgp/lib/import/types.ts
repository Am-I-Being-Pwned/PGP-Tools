import type { IdentityConflict } from "../identity/binding";
import type { KeyDetails, KeyInfo } from "../pgp/types";
import type { ContactRecipient, ContactSource } from "../storage/contacts";

// What the import UI is written against: `prepareImport` produces these,
// the preview only renders them.

/** How an incoming key relates to what's already stored. */
export type ImportStatus =
  | "new"
  /** Same fingerprint, but the cert has moved on. */
  | "update"
  /** Byte-identical cert: importing is a no-op. */
  | "duplicate"
  | "rejected";

/**
 * `<engine>-<half>`: storage, comparison and the protect step follow from
 * the pair. "crx" has no public half; a CRX key is only ever its RSA private key.
 */
export type KeyKind =
  "pgp-public" | "pgp-private" | "ssh-public" | "ssh-private" | "crx";

/** Somebody else's public half: stored as a contact, importable in bulk,
 *  never routed through the protect step. Every other kind is secret. */
const PUBLIC_KINDS = new Set<KeyKind>(["pgp-public", "ssh-public"]);

export function isPublicKind(kind: KeyKind): boolean {
  return PUBLIC_KINDS.has(kind);
}

/** Secret material: must go through the protect step, source text kept in a ref. */
export function isSecretKind(kind: KeyKind): boolean {
  return !isPublicKind(kind);
}

/** Stand-in id until the protect step derives a CRX key's extension ID
 *  (the preview never sees the key material). Never reaches storage. */
export const PENDING_KEY_ID = "pending";

/**
 * Several public keys that belong to ONE person (a GitHub lookup, a pasted
 * `authorized_keys` block). An optional field on `ssh-public` rather than a
 * new {@link KeyKind}, so kind routing is unchanged; the FIRST member is the
 * key's `keyId`/`publicArmored` and the stored record's head.
 */
export interface ContactGroup {
  /** The contact's `userIds[0]`. Auto-derived only when the keys agree;
   *  otherwise user-supplied, never guessed. */
  label: string;
  /** The contact's upsert identity. ABSENT MEANS HAND-SUPPLIED; read it
   *  through `contactSource`, never directly. */
  source?: ContactSource;
  /** Empty only when every line was refused (a `rejected` import). */
  members: ContactRecipient[];
  /** Kept, not dropped: a silently missing key is the failure to avoid. */
  rejected: RejectedLine[];
}

export interface RejectedLine {
  line: string;
  reason: string;
}

export interface IncomingKey {
  /** Fingerprint, or {@link PENDING_KEY_ID} until known. */
  keyId: string;
  kind: KeyKind;
  status: ImportStatus;
  /** Parsed OpenPGP facts; null for other engines. */
  info: KeyInfo | null;
  details: KeyDetails | null;
  userIds: string[];
  changes: string[];
  existingAddedAt?: number | null;
  rejection?: string;
  /** Allowed but flagged (e.g. SHA-1 binding signature). */
  securityWarning?: string;
  /**
   * The cert's PUBLIC armor; empty for CRX. Private key material never
   * travels here: it stays in `PreparedImport.secrets` and goes straight to
   * the protect step (SECURITY.md zeroization table).
   */
  publicArmored: string;
  /** For a fetched `new` key: the contact whose key this REPLACES. */
  replaces?: string;
  /** A NEW key claiming an identity someone else holds (`identity/binding`).
   *  Never saved without the user choosing. */
  conflict?: IdentityConflict;
  /** Every still-listed key is turned off on the stored record; asked
   *  about like a conflict, starts on Skip. */
  allKeysOff?: true;
  /** A person with several keys; `keyId`/`publicArmored` stay the first member's. */
  group?: ContactGroup;
  /**
   * Where a single fetched key came from (keyserver). ABSENT MEANS
   * HAND-SUPPLIED: a pasted cert must never acquire a provenance it lacks.
   */
  source?: ContactSource;
}
