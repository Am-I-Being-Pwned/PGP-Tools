import type { KeyDetails, KeyInfo } from "../pgp/types";

/**
 * What the import UI is written against. `prepareImport` (wired up in the
 * implementation pass) turns pasted/dropped text into these; the preview
 * panel only ever renders them, so the two halves can be built and tested
 * independently.
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

export interface IncomingKey {
  /** Fingerprint; also the list key. */
  keyId: string;
  kind: "public" | "private" | "crx";
  status: ImportStatus;
  /** Parsed facts for the preview body. Null for a CRX signing key,
   *  which is a raw RSA PEM with no OpenPGP metadata to show. */
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
   * what the preview parses. Private key material never travels in this
   * object: it stays in the import panel's ref and goes straight to the
   * protect step (see ImportKeyPage's armoredRef and SECURITY.md's
   * zeroization table).
   */
  publicArmored: string;
}
