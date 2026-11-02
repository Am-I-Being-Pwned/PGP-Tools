import type { KeyDetails, KeyInfo } from "../../lib/pgp/types";
import type { ContactRecipient } from "../../lib/storage/contacts";
import { t } from "../../lib/i18n";

/**
 * What the key body renders, engine-neutral: each engine supplies the
 * facts it has. An absent fact doesn't render; it is never a blank row.
 */

/** One component key (primary or subkey). Single-key engines supply none. */
export interface ComponentKeyRow {
  fingerprint: string;
  algorithm: string;
  bits?: number;
  /** Absent when the engine records no creation date (SSH). */
  createdAt?: number;
  /** `null` renders "never expires"; absent means no concept of expiry. */
  expiresAt?: number | null;
  isPrimary: boolean;
  canSign: boolean;
  canEncrypt: boolean;
  canCertify: boolean;
  canAuthenticate: boolean;
  status: "active" | "expired" | "revoked" | "invalid";
  revocationReason?: string;
  policyError?: string;
}

/** Absent means the engine has no verdict, and no banner shows. */
export interface KeyHealth {
  usableForEncryption: boolean;
  usableForSigning: boolean;
  policyError?: string;
}

export interface KeyFacts {
  /**
   * Grouped into 4-char blocks when hex. OMITTED for a multi-key contact:
   * its keys are peers, and naming one would imply a primary key.
   */
  fingerprint?: string;
  algorithm: string;
  createdAt?: number;
  /** `null` renders "Never"; omitted means no concept of expiry. */
  expiresAt?: number | null;
  health?: KeyHealth;
  /** Omitted when the breakdown failed to parse or doesn't exist. */
  components?: {
    rows: ComponentKeyRow[];
    truncated: boolean;
    /** Defaults to "Subkeys"; a contact's separate keys are not subkeys. */
    title?: string;
    rowLabel?: string;
  };
}

/** `details` is optional: a cert whose breakdown fails still previews. */
export function pgpKeyFacts(
  info: KeyInfo,
  details: KeyDetails | null,
): KeyFacts {
  return {
    fingerprint: info.keyId,
    algorithm: info.algorithm,
    createdAt: info.createdAt,
    expiresAt: info.expiresAt,
    health: {
      usableForEncryption: info.usableForEncryption,
      usableForSigning: info.usableForSigning,
      policyError: info.policyError,
    },
    components: details
      ? { rows: details.keys, truncated: details.truncated }
      : undefined,
  };
}

/** An SSH key is a fingerprint and an algorithm; everything else is absent. */
export function sshKeyFacts(fingerprint: string, algorithm: string): KeyFacts {
  return { fingerprint, algorithm };
}

/**
 * Every key gets a row with its FULL fingerprint: that is the user's only
 * out-of-band check against GitHub (or anything between) handing back a
 * key the contact never published. Never summarise or truncate.
 */
export function sshGroupKeyFacts(
  members: readonly ContactRecipient[],
): KeyFacts {
  return {
    // Head fingerprint only for exactly one key; with several it would
    // imply a primary key (see `fingerprint`).
    ...(members.length === 1 ? { fingerprint: members[0].keyId } : {}),
    algorithm: members[0].algorithm,
    components: {
      rows: members.map((m) => ({
        fingerprint: m.keyId,
        algorithm: m.algorithm,
        isPrimary: false,
        // An age recipient that parses IS an encryption key; age has no signatures.
        canSign: false,
        canEncrypt: true,
        canCertify: false,
        canAuthenticate: false,
        status: "active" as const,
      })),
      truncated: false,
      title: t("common_keys"),
      rowLabel: t("keys_group_row_label"),
    },
  };
}
