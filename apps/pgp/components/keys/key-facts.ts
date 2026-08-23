import type { KeyDetails, KeyInfo } from "../../lib/pgp/types";
import type { ContactRecipient } from "../../lib/storage/contacts";

/**
 * What the key body RENDERS, as opposed to what any one engine parses.
 *
 * KeyPreviewBody used to take an OpenPGP `KeyInfo` directly, which quietly
 * made "a key" mean "an OpenPGP certificate": user IDs, a creation date,
 * an expiry, subkeys. Other engines have none of that -- an SSH key is a
 * fingerprint and an algorithm, and nothing else -- so the body takes
 * these facts instead, and each engine supplies the ones it has. A fact
 * that is absent simply doesn't render; it is never a blank row.
 *
 * Every field is derived at the call site (see {@link pgpKeyFacts}), so
 * the body stays presentational and no engine's types leak into it.
 */

/**
 * One component key of a certificate -- the primary key or a subkey.
 *
 * Structurally a subset of OpenPGP's `SubkeyDetail`, so the adapter is a
 * pass-through rather than a mapping, but named for what the UI does with
 * it: engines that are a single key (SSH, CRX) supply no rows at all and
 * the section doesn't render.
 */
export interface ComponentKeyRow {
  fingerprint: string;
  algorithm: string;
  /** Public-key size in bits, when the algorithm has a meaningful one. */
  bits?: number;
  /** Absent for an engine whose keys carry no creation date -- an SSH
   *  key records none, and a row that printed one anyway would be
   *  printing the epoch. Absent means the clause isn't rendered, the
   *  same rule the facts card above already follows. */
  createdAt?: number;
  /** `null` renders "never expires"; absent means the engine has no
   *  concept of expiry and nothing is said either way. */
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

/** The engine's verdict on the key, in the terms the health banner needs.
 *  Absent means the engine has no verdict to offer, and no banner shows. */
export interface KeyHealth {
  /** The engine accepts it for receiving encrypted messages. */
  usableForEncryption: boolean;
  /** The engine accepts it for producing signatures. */
  usableForSigning: boolean;
  /** Why the engine rejected it, when it did (e.g. a SHA-1 self-sig). */
  policyError?: string;
}

export interface KeyFacts {
  /**
   * The identifier shown in the facts card and copied by the button
   * beside it, grouped into 4-character blocks. An OpenPGP fingerprint
   * today; an SSH public-key hash later.
   */
  fingerprint: string;
  /** Raw algorithm name; the body runs it through `formatAlgorithm`. */
  algorithm: string;
  /** Omitted by engines whose keys carry no creation date. */
  createdAt?: number;
  /** `null` renders "Never"; omitted means the engine has no concept of
   *  expiry and the row doesn't render at all. */
  expiresAt?: number | null;
  health?: KeyHealth;
  /** The certificate broken down into its component keys. Omitted when
   *  the breakdown failed to parse, or the engine has no such thing. */
  components?: {
    rows: ComponentKeyRow[];
    /** The cert carried more rows than the parser's cap. */
    truncated: boolean;
    /** Section heading noun. Defaults to "Subkeys", which is what an
     *  OpenPGP certificate's components are -- a fetched contact's are
     *  separate keys belonging to one person, and calling those subkeys
     *  would be saying something untrue about them. */
    title?: string;
    /** Per-row noun, defaulting to "Subkey", for the same reason. */
    rowLabel?: string;
  };
}

/**
 * OpenPGP -> presentation. `details` is optional because a cert whose
 * breakdown fails to parse still previews from its `KeyInfo`: the subkey
 * section, the bit count and the revocation banner simply don't render.
 */
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

/**
 * SSH -> presentation.
 *
 * An SSH key is a fingerprint and an algorithm, and genuinely nothing
 * else: no user IDs, no creation date, no expiry, no subkeys, and no
 * engine verdict beyond "it parsed" (an age recipient that parses IS
 * usable, so a health banner could only ever say so). Everything else is
 * therefore ABSENT rather than null -- absent means the row doesn't
 * render, which is what makes this a two-row facts card instead of a
 * certificate with four blanks in it.
 */
export function sshKeyFacts(fingerprint: string, algorithm: string): KeyFacts {
  return { fingerprint, algorithm };
}

/**
 * A multi-key contact -> presentation.
 *
 * Every key gets a row, and every fingerprint is shown IN FULL. Not
 * summarised as "3 keys": the fingerprints are the only out-of-band
 * check the user has -- they can read them off github.com/<user>.keys,
 * or ask the person over another channel -- and the threat this import
 * has to stay checkable against is GitHub (or anything between) handing
 * back a key the user's contact never published. A count tells you
 * nothing about that; a truncated list tells you nothing about the key
 * it truncated.
 *
 * The facts card keeps showing the FIRST key's fingerprint, because
 * that is the identity of the stored record (see `recipientsField`), and
 * the rows list all of them including that one.
 */
export function sshGroupKeyFacts(
  members: readonly ContactRecipient[],
): KeyFacts {
  return {
    fingerprint: members[0].keyId,
    algorithm: members[0].algorithm,
    components: {
      // None is `isPrimary`: they are peers, not a certificate, and the
      // body lists exactly the non-primary rows.
      rows: members.map((m) => ({
        fingerprint: m.keyId,
        algorithm: m.algorithm,
        isPrimary: false,
        // An age recipient that parses IS an encryption key, and can be
        // nothing else -- there are no signatures in age.
        canSign: false,
        canEncrypt: true,
        canCertify: false,
        canAuthenticate: false,
        status: "active" as const,
      })),
      truncated: false,
      title: "Keys",
      rowLabel: "Key",
    },
  };
}
