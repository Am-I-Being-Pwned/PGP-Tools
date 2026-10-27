import type { IdentityConflict } from "../../lib/identity/binding";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import { t } from "../../lib/i18n";
import { contactClash } from "../../lib/identity/binding";

/**
 * Everything the signer card shows, worked out once.
 *
 * Kept apart from the card itself so the panel and Reply's reader tab
 * render the SAME verdict: the tab is handed this state (see
 * `lib/reader-protocol`) instead of a bare contact, so it cannot drop the
 * clash pill, the "not marked verified by you" or "may have been
 * forwarded" note, the signing date or a lookalike / SHA-1 warning.
 */
export interface SignerCardState {
  contact: PublicContactKey;
  tone: "success" | "warning";
  /** The band's label: "Signature verified", or its caveat. */
  label: string;
  note?: string;
  /** Another contact (or the user) shares this signer's name or address. */
  clash?: IdentityConflict;
  /** Signed, but by a key we do not hold: no clash, no key details. */
  unverified: boolean;
}

export function signerCardState({
  signer,
  tone,
  note,
  caveat,
  statusText,
  extraNote,
  contacts,
  myKeys,
}: {
  signer: PublicContactKey | ProtectedKeyBlob;
  tone: "success" | "warning";
  note?: string | null;
  caveat?: string | null;
  statusText?: string;
  /** Added after `note` (the translation's "covers the original"). */
  extraNote?: string | null;
  contacts: PublicContactKey[];
  myKeys: ProtectedKeyBlob[];
}): SignerCardState {
  const unverified = tone === "warning" && !caveat;
  return {
    contact: signerAsContact(signer),
    tone,
    unverified,
    label: unverified
      ? t("workspace_unverified")
      : (caveat ?? statusText ?? t("workspace_signature_verified")),
    note: unverified
      ? statusText
      : [note, extraNote].filter(Boolean).join(" · ") || undefined,
    // Signed by a contact who shares a name or address with another:
    // the same pill as on the card, so the two read apart here too.
    clash:
      "armoredPublicKey" in signer && !unverified
        ? contactClash(signer.keyId, contacts, myKeys)
        : undefined,
  };
}

/**
 * The card state with only what it DISPLAYS, for the reader tab: no
 * public key (neither the top-level one nor any per-key `recipients`),
 * and each clash holder cut down to the name and key id its pill reads.
 */
export function displayOnlySignerCard(state: SignerCardState): SignerCardState {
  const c = state.contact;
  const contact: PublicContactKey = {
    keyId: c.keyId,
    userIds: c.userIds,
    algorithm: c.algorithm,
    alias: c.alias,
    kind: c.kind,
    expiresAt: c.expiresAt,
    source: c.source,
    revoked: c.revoked,
    verified: c.verified,
    verifiedAt: c.verifiedAt,
    securityWarning: c.securityWarning,
    lookalike: c.lookalike,
    armoredPublicKey: "",
    addedAt: 0,
    lastUsedAt: 0,
  };
  // Absent stays absent, as on a stored record.
  for (const k of Object.keys(contact) as (keyof PublicContactKey)[]) {
    if (contact[k] === undefined) delete contact[k];
  }
  return {
    ...state,
    contact,
    clash: state.clash && {
      kind: state.clash.kind,
      ...(state.clash.lookalike ? { lookalike: true as const } : {}),
      holders: state.clash.holders.map((h) => ({
        keyId: h.keyId,
        userIds: h.userIds,
        ...(h.own ? { own: true as const } : {}),
      })),
    },
  };
}

/** A signer as the contact record `ContactCard` renders: a contact as
 *  is, an own key reshaped. */
export function signerAsContact(
  signer: PublicContactKey | ProtectedKeyBlob,
): PublicContactKey {
  return "armoredPublicKey" in signer
    ? signer
    : {
        keyId: signer.keyId,
        userIds: signer.userIds,
        algorithm: signer.algorithm,
        armoredPublicKey: signer.publicKeyArmored,
        addedAt: 0,
        lastUsedAt: 0,
      };
}
