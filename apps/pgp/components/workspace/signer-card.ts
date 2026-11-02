import { t } from "~/lib/i18n";
import { contactClash, type IdentityConflict } from "~/lib/identity/binding";
import type { PublicContactKey } from "~/lib/storage/contacts";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";

/**
 * Everything the signer card shows, computed once so the panel and Reply's
 * reader tab render the SAME verdict (the tab gets this, not a bare contact,
 * so it cannot drop the clash pill, notes or warnings).
 */
export interface SignerCardState {
  contact: PublicContactKey;
  tone: "success" | "warning";
  label: string;
  note?: string;
  clash?: IdentityConflict;
  /** Signed by a key we do not hold. */
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
    clash:
      "armoredPublicKey" in signer && !unverified
        ? contactClash(signer.keyId, contacts, myKeys)
        : undefined,
  };
}

/** For the reader tab: only what is DISPLAYED -- no public key, clash holders cut to name + key id. */
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
