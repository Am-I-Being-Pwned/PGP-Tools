import type { KeyInfo } from "./pgp/types";
import type { ParsedCert } from "./pgp/wasm";
import type { PublicContactKey } from "./storage/contacts";
import { t } from "./i18n";
import { formatDate } from "./i18n/format";
import { mergePublicKey, parseKeys, revocationIssuers } from "./pgp/wasm";
import { IDENTITY_VERSION, updateContact } from "./storage/contacts";

export interface StoredCert {
  keyId: string;
  armored: string;
}

/**
 * Fold an imported copy of a key into the stored copy. Every re-import
 * merges, never replaces: a stripped copy can't resurrect a revoked
 * subkey, and a revoked copy revokes the contact.
 */
export async function mergeIntoStored(
  stored: StoredCert,
  incomingArmored: string,
): Promise<ParsedCert> {
  const merged = await mergePublicKey(stored.armored, incomingArmored);
  const [cert] = await parseKeys(merged);
  return cert;
}

/**
 * Merge into the stored contact AS IT IS NOW, inside the contacts lock,
 * so nothing changed meanwhile is undone. Undefined if the contact is gone.
 *
 * The revocation check's write; it never changes WHO the contact is
 * without the import Review:
 *  - no new User IDs: saved;
 *  - new User IDs + revoked: revocation saved under the OLD User IDs,
 *    "verified" dropped;
 *  - new User IDs, not revoked: nothing written, `needsReview` set.
 */
export async function mergeIntoContact(
  keyId: string,
  incomingArmored: string,
): Promise<
  | { contact: PublicContactKey; keyInfo: KeyInfo; needsReview?: true }
  | undefined
> {
  let keyInfo: KeyInfo | undefined;
  // Widened: set inside the callback, which narrowing can't see.
  let needsReview = false as boolean;
  const contact = await updateContact(keyId, async (current) => {
    const merged = await mergeIntoStored(
      { keyId: current.keyId, armored: current.armoredPublicKey },
      incomingArmored,
    );
    keyInfo = merged.keyInfo;
    const before = new Set(current.userIds);
    const grows = merged.keyInfo.userIds.some((u) => !before.has(u));
    if (grows && !merged.keyInfo.revoked) {
      needsReview = true;
      return current;
    }
    const {
      revoked: _revoked,
      lookalike: _lookalike,
      verified: _verified,
      verifiedAt: _verifiedAt,
      ...rest
    } = current;
    const { lookalike, ...fields } = contactFieldsFrom(merged.keyInfo);
    return {
      ...rest,
      armoredPublicKey: merged.armored,
      ...fields,
      ...(grows
        ? {
            // Identity stays as the user saved it.
            userIds: current.userIds,
            ...(current.lookalike ? { lookalike: true as const } : {}),
          }
        : {
            ...(lookalike ? { lookalike } : {}),
            ...(current.verified
              ? { verified: true as const, verifiedAt: current.verifiedAt }
              : {}),
          }),
    };
  });
  if (!contact || !keyInfo) return undefined;
  return needsReview
    ? { contact, keyInfo, needsReview: true }
    : { contact, keyInfo };
}

/** Apply a bare revocation certificate to a stored contact. `"unknown"`
 *  when it names no stored key; null when not a revocation. */
export async function applyRevocation(
  text: string,
  stored: readonly StoredCert[],
): Promise<ParsedCert | "unknown" | null> {
  const issuers = await revocationIssuers(text);
  if (!issuers) return null;
  const match = stored.find((s) =>
    issuers.some((i) => s.keyId.toUpperCase().endsWith(i.toUpperCase())),
  );
  if (!match) return "unknown";
  return mergeIntoStored(match, text);
}

export function contactFieldsFrom(
  keyInfo: KeyInfo,
): Pick<
  PublicContactKey,
  | "userIds"
  | "expiresAt"
  | "usableForEncryption"
  | "securityWarning"
  | "revoked"
  | "lookalike"
  | "identityVersion"
> {
  return {
    userIds: keyInfo.userIds,
    expiresAt: keyInfo.expiresAt,
    usableForEncryption: keyInfo.usableForEncryption,
    securityWarning: keyInfo.securityWarning,
    // Written only when true, so an unrevoked record keeps its bytes.
    ...(keyInfo.revoked ? { revoked: true } : {}),
    ...(keyInfo.lookalike ? { lookalike: true } : {}),
    identityVersion: IDENTITY_VERSION,
  };
}

/** Sign-only keys are valid contacts (for verification). */
export function isUsableContact(keyInfo: KeyInfo): boolean {
  return keyInfo.usableForEncryption || keyInfo.usableForSigning;
}

/** Why a cert can't be imported; expiry (the common case) names the date. */
export function importRejectionMessage(keyInfo: KeyInfo | undefined): string {
  if (!keyInfo) {
    return t("import_reject_no_public_key");
  }
  if (keyInfo.expiresAt !== null && keyInfo.expiresAt < Date.now()) {
    return t("import_reject_expired", { date: formatDate(keyInfo.expiresAt) });
  }
  return keyInfo.policyError ?? t("import_reject_unusable");
}
