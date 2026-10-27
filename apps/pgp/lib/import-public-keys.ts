import type { KeyInfo } from "./pgp/types";
import type { ParsedCert } from "./pgp/wasm";
import type { PublicContactKey } from "./storage/contacts";
import { t } from "./i18n";
import { formatDate } from "./i18n/format";
import { mergePublicKey, parseKeys, revocationIssuers } from "./pgp/wasm";
import { IDENTITY_VERSION, updateContactAsync } from "./storage/contacts";

/** A stored public cert an import can land on. */
export interface StoredCert {
  keyId: string;
  armored: string;
}

/**
 * Fold an imported copy of a key into the stored copy of the SAME key.
 *
 * Every re-import goes through here rather than replacing the stored
 * cert: a merge can only add what the owner signed, so an old or
 * stripped copy can't bring back a subkey the owner revoked, and a
 * revoked copy revokes the contact instead of being turned away as
 * "unusable" while the stale copy stays live.
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
 * Merge `incomingArmored` into the stored contact `keyId` AS IT IS NOW,
 * inside the contacts lock, and save it. For a write that starts from an
 * older copy -- a keyserver check that took a while -- so nothing changed
 * meanwhile (an imported revocation, a rename, a delete) is undone.
 * Resolves undefined, writing nothing, when the contact is gone.
 *
 * This is the revocation check's write, and it never changes WHO the
 * contact is. Every other way a key gains a User ID goes through the
 * import Review, which checks it against everyone else and asks; this
 * one ran with no Review, so a keyserver copy carrying a new User ID
 * bound it to the contact silently, and kept "verified" on it. So:
 *
 *  - nothing new about who it is: saved as before (a revocation, a new
 *    expiry, a new subkey);
 *  - new User IDs, and revoked: the revocation is saved (it must
 *    stick), under the contact's OLD User IDs, and "verified" is dropped
 *    -- the cert the user compared is no longer the one stored;
 *  - new User IDs, not revoked: NOTHING is written, and `needsReview`
 *    says so, for the caller to send the copy through the import Review
 *    like any other update.
 */
export async function mergeIntoContact(
  keyId: string,
  incomingArmored: string,
): Promise<
  | { contact: PublicContactKey; keyInfo: KeyInfo; needsReview?: true }
  | undefined
> {
  let keyInfo: KeyInfo | undefined;
  // Widened: it is set inside the callback below, which narrowing from a
  // plain `false` cannot see.
  let needsReview = false as boolean;
  const contact = await updateContactAsync(keyId, async (current) => {
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
            // Who it is stays who the user saved: the old User IDs, and
            // the lookalike flag they were derived with.
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

/**
 * A bare revocation certificate (`gpg --gen-revoke`, or this app's own
 * export) carries no key, so it can only ever mean "revoke a contact I
 * already have". Returns the merged contact, `"unknown"` when it names a
 * key that isn't stored, or null when the text isn't a revocation.
 */
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

/** The stored-record fields a parsed cert decides. */
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
    // Sign-only keys are valid contacts (for verification) but can't
    // be offered as encryption recipients -- record which is which.
    usableForEncryption: keyInfo.usableForEncryption,
    // Allowed, but flagged (e.g. SHA-1 binding signature).
    securityWarning: keyInfo.securityWarning,
    // Written only when true, so an unrevoked record keeps its bytes.
    ...(keyInfo.revoked ? { revoked: true } : {}),
    ...(keyInfo.lookalike ? { lookalike: true } : {}),
    identityVersion: IDENTITY_VERSION,
  };
}

/** A contact is worth keeping if you can either encrypt to it OR verify
 *  its signatures. Sign-only keys (no encryption subkey) are perfectly
 *  valid contacts -- you just can't encrypt to them. */
export function isUsableContact(keyInfo: KeyInfo): boolean {
  return keyInfo.usableForEncryption || keyInfo.usableForSigning;
}

/** Human-readable reason a cert can't be imported as a contact. Expiry
 *  is by far the most common cause, so call it out with the date rather
 *  than hiding it in the generic "expired, revoked, or unsupported"
 *  catch-all. */
export function importRejectionMessage(keyInfo: KeyInfo | undefined): string {
  if (!keyInfo) {
    return t("import_reject_no_public_key");
  }
  if (keyInfo.expiresAt !== null && keyInfo.expiresAt < Date.now()) {
    return t("import_reject_expired", { date: formatDate(keyInfo.expiresAt) });
  }
  return keyInfo.policyError ?? t("import_reject_unusable");
}
