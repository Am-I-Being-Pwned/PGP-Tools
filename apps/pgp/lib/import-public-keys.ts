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
 */
export async function mergeIntoContact(
  keyId: string,
  incomingArmored: string,
): Promise<{ contact: PublicContactKey; keyInfo: KeyInfo } | undefined> {
  let keyInfo: KeyInfo | undefined;
  const contact = await updateContactAsync(keyId, async (current) => {
    const merged = await mergeIntoStored(
      { keyId: current.keyId, armored: current.armoredPublicKey },
      incomingArmored,
    );
    keyInfo = merged.keyInfo;
    const { revoked: _revoked, lookalike: _lookalike, ...rest } = current;
    return {
      ...rest,
      armoredPublicKey: merged.armored,
      ...contactFieldsFrom(merged.keyInfo),
    };
  });
  return contact && keyInfo ? { contact, keyInfo } : undefined;
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

export interface PublicImportSummary {
  /** Contacts actually written. */
  added: number;
  /** Usable certs re-imported over an existing contact (same
   *  fingerprint): the stored record is refreshed -- new expiry, UIDs,
   *  subkeys -- rather than silently skipped, so a contact who extends
   *  their key's validity doesn't stay stale until encryption breaks. */
  updated: number;
  /** Blocks with no usable cert (or that failed to parse). */
  failed: number;
  /** Imported certs carrying a security warning (e.g. SHA-1). */
  flagged: number;
  /** First policy rejection reason per failed block, for display. */
  rejectionReasons: string[];
}

/**
 * Import a list of armored public-key blocks as contacts. Shared by the
 * contacts drop zone and the bulk key import.
 *
 * A single armored block may bundle several certs (e.g. a publisher's
 * yearly-rotated keys); each block is split so we import the live
 * cert(s) and store each against its own armor -- not the whole blob,
 * which would otherwise encrypt to the first (usually expired) cert.
 * When a block has a usable cert, its unusable siblings are treated as
 * stale rotations and dropped silently rather than reported as failures.
 */
export async function importPublicKeyBlocks(
  blocks: string[],
  existing: readonly StoredCert[],
  onImport: (contact: PublicContactKey) => Promise<void>,
): Promise<PublicImportSummary> {
  const summary: PublicImportSummary = {
    added: 0,
    updated: 0,
    failed: 0,
    flagged: 0,
    rejectionReasons: [],
  };

  const write = async (cert: ParsedCert, isRefresh: boolean) => {
    const { keyInfo, armored } = cert;
    await onImport({
      keyId: keyInfo.keyId,
      algorithm: keyInfo.algorithm,
      armoredPublicKey: armored,
      addedAt: Date.now(),
      lastUsedAt: Date.now(),
      ...contactFieldsFrom(keyInfo),
    });
    if (isRefresh) summary.updated++;
    else summary.added++;
    // Counted for the SHA-1 toast, so SHA-1 warnings only.
    if (keyInfo.securityWarning?.includes("SHA-1")) summary.flagged++;
  };

  for (const block of blocks) {
    let certs;
    try {
      certs = await parseKeys(block);
    } catch {
      // One unreadable stored cert must not abort the rest of the batch.
      const revoked = await applyRevocation(block, existing).catch(() => null);
      if (revoked && revoked !== "unknown") {
        await write(revoked, true);
        continue;
      }
      summary.failed++;
      if (revoked === "unknown") {
        summary.rejectionReasons.push(t("import_reject_revocation_unknown"));
      }
      continue;
    }

    // Same fingerprint as an existing contact: merge into it, usable or
    // not -- that is how a revocation reaches a stored contact.
    let wrote = false;
    for (const cert of certs) {
      const match = existing.find(
        (e) => e.keyId.toUpperCase() === cert.keyInfo.keyId.toUpperCase(),
      );
      if (!match) continue;
      await write(await mergeIntoStored(match, cert.armored), true);
      wrote = true;
    }

    const fresh = certs.filter(
      (c) =>
        isUsableContact(c.keyInfo) &&
        !existing.some(
          (e) => e.keyId.toUpperCase() === c.keyInfo.keyId.toUpperCase(),
        ),
    );
    if (fresh.length === 0 && !wrote) {
      // Nothing live in this block: surface the first cert's reason.
      summary.failed++;
      summary.rejectionReasons.push(importRejectionMessage(certs[0]?.keyInfo));
      continue;
    }
    for (const cert of fresh) await write(cert, false);
  }

  return summary;
}
