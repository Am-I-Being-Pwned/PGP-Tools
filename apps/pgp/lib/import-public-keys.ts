import { format } from "date-fns";

import type { KeyInfo } from "./pgp/types";
import type { PublicContactKey } from "./storage/contacts";
import { parseKeys } from "./pgp/wasm";

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
    return "This block contains no usable public key.";
  }
  if (keyInfo.expiresAt !== null && keyInfo.expiresAt < Date.now()) {
    return `This key expired on ${format(keyInfo.expiresAt, "PPP")}. Ask the owner for their current key.`;
  }
  return (
    keyInfo.policyError ??
    "This public key has no usable encryption or signing key."
  );
}

export interface PublicImportSummary {
  /** Contacts actually written. */
  added: number;
  /** Usable certs skipped because the keyId already exists. */
  skipped: number;
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
  existingKeyIds: string[],
  onImport: (contact: PublicContactKey) => Promise<void>,
): Promise<PublicImportSummary> {
  const summary: PublicImportSummary = {
    added: 0,
    skipped: 0,
    failed: 0,
    flagged: 0,
    rejectionReasons: [],
  };

  for (const block of blocks) {
    let certs;
    try {
      certs = await parseKeys(block);
    } catch {
      summary.failed++;
      continue;
    }

    const usable = certs.filter((c) => isUsableContact(c.keyInfo));
    if (usable.length === 0) {
      // Nothing live in this block: surface the first cert's reason.
      summary.failed++;
      summary.rejectionReasons.push(importRejectionMessage(certs[0]?.keyInfo));
      continue;
    }

    for (const { keyInfo, armored } of usable) {
      if (existingKeyIds.includes(keyInfo.keyId)) {
        summary.skipped++;
        continue;
      }
      await onImport({
        keyId: keyInfo.keyId,
        userIds: keyInfo.userIds,
        algorithm: keyInfo.algorithm,
        armoredPublicKey: armored,
        addedAt: Date.now(),
        lastUsedAt: Date.now(),
        expiresAt: keyInfo.expiresAt,
        // Sign-only keys are valid contacts (for verification) but can't
        // be offered as encryption recipients -- record which is which.
        usableForEncryption: keyInfo.usableForEncryption,
        // Allowed, but flagged (e.g. SHA-1 binding signature).
        securityWarning: keyInfo.securityWarning,
      });
      summary.added++;
      if (keyInfo.securityWarning) summary.flagged++;
    }
  }

  return summary;
}
