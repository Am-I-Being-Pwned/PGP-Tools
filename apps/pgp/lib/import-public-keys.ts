import type { PublicContactKey } from "./storage/contacts";
import { parseKeys } from "./pgp/wasm";

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

    const usable = certs.filter((c) => c.keyInfo.usableForEncryption);
    if (usable.length === 0) {
      // Nothing live in this block: surface the first cert's reason.
      summary.failed++;
      summary.rejectionReasons.push(
        certs[0]?.keyInfo.policyError ??
          "no usable encryption subkey on this key",
      );
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
        // Allowed, but flagged (e.g. SHA-1 binding signature).
        securityWarning: keyInfo.securityWarning,
      });
      summary.added++;
      if (keyInfo.securityWarning) summary.flagged++;
    }
  }

  return summary;
}
