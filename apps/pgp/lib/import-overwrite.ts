import { format } from "date-fns";

/** A stored key record an import can collide with. Both `ProtectedKeyBlob`
 *  (keyring, `createdAt`) and `PublicContactKey` (contacts, `addedAt` +
 *  `expiresAt`) satisfy it structurally. */
export interface ExistingKeyEntry {
  keyId: string;
  userIds: string[];
  addedAt?: number;
  createdAt?: number;
  expiresAt?: number | null;
}

/** An import that would replace a stored key, with display metadata for
 *  the confirmation step. */
export interface ImportOverwrite {
  /** Primary user ID of the stored key being replaced. */
  userId: string;
  /** When the stored key was added, if recorded. */
  addedAt: number | null;
  /** Cheap human-readable field changes (expiry, new user IDs). */
  changes: string[];
}

/**
 * Decide whether importing a key updates an existing entry (same
 * fingerprint) or is a clean new import. Returns the collision details
 * for the confirm step, or null when the fingerprint is unknown.
 */
export function detectImportOverwrite(
  fingerprint: string,
  existing: ExistingKeyEntry[],
  incoming?: { expiresAt?: number | null; userIds?: string[] },
): ImportOverwrite | null {
  const wanted = fingerprint.toUpperCase();
  const match = existing.find((e) => e.keyId.toUpperCase() === wanted);
  if (!match) return null;

  const changes: string[] = [];
  if (incoming) {
    // Expiry diff only when both sides actually record one (the keyring
    // doesn't store expiry, so a keyring collision skips this line).
    if (
      match.expiresAt !== undefined &&
      incoming.expiresAt !== undefined &&
      (incoming.expiresAt ?? null) !== (match.expiresAt ?? null)
    ) {
      changes.push(
        incoming.expiresAt == null
          ? "no longer expires"
          : `new expiry: ${format(incoming.expiresAt, "PPP")}`,
      );
    }
    const known = new Set(match.userIds);
    const newIds = (incoming.userIds ?? []).filter((u) => !known.has(u));
    if (newIds.length > 0) {
      changes.push(`${newIds.length} new user ID${newIds.length === 1 ? "" : "s"}`);
    }
  }

  return {
    userId: match.userIds[0] ?? match.keyId.slice(-16),
    addedAt: match.addedAt ?? match.createdAt ?? null,
    changes,
  };
}
