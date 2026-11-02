import { t, tn } from "./i18n";
import { formatDate } from "./i18n/format";

export interface ExistingKeyEntry {
  keyId: string;
  userIds: string[];
  addedAt?: number;
  createdAt?: number;
  expiresAt?: number | null;
}

export interface ImportOverwrite {
  userId: string;
  addedAt: number | null;
  changes: string[];
}

/** Collision details for the confirm step, or null for a new key. */
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
    // Only when both sides record expiry (the keyring doesn't).
    if (
      match.expiresAt !== undefined &&
      incoming.expiresAt !== undefined &&
      (incoming.expiresAt ?? null) !== (match.expiresAt ?? null)
    ) {
      changes.push(
        incoming.expiresAt == null
          ? t("import_change_no_expiry")
          : t("import_change_new_expiry", {
              date: formatDate(incoming.expiresAt),
            }),
      );
    }
    const known = new Set(match.userIds);
    const newIds = (incoming.userIds ?? []).filter((u) => !known.has(u));
    if (newIds.length > 0) {
      changes.push(tn("import_change_new_user_ids", newIds.length));
    }
  }

  return {
    userId: match.userIds[0] ?? match.keyId.slice(-16),
    addedAt: match.addedAt ?? match.createdAt ?? null,
    changes,
  };
}
