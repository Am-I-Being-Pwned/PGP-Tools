/**
 * Recipient picker ordering: recently-used recipients surface first
 * (most recent first), the rest follow alphabetically. The recency list
 * itself is a small capped preference of key fingerprints updated after
 * each successful encrypt.
 */

import { formatKeyDisplayName } from "./utils/key-naming";

/** Maximum number of fingerprints kept in the recents preference, and
 *  the maximum size of the picker's "Recent" section. */
export const RECENT_RECIPIENTS_CAP = 10;

/** The minimal shape the recipient helpers need -- both
 *  `PublicContactKey` and `ProtectedKeyBlob` satisfy it. */
export interface RecipientLike {
  keyId: string;
  userIds: string[];
}

/** An ordered split of the picker's options: `recent` first (in the
 *  recency list's order), then `rest` alphabetically by display name. */
export interface OrderedRecipients<T> {
  recent: T[];
  rest: T[];
}

function displayName(item: RecipientLike): string {
  return formatKeyDisplayName(item.userIds[0]).name.toLowerCase();
}

/**
 * Split `items` into the recently-used ones (ordered as in `recents`,
 * most-recent-first, capped) and the rest (alphabetical by display
 * name). Fingerprints in `recents` with no matching item are ignored.
 */
export function orderRecipients<T extends RecipientLike>(
  items: T[],
  recents: string[],
  cap: number = RECENT_RECIPIENTS_CAP,
): OrderedRecipients<T> {
  const byId = new Map(items.map((item) => [item.keyId, item]));
  const recent: T[] = [];
  for (const fingerprint of recents) {
    if (recent.length >= cap) break;
    const item = byId.get(fingerprint);
    if (item && !recent.includes(item)) recent.push(item);
  }
  const recentIds = new Set(recent.map((item) => item.keyId));
  const rest = items
    .filter((item) => !recentIds.has(item.keyId))
    .sort((a, b) => displayName(a).localeCompare(displayName(b)));
  return { recent, rest };
}

/**
 * Whether a picker option matches a search query. Every whitespace-
 * separated token of the query must appear (case-insensitive) somewhere
 * in the option's display name, detail (comment/email) or key id, so
 * "james rno" narrows across name and address together.
 * An empty/blank query matches everything.
 */
export function matchesRecipientSearch(
  item: RecipientLike,
  query: string,
): boolean {
  const tokens = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return true;
  const { name, detail } = formatKeyDisplayName(item.userIds[0]);
  const haystack = `${name} ${detail} ${item.keyId}`.toLowerCase();
  return tokens.every((token) => haystack.includes(token));
}

/**
 * Fold the recipients of a successful encrypt into the stored recency
 * list: used fingerprints move to the front (keeping their relative
 * order), duplicates collapse, and the result is capped.
 */
export function updateRecentRecipients(
  current: string[],
  used: string[],
  cap: number = RECENT_RECIPIENTS_CAP,
): string[] {
  const next: string[] = [];
  for (const fingerprint of [...used, ...current]) {
    if (!next.includes(fingerprint)) next.push(fingerprint);
  }
  return next.slice(0, cap);
}
