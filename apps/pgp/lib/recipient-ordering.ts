/** Recipient picker ordering: recently-used first, the rest alphabetical. */

import { displayUserId, formatKeyDisplayName } from "./utils/key-naming";

export const RECENT_RECIPIENTS_CAP = 10;

export interface RecipientLike {
  keyId: string;
  userIds: string[];
  /** Read through `displayUserId`, never directly, so ordering and search
   *  agree with what the picker shows. */
  alias?: string;
}

export interface OrderedRecipients<T> {
  recent: T[];
  rest: T[];
}

function displayName(item: RecipientLike): string {
  return formatKeyDisplayName(displayUserId(item)).name.toLowerCase();
}

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

/** Every query token must appear somewhere in name, detail, first User ID
 *  or key id. */
export function matchesRecipientSearch(
  item: RecipientLike,
  query: string,
): boolean {
  const tokens = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return true;
  const { name, detail } = formatKeyDisplayName(displayUserId(item));
  // Keep the certificate's name searchable after a rename.
  const haystack =
    `${name} ${detail} ${item.userIds[0] ?? ""} ${item.keyId}`.toLowerCase();
  return tokens.every((token) => haystack.includes(token));
}

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
