/** Parse "Name (comment) <email>" into parts. */
export function parseUserId(userId: string | undefined): {
  name: string;
  email: string;
  comment?: string;
} {
  if (!userId) return { name: "Unknown", email: "" };
  const match = /^(.+?)\s*(?:\((.+?)\)\s*)?<(.+?)>$/.exec(userId);
  if (!match) return { name: userId, email: "" };
  const name = match[1].trim();
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- match[2] is an optional capture group
  const comment = match[2]?.trim();
  const email = match[3].trim();
  return { name, comment, email };
}

/** Format for display in a combobox/selector: "name detail" */
export function formatKeyDisplayName(userId: string | undefined): {
  name: string;
  detail: string;
} {
  const { name, comment, email } = parseUserId(userId);
  const detail = comment ? `${comment} - ${email}` : email;
  return { name, detail };
}

/**
 * Anything with a display identity: one of the user's own keys, or a
 * contact. Both carry OpenPGP User IDs (an SSH key's comment stands in
 * as the sole element) and both can carry a local, user-set alias.
 */
export interface NamedKey {
  /** Local display name. Absent -- never `""` -- means "no alias set". */
  alias?: string;
  userIds: string[];
}

/**
 * The one place the alias-or-real-identity fallback is decided.
 *
 * Every name this app shows for a key or a contact comes from here, so
 * the fallback cannot drift between the card, the picker, the details
 * page and the search box -- which is exactly how a rename ends up
 * visible in three of the four. `undefined` means the subject has no
 * name at all (an SSH key with no comment); the caller decides what to
 * show instead, since a card, a filename and a search haystack want
 * different things.
 */
export function displayUserId(key: NamedKey): string | undefined {
  return key.alias ?? key.userIds[0];
}
