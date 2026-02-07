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
