/**
 * A file name as this app shows it, or saves under it.
 *
 * File names are attacker-chosen -- an attachment, a download -- and the
 * panel puts them next to signature verdicts. Raw, a name can reorder
 * the text around it (a right-to-left override turns "inv<RLO>csa.exe"
 * into "invexe.asc"), hide characters (zero-width), or break a line.
 * So bidi controls, invisible format characters and control characters
 * are removed. Lookalike letters are left for MarkedText to point at.
 */
/* eslint-disable no-control-regex -- finding control characters is the point */
const UNSAFE =
  /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/gu;
/* eslint-enable no-control-regex */

export function safeFileName(name: string): string {
  return name.replace(UNSAFE, "");
}

/** {@link safeFileName}, shortened from the MIDDLE past `max` characters
 *  so the extension -- the part that says what the file is -- stays. */
export function displayFileName(name: string, max = 60): string {
  const clean = [...safeFileName(name)];
  if (clean.length <= max) return clean.join("");
  const tail = Math.min(16, Math.floor(max / 3));
  return `${clean.slice(0, max - tail - 1).join("")}…${clean.slice(-tail).join("")}`;
}

/**
 * Text holding characters that change how it displays without showing
 * themselves: bidi controls (a right-to-left override makes "0001" read
 * as "1000"), zero-width and other format characters, and control
 * characters other than tab and line breaks. For SIGNED text these are
 * part of what was signed, so they are reported, not removed.
 */
/* eslint-disable no-control-regex -- finding control characters is the point */
const HIDDEN =
  /[\u0000-\u0008\u000b-\u000c\u000e-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/u;
/* eslint-enable no-control-regex */

export function hasHiddenCharacters(text: string): boolean {
  return HIDDEN.test(text);
}
