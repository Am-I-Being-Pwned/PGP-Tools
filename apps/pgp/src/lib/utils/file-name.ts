/**
 * File names are attacker-chosen and shown next to signature verdicts:
 * strip bidi overrides (RLO turns "inv<RLO>csa.exe" into "invexe.asc"),
 * invisible and control characters. Lookalikes are left for MarkedText.
 */
/* eslint-disable no-control-regex -- finding control characters is the point */
const UNSAFE =
  /[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/gu;
/* eslint-enable no-control-regex */

export function safeFileName(name: string): string {
  return name.replace(UNSAFE, "");
}

/** Shortened from the middle so the extension stays visible. */
export function displayFileName(name: string, max = 60): string {
  const clean = [...safeFileName(name)];
  if (clean.length <= max) return clean.join("");
  const tail = Math.min(16, Math.floor(max / 3));
  return `${clean.slice(0, max - tail - 1).join("")}…${clean.slice(-tail).join("")}`;
}
