/** Fingerprint layout, pure so tests can import it without components. */

/** By shape, not the `SHA256:` prefix, so an unknown format isn't mangled. */
export const HEX_FINGERPRINT = /^[0-9a-fA-F]+$/;

/**
 * Aligned rows of 4-char groups, as GnuPG prints them. ONLY for a hex
 * fingerprint: anything else is one unbroken line, copied byte-for-byte.
 * A mangled SSH copy silently defeats the out-of-band check
 * (T-GITHUB-KEY-SUBSTITUTION).
 */
export function fingerprintLines(fp: string): string[] {
  if (!HEX_FINGERPRINT.test(fp)) return [fp];
  const groups = fp.match(/.{1,4}/g) ?? [fp];
  const lines: string[] = [];
  for (let i = 0; i < groups.length; i += 5) {
    lines.push(groups.slice(i, i + 5).join(" "));
  }
  return lines;
}

/** Last 16 hex digits, never fewer (shorter collides), as two lines.
 *  Callers check {@link HEX_FINGERPRINT} first. */
export function longIdLines(fingerprint: string): [string, string] {
  const id = fingerprint.slice(-16);
  return [
    `${id.slice(0, 4)} ${id.slice(4, 8)}`,
    `${id.slice(8, 12)} ${id.slice(12)}`,
  ];
}
