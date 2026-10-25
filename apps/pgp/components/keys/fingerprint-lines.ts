/**
 * How a fingerprint is laid out for reading and copying. Pure, and kept
 * apart from KeyPreviewBody (which renders it) so the unit tests can
 * import it without pulling in any component.
 */

/** A fingerprint that is nothing but hex digits -- an OpenPGP one. The
 *  shape, not the prefix: an OpenSSH fingerprint happens to start
 *  `SHA256:`, but testing for that literal would mangle the next non-hex
 *  format just as badly, and this predicate keeps working without being
 *  told about it. */
export const HEX_FINGERPRINT = /^[0-9a-fA-F]+$/;

/**
 * Fingerprint as aligned rows of five 4-char groups (the way GnuPG
 * prints it), so two fingerprints can be compared block by block.
 *
 * ONLY for a hex fingerprint. An OpenSSH one is `SHA256:` followed by
 * unpadded base64, where the grouping is not a convention but damage:
 * it split the prefix itself (`SHA2 56:I oCz+ ...`) and chopped the
 * base64 at offsets that mean nothing. That reached the clipboard too
 * (see `handleCopyFingerprint` in KeyPreviewBody), and comparing a fingerprint out of band
 * is the ONLY check a user has that GitHub served the key its owner
 * published -- `T-GITHUB-KEY-SUBSTITUTION` in
 * `lib/security/threat-model.ts`. A mangled copy defeats that silently:
 * it neither matches nor visibly fails.
 *
 * So a non-hex fingerprint is returned as ONE unbroken line -- rendered
 * whole, and copied byte-for-byte as `ssh-keygen -lf` prints it.
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

/** The long key id of a hex fingerprint -- its last 16 digits, never
 *  fewer (a shorter tail is too easy to collide) -- as two lines of two
 *  groups ("E3AA 9980" / "1E25 0E69"), the form a list row shows.
 *  Callers check {@link HEX_FINGERPRINT} first -- the tail of anything
 *  else (an SSH hash, a CRX extension id) identifies nothing. */
export function longIdLines(fingerprint: string): [string, string] {
  const id = fingerprint.slice(-16);
  return [
    `${id.slice(0, 4)} ${id.slice(4, 8)}`,
    `${id.slice(8, 12)} ${id.slice(12)}`,
  ];
}
