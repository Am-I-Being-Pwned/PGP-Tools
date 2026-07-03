/**
 * Reconstruct PGP armor from a context-menu selection.
 *
 * Chrome's `info.selectionText` collapses all whitespace (including
 * the line breaks PGP armor depends on) into single spaces. The armor
 * itself has enough structure that we can put the newlines back:
 *
 *   -----BEGIN PGP <TYPE> BLOCK-----
 *   <armor headers like "Version: ...", may have multi-word values>
 *   <blank line>
 *   <base64 data, wrapped to 64 chars per line>
 *   =<4-char base64 CRC>
 *   -----END PGP <TYPE> BLOCK-----
 *
 * Heuristics:
 *  - BEGIN/END markers survive collapse intact (they have no internal
 *    whitespace that would be ambiguous).
 *  - Armor headers always start with a token ending in `:`. Header
 *    values can have multiple whitespace-separated tokens (e.g.
 *    `Version: Encryption Desktop 10.4.1`); we keep consuming value
 *    tokens until we hit either another header (token ending in `:`)
 *    or the first long pure-base64 token (the data).
 *  - The CRC line is the last token matching `=XXXX` (5 chars,
 *    leading `=`, exactly 4 base64 chars).
 *  - Data is everything between the last header line and the CRC.
 */

const BEGIN_MARKER = /-----BEGIN PGP ([A-Z ]+?) BLOCK-----/;
const END_MARKER = /-----END PGP ([A-Z ]+?) BLOCK-----/;
const BASE64_TOKEN = /^[A-Za-z0-9+/=]+$/;
const CRC_TOKEN = /^=[A-Za-z0-9+/]{4}$/;
const HEADER_KEY = /^[A-Za-z][A-Za-z0-9-]*:$/;
const MIN_DATA_TOKEN_LEN = 40;

/** True if the text contains a BEGIN PGP marker but the line right
 *  after it has been collapsed (i.e. no `\n` after the marker). */
export function looksLikeCollapsedArmor(text: string): boolean {
  if (!BEGIN_MARKER.test(text)) return false;
  return !/-----BEGIN PGP [A-Z ]+ BLOCK-----\n/.test(text);
}

/** Best-effort reconstruction. If anything looks off, returns the
 *  original text unchanged so the caller's parser surfaces the real
 *  error rather than something we mangled. */
export function reconstructArmor(text: string): string {
  const bm = BEGIN_MARKER.exec(text);
  const em = END_MARKER.exec(text);
  if (!bm || !em) return text;
  if (bm[1] !== em[1]) return text; // BEGIN/END types don't match -- bail

  const blockType = bm[1];
  const middle = text.slice(bm.index + bm[0].length, em.index).trim();
  const tokens = middle.split(/\s+/).filter((t) => t.length > 0);
  if (tokens.length === 0) return text;

  // Locate the first long pure-base64 token: this is the start of data.
  let dataStart = -1;
  for (let i = 0; i < tokens.length; i++) {
    if (
      tokens[i].length >= MIN_DATA_TOKEN_LEN &&
      BASE64_TOKEN.test(tokens[i])
    ) {
      dataStart = i;
      break;
    }
  }
  if (dataStart === -1) return text;

  // Locate the CRC token from the end (last `=XXXX`).
  let crcIdx = -1;
  for (let i = tokens.length - 1; i >= dataStart; i--) {
    if (CRC_TOKEN.test(tokens[i])) {
      crcIdx = i;
      break;
    }
  }

  const headerTokens = tokens.slice(0, dataStart);
  const dataTokens =
    crcIdx === -1
      ? tokens.slice(dataStart)
      : tokens.slice(dataStart, crcIdx);
  const crc = crcIdx === -1 ? "" : tokens[crcIdx];

  // Group header tokens into "Key: value..." lines.
  const headerLines: string[] = [];
  let i = 0;
  while (i < headerTokens.length) {
    if (!HEADER_KEY.test(headerTokens[i])) {
      // Skip stray tokens that don't start a header (shouldn't happen
      // for valid armor, but be defensive).
      i++;
      continue;
    }
    const key = headerTokens[i];
    i++;
    const valueParts: string[] = [];
    while (i < headerTokens.length && !HEADER_KEY.test(headerTokens[i])) {
      valueParts.push(headerTokens[i]);
      i++;
    }
    headerLines.push(`${key} ${valueParts.join(" ")}`);
  }

  // Re-wrap base64 data to 64 chars per line.
  const wrapped = dataTokens.join("").replace(/(.{64})/g, "$1\n").replace(/\n$/, "");

  const headerBlock =
    headerLines.length > 0 ? headerLines.join("\n") + "\n\n" : "\n";
  const crcBlock = crc ? `\n${crc}` : "";

  return (
    `-----BEGIN PGP ${blockType} BLOCK-----\n` +
    headerBlock +
    wrapped +
    crcBlock +
    `\n-----END PGP ${blockType} BLOCK-----`
  );
}

/** Pass-through unless the input looks like collapsed armor. */
export function recoverArmorIfNeeded(text: string): string {
  return looksLikeCollapsedArmor(text) ? reconstructArmor(text) : text;
}
