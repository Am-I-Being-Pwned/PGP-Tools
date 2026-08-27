/**
 * Put PGP armor back together after something has mangled it.
 *
 * TWO DIFFERENT DAMAGE MODELS, two repairs, and they are separate
 * because what makes them safe is different:
 *
 *  1. WHITESPACE COLLAPSE ({@link reconstructArmor}) -- Chrome's
 *     `info.selectionText` turns every run of whitespace into a single
 *     space, so the line structure has to be inferred from the armor's
 *     grammar. Heuristic, and it bails rather than guess.
 *
 *  2. ESCAPING ({@link repairArmorEscapes}) -- the text went through a
 *     machine that represents newlines as something else: a JSON string
 *     (`\n`), an HTML page (`<br>`), a URL (`%0A`). This one is not a
 *     heuristic. Base64 has a fixed alphabet, and none of `\`, `<`, `>`,
 *     `%`, `&` or `;` is in it, so inside an armor block those tokens
 *     cannot be data -- they can only be damage, and reversing them is
 *     exact rather than clever.
 *
 * BOTH ARE STRICTLY BLOCK-SCOPED. Only the text between a matched
 * BEGIN/END pair is ever rewritten; everything else is returned byte for
 * byte. That is what makes it safe to run this over the workspace input
 * box, which also holds messages the user is COMPOSING -- someone typing
 * `console.log("a\nb")` must get their backslash-n back unchanged, and
 * a global unescape would silently eat it.
 */

/**
 * Reconstruct PGP armor from a context-menu selection.
 *
 * Chrome's `info.selectionText` collapses all whitespace (including
 * the line breaks PGP armor depends on) into single spaces. The armor
 * itself has enough structure that we can put the newlines back:
 *
 *   -----BEGIN PGP <TYPE>-----
 *   <armor headers like "Version: ...", may have multi-word values>
 *   <blank line>
 *   <base64 data, wrapped to 64 chars per line>
 *   =<4-char base64 CRC>
 *   -----END PGP <TYPE>-----
 *
 * Heuristics:
 *  - BEGIN/END markers survive collapse intact (they have no internal
 *    whitespace that would be ambiguous).
 *  - BEGIN/END types must match. This also keeps cleartext-signed
 *    messages (whose free-text body must NOT be rewrapped as base64)
 *    out of reconstruction: their first BEGIN is `PGP SIGNED MESSAGE`
 *    but the first END is `PGP SIGNATURE`.
 *  - Armor headers always start with a token ending in `:`. Header
 *    values can have multiple whitespace-separated tokens (e.g.
 *    `Version: Encryption Desktop 10.4.1`); we keep consuming value
 *    tokens until we hit either another header (token ending in `:`)
 *    or the first long pure-base64 token (the data).
 *  - The CRC line is the last token matching `=XXXX` (5 chars,
 *    leading `=`, exactly 4 base64 chars).
 *  - Data is everything between the last header line and the CRC.
 */

const BEGIN_MARKER = /-----BEGIN PGP ([A-Z ]+?)-----/;
const END_MARKER = /-----END PGP ([A-Z ]+?)-----/;
const BASE64_TOKEN = /^[A-Za-z0-9+/=]+$/;
const CRC_TOKEN = /^=[A-Za-z0-9+/]{4}$/;
const HEADER_KEY = /^[A-Za-z][A-Za-z0-9-]*:$/;
const MIN_DATA_TOKEN_LEN = 40;

/** True if the text contains a BEGIN PGP marker but the line right
 *  after it has been collapsed (i.e. no `\n` after the marker). */
export function looksLikeCollapsedArmor(text: string): boolean {
  if (!BEGIN_MARKER.test(text)) return false;
  return !/-----BEGIN PGP [A-Z ]+-----\n/.test(text);
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
    crcIdx === -1 ? tokens.slice(dataStart) : tokens.slice(dataStart, crcIdx);
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
  const wrapped = dataTokens
    .join("")
    .replace(/(.{64})/g, "$1\n")
    .replace(/\n$/, "");

  const headerBlock =
    headerLines.length > 0 ? headerLines.join("\n") + "\n\n" : "\n";
  const crcBlock = crc ? `\n${crc}` : "";

  return (
    `-----BEGIN PGP ${blockType}-----\n` +
    headerBlock +
    wrapped +
    crcBlock +
    `\n-----END PGP ${blockType}-----`
  );
}

// ── Escape repair ────────────────────────────────────────────────────

/**
 * How a newline comes back mangled, and what it was.
 *
 * Order matters: `\r\n` is tried before `\n` so a CRLF pair becomes ONE
 * newline rather than two. `%0D` maps to nothing for the same reason --
 * a lone carriage return that survived is noise, not a line.
 *
 * Every `from` here contains at least one character outside the base64
 * alphabet (`A-Z a-z 0-9 + / =`), which is what makes the substitution
 * exact inside an armor block rather than a guess. Adding an entry whose
 * `from` is pure base64 would break that property and must not be done.
 */
const ESCAPE_FORMS: [RegExp, string][] = [
  [/\\r\\n/g, "\n"],
  [/\\n/g, "\n"],
  [/\\r/g, "\n"],
  [/\\t/g, "\t"],
  [/<br\s*\/?>/gi, "\n"],
  [/&#0*10;/g, "\n"],
  [/&#0*13;/g, ""],
  [/%0A/gi, "\n"],
  [/%0D/gi, ""],
];

/** Any PEM-style block, with BEGIN and END types required to MATCH.
 *
 *  NOT just `BEGIN PGP`: an OpenSSH private key, a PKCS#1/PKCS#8 PEM (a
 *  CRX signing key) and an armored age file are all multi-line base64
 *  between markers, all reach this app through the same paste box, and
 *  all break in exactly the same way when a machine eats their newlines.
 *  Restricting this to PGP would have fixed one of the four kinds of key
 *  this app accepts.
 *
 *  The backreference is what keeps a cleartext-signed message out of
 *  this regex: it opens `PGP SIGNED MESSAGE` and closes `PGP SIGNATURE`,
 *  so only its inner signature block matches here -- the body is handled
 *  separately below, under a stricter rule. */
const ARMOR_BLOCK = /-----BEGIN ([A-Z0-9 ]+?)-----([\s\S]*?)-----END \1-----/g;

/** A cleartext-signed message, whole: header, free-text body and the
 *  detached signature that covers it. */
const CLEARTEXT_BLOCK =
  /-----BEGIN PGP SIGNED MESSAGE-----[\s\S]*?-----END PGP SIGNATURE-----/g;

/**
 * A source-language LINE CONTINUATION: a backslash immediately before a
 * newline, plus the next line's indentation.
 *
 * Rust, C, shell and Python all use it, and it is what turns a long
 * escaped string into a readable block in a source file -- so armor
 * copied out of a test fixture or a code sample arrives carrying BOTH
 * this and the `\n` escaping. Repairing only the escaping leaves a
 * stranded backslash on every line, which is not valid base64 and does
 * not parse. (Found by pasting this project's own Rust fixture into the
 * workspace.)
 *
 * Safe for the same reason the escape forms are: a backslash is not in
 * the base64 alphabet, so inside an armor block it cannot be data. It is
 * matched only IMMEDIATELY before a newline -- a backslash mid-line is
 * left alone, because a rule that deleted those would be guessing rather
 * than reversing a known transform.
 *
 * NOT DONE HERE: quoted-printable soft line breaks (`=` before a
 * newline), which is the same idea for email. `=` IS in the base64
 * alphabet -- it is the padding, and it ends the `wjg=` and `=AEHv`
 * lines of every armor block -- so that rule would corrupt healthy
 * armor. Left out on purpose.
 */
const LINE_CONTINUATION = /\\\n[ \t]*/g;

function applyEscapeForms(text: string): string {
  // Continuations first: they are the OUTER layer. The source file wrote
  // `\n\` + newline, so unescaping before un-continuing would turn the
  // `\n` into a real newline and leave the backslash behind, attached to
  // the wrong line.
  let out = text.replace(LINE_CONTINUATION, "");
  for (const [from, to] of ESCAPE_FORMS) out = out.replace(from, to);
  return out;
}

/**
 * Undo escaping inside every armor block, leaving all other text alone.
 *
 * The block is re-emitted with its markers on their own lines, which is
 * what rescues armor that arrives embedded in something else -- a JSON
 * value, a quoted string, a log line -- where the BEGIN marker would
 * otherwise still be stuck mid-line behind `{"msg": "`.
 *
 * CLEARTEXT-SIGNED MESSAGES GET A STRICTER RULE, because their body is
 * free text and CAN legitimately contain a backslash: the escape forms
 * are applied only when the whole block holds no real newline at all,
 * which is proof it was flattened. A cleartext message that still has
 * its line structure is left exactly as it is, even if it mentions
 * `\n` -- the alternative is corrupting the very bytes the signature is
 * computed over, turning a valid signature into a tampering warning.
 */
export function repairArmorEscapes(text: string): string {
  // Cheap bail-out, and it is a performance guard rather than a
  // correctness one. Every repair below needs a CLOSING marker, and the
  // regexes' worst case is precisely the input that has none: each BEGIN
  // is scanned to end-of-string looking for a partner that is not there.
  // Measured at 8.6ms for 2400 unclosed markers in a 64 KB paste, versus
  // 0.01ms with this line. `handleInputChange` runs on every keystroke,
  // so a quadratic path in it is worth one `includes`.
  if (!text.includes("-----END ")) return text;

  const cleartextRepaired = text.replace(CLEARTEXT_BLOCK, (block) =>
    block.includes("\n") ? block : applyEscapeForms(block),
  );

  return cleartextRepaired.replace(
    ARMOR_BLOCK,
    (block, type: string, body: string) => {
      // NO normalisation of the restored newlines. Escaping preserved
      // the block's structure faithfully, so unescaping gives it back
      // exactly -- including the blank line between the armor headers
      // and the data, which is REQUIRED and which an eager
      // `^\n+ -> \n` tidy-up silently ate.
      const repaired = applyEscapeForms(body);
      // Nothing to do: return the ORIGINAL match so armor that was already
      // fine is byte-identical, rather than "equivalent".
      const rebuilt = `-----BEGIN ${type}-----${repaired}-----END ${type}-----`;
      return rebuilt === block ? block : `\n${rebuilt}\n`;
    },
  );
}

/**
 * The one entry point every text intake uses: repair escaping, then
 * whitespace collapse.
 *
 * In that order, because the collapse detector looks for a real newline
 * after the BEGIN marker -- run first, it would see an escaped message
 * as collapsed and hand it to `reconstructArmor`'s base64 rewrapper,
 * which is the wrong repair for the wrong damage.
 *
 * Both halves are pass-throughs when there is nothing to fix, so text
 * that is already fine (or is not armor at all) comes back unchanged.
 */
export function recoverArmorIfNeeded(text: string): string {
  const unescaped = repairArmorEscapes(text);
  return looksLikeCollapsedArmor(unescaped)
    ? reconstructArmor(unescaped)
    : unescaped;
}
