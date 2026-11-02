/**
 * Put PGP armor back together after something has mangled it. Two repairs:
 * whitespace collapse ({@link reconstructArmor}, heuristic, bails rather
 * than guess) and escaping ({@link repairArmorEscapes}, exact: `\`, `<`,
 * `>`, `%`, `&`, `;` are outside base64 so inside armor they can only be
 * damage).
 *
 * Both are strictly block-scoped: only text between a matched BEGIN/END
 * pair is rewritten. The workspace input also holds messages being
 * composed, and a global unescape would eat a typed `\n`.
 */

const BEGIN_MARKER = /-----BEGIN PGP ([A-Z ]+?)-----/;
const END_MARKER = /-----END PGP ([A-Z ]+?)-----/;
const BASE64_TOKEN = /^[A-Za-z0-9+/=]+$/;
const CRC_TOKEN = /^=[A-Za-z0-9+/]{4}$/;
const HEADER_KEY = /^[A-Za-z][A-Za-z0-9-]*:$/;
const MIN_DATA_TOKEN_LEN = 40;
const ARMOR_LINE_LEN = 64;

/** True if a BEGIN PGP marker has no line break after it. `\r?\n`, not
 *  `\n`: CRLF armor is intact and must not be "reconstructed". */
export function looksLikeCollapsedArmor(text: string): boolean {
  if (!BEGIN_MARKER.test(text)) return false;
  return !/-----BEGIN PGP [A-Z ]+-----\r?\n/.test(text);
}

/**
 * True when a token starts the base64 data rather than being a header
 * value. A token right after a `Key:` must be a full 64-char armor line:
 * a 40-hex `Comment: Fingerprint: ...` value is base64-shaped and would
 * otherwise be folded into the payload. The looser bound elsewhere keeps
 * an empty-valued header (`Comment:`) before the data working.
 */
function isDataToken(token: string, previous: string | undefined): boolean {
  if (!BASE64_TOKEN.test(token)) return false;
  const min =
    previous !== undefined && HEADER_KEY.test(previous)
      ? ARMOR_LINE_LEN
      : MIN_DATA_TOKEN_LEN;
  return token.length >= min;
}

/** Rebuild armor whose whitespace was collapsed (context-menu
 *  `selectionText`). BEGIN/END types must match, which also keeps
 *  cleartext-signed bodies out. If anything looks off, returns the input
 *  unchanged so the parser surfaces the real error. */
export function reconstructArmor(text: string): string {
  const bm = BEGIN_MARKER.exec(text);
  const em = END_MARKER.exec(text);
  if (!bm || !em) return text;
  if (bm[1] !== em[1]) return text;

  const blockType = bm[1];
  const middle = text.slice(bm.index + bm[0].length, em.index).trim();
  const tokens = middle.split(/\s+/).filter((t) => t.length > 0);
  if (tokens.length === 0) return text;

  let dataStart = -1;
  for (let i = 0; i < tokens.length; i++) {
    if (isDataToken(tokens[i], tokens[i - 1])) {
      dataStart = i;
      break;
    }
  }
  if (dataStart === -1) return text;

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

  const headerLines: string[] = [];
  let i = 0;
  while (i < headerTokens.length) {
    if (!HEADER_KEY.test(headerTokens[i])) {
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

const SIGNED_BEGIN = "-----BEGIN PGP SIGNED MESSAGE-----";
const SIGNATURE_BEGIN = "-----BEGIN PGP SIGNATURE-----";
const SIGNATURE_END = "-----END PGP SIGNATURE-----";

/**
 * Find a collapsed cleartext-signed message (BEGIN SIGNED MESSAGE, then a
 * full signature block on the same line). `indexOf` scan, not a regex:
 * the regex backtracked cubically and a page could stall the worker with
 * ~100 KB of repeated markers. Must stay linear.
 */
function findCollapsedCleartext(
  text: string,
): {
  index: number;
  whole: string;
  head: string;
  signatureBlock: string;
} | null {
  let from = 0;
  for (;;) {
    const start = text.indexOf(SIGNED_BEGIN, from);
    if (start < 0) return null;
    const afterStart = start + SIGNED_BEGIN.length;
    const newline = text.indexOf("\n", afterStart);
    const lineEnd = newline < 0 ? text.length : newline;
    const sig = text.indexOf(SIGNATURE_BEGIN, afterStart);
    if (sig >= 0 && sig + SIGNATURE_BEGIN.length <= lineEnd) {
      const end = text.indexOf(SIGNATURE_END, sig + SIGNATURE_BEGIN.length);
      if (end >= 0 && end + SIGNATURE_END.length <= lineEnd) {
        const stop = end + SIGNATURE_END.length;
        return {
          index: start,
          whole: text.slice(start, stop),
          head: text.slice(afterStart, sig),
          signatureBlock: text.slice(sig, stop),
        };
      }
    }
    if (newline < 0) return null;
    from = newline + 1;
  }
}
const HASH_NAME = /^[A-Za-z0-9-]+,?$/;

/**
 * Rebuild a collapsed cleartext-signed message. The `Hash:` header and the
 * signature come back exactly; the body's line breaks are unrecoverable so
 * it is kept as one line. A multi-line body then fails to verify, which is
 * the honest outcome: we only remove line breaks, never invent them, so
 * this can never produce a false "valid". Returns null when not
 * applicable; surrounding text is kept byte for byte.
 */
export function reconstructCleartextSigned(text: string): string | null {
  const m = findCollapsedCleartext(text);
  if (!m) return null;
  const { whole, head, signatureBlock } = m;

  const tokens = head
    .trim()
    .split(/\s+/)
    .filter((t) => t.length > 0);
  const headerLines: string[] = [];
  let i = 0;
  while (tokens[i] === "Hash:" && i + 1 < tokens.length) {
    const names = [tokens[i + 1]];
    i += 2;
    if (!HASH_NAME.test(names[0])) return null;
    while (names[names.length - 1].endsWith(",") && i < tokens.length) {
      if (!HASH_NAME.test(tokens[i])) return null;
      names.push(tokens[i]);
      i++;
    }
    headerLines.push(`Hash: ${names.join(" ")}`);
  }
  const body = tokens.slice(i).join(" ");

  const signature = reconstructArmor(signatureBlock);
  if (signature === signatureBlock) return null;

  const rebuilt =
    "-----BEGIN PGP SIGNED MESSAGE-----\n" +
    headerLines.map((l) => `${l}\n`).join("") +
    "\n" +
    `${body}\n` +
    signature;
  return text.slice(0, m.index) + rebuilt + text.slice(m.index + whole.length);
}

// ── Escape repair ────────────────────────────────────────────────────

/**
 * Mangled-newline forms. Order matters: `\r\n` before `\n` so CRLF becomes
 * one newline. Every `from` must contain a non-base64 character -- that is
 * what makes the substitution exact inside armor. Never add a pure-base64
 * `from`.
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

/** Any PEM-style block (PGP, OpenSSH, PKCS PEM, age), BEGIN/END types must
 *  match. The backreference keeps a cleartext-signed body out: only its
 *  inner signature matches here; the body gets the stricter rule below. */
const ARMOR_BLOCK = /-----BEGIN ([A-Z0-9 ]+?)-----([\s\S]*?)-----END \1-----/g;

const CLEARTEXT_BLOCK =
  /-----BEGIN PGP SIGNED MESSAGE-----[\s\S]*?-----END PGP SIGNATURE-----/g;

/**
 * Backslash-newline line continuation (Rust/C/shell/Python string
 * fixtures). Safe because `\` is not base64; matched only immediately
 * before a newline. Quoted-printable soft breaks (`=` + newline) are
 * deliberately NOT handled: `=` is base64 padding and that rule would
 * corrupt healthy armor.
 */
const LINE_CONTINUATION = /\\\n[ \t]*/g;

function applyEscapeForms(text: string): string {
  // Continuations first: they are the outer layer.
  let out = text.replace(LINE_CONTINUATION, "");
  for (const [from, to] of ESCAPE_FORMS) out = out.replace(from, to);
  return out;
}

/**
 * Undo escaping inside every armor block, leaving other text alone; the
 * block is re-emitted with markers on their own lines (rescues armor
 * embedded in JSON/log lines).
 *
 * Cleartext-signed messages are only unescaped when the whole block has no
 * real newline (proof it was flattened): their body may legitimately
 * contain `\n`, and rewriting signed bytes would turn a valid signature
 * into a tampering warning.
 */
export function repairArmorEscapes(text: string): string {
  // Perf guard: runs on every keystroke, and unclosed BEGINs are the
  // regexes' quadratic worst case.
  if (!text.includes("-----END ")) return text;

  const cleartextRepaired = text.replace(CLEARTEXT_BLOCK, (block) =>
    block.includes("\n") ? block : applyEscapeForms(block),
  );

  return cleartextRepaired.replace(
    ARMOR_BLOCK,
    (block, type: string, body: string) => {
      // No newline normalisation: the blank line after armor headers is
      // required.
      const repaired = applyEscapeForms(body);
      // Unchanged armor must stay byte-identical.
      const rebuilt = `-----BEGIN ${type}-----${repaired}-----END ${type}-----`;
      return rebuilt === block ? block : `\n${rebuilt}\n`;
    },
  );
}

/**
 * Entry point for every text intake: repair escaping, then whitespace
 * collapse. Order matters: the collapse detector would see escaped armor
 * as collapsed and apply the wrong repair. No-op on text that is fine.
 */
export function recoverArmorIfNeeded(text: string): string {
  const unescaped = repairArmorEscapes(text);
  if (!looksLikeCollapsedArmor(unescaped)) return unescaped;
  return reconstructCleartextSigned(unescaped) ?? reconstructArmor(unescaped);
}
