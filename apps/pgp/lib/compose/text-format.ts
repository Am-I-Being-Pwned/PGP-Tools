/**
 * Pure text editing for the message box: Unicode inline formatting and
 * find/replace. Everything here takes the current text plus a selection
 * and returns the new text plus the selection to apply -- no DOM, so it
 * is unit-tested directly and the component only has to read
 * `selectionStart`/`selectionEnd` and write the result back.
 *
 * WHY UNICODE, NOT MARKDOWN. A PGP message is plain text and stays plain
 * text on the other side; nothing renders `**markers**`. Unicode has
 * letter forms that ARE bold, italic and monospace (the Mathematical
 * Alphanumeric Symbols block) and a combining stroke that IS
 * strikethrough, and they survive any channel that carries UTF-8: mail,
 * chat, a signed cleartext block. Sans-serif variants are used so the
 * result reads as styled prose rather than as maths.
 *
 * The cost is that only Latin letters (and digits, for bold and
 * monospace) have such forms; other characters pass through unchanged.
 * A style is a toggle: applying it to a selection that already carries
 * it takes it off.
 */

export interface Selection {
  start: number;
  end: number;
}

export interface Edit extends Selection {
  text: string;
}

export type InlineStyle = "bold" | "italic" | "strike" | "code";

/** Combining long stroke overlay: one after each character strikes it. */
const STRIKE = "\u0336";

// Code point of the 'A' of each styled Latin alphabet (uppercase runs
// straight into lowercase, 52 letters), and of its '0' where the style
// has digits. Italic has no digit forms in Unicode.
const ALPHABET: Record<"bold" | "italic" | "boldItalic" | "mono", number> = {
  bold: 0x1d5d4,
  italic: 0x1d608,
  boldItalic: 0x1d63c,
  mono: 0x1d670,
};
const DIGITS: Partial<Record<keyof typeof ALPHABET, number>> = {
  bold: 0x1d7ec,
  mono: 0x1d7f6,
};

interface Glyph {
  /** The plain ASCII character, or the original when it has no forms. */
  base: string;
  bold: boolean;
  italic: boolean;
  mono: boolean;
  strike: boolean;
}

function letterIndex(ch: string): number {
  const c = ch.charCodeAt(0);
  if (c >= 0x41 && c <= 0x5a) return c - 0x41;
  if (c >= 0x61 && c <= 0x7a) return c - 0x61 + 26;
  return -1;
}

/** Break a styled character down to its ASCII base and style flags. */
function decode(ch: string): Glyph {
  const cp = ch.codePointAt(0) ?? 0;
  for (const [name, start] of Object.entries(ALPHABET) as [
    keyof typeof ALPHABET,
    number,
  ][]) {
    if (cp >= start && cp < start + 52) {
      const i = cp - start;
      const base = String.fromCharCode(i < 26 ? 0x41 + i : 0x61 + i - 26);
      return {
        base,
        bold: name === "bold" || name === "boldItalic",
        italic: name === "italic" || name === "boldItalic",
        mono: name === "mono",
        strike: false,
      };
    }
    const d = DIGITS[name];
    if (d !== undefined && cp >= d && cp < d + 10) {
      return {
        base: String.fromCharCode(0x30 + cp - d),
        bold: name === "bold",
        italic: false,
        mono: name === "mono",
        strike: false,
      };
    }
  }
  return { base: ch, bold: false, italic: false, mono: false, strike: false };
}

/** Rebuild a character from its base and flags. Letters without a form
 *  for the requested combination fall back as far as needed (italic
 *  digits do not exist, so a bold-italic digit renders bold). */
function encode(g: Glyph): string {
  let out = g.base;
  const li = letterIndex(g.base);
  const isDigit = g.base >= "0" && g.base <= "9";
  if (g.mono) {
    if (li !== -1) out = String.fromCodePoint(ALPHABET.mono + li);
    else if (isDigit) {
      out = String.fromCodePoint(
        (DIGITS.mono ?? 0) + g.base.charCodeAt(0) - 0x30,
      );
    }
  } else if (g.bold && g.italic) {
    if (li !== -1) out = String.fromCodePoint(ALPHABET.boldItalic + li);
    else if (isDigit) {
      out = String.fromCodePoint(
        (DIGITS.bold ?? 0) + g.base.charCodeAt(0) - 0x30,
      );
    }
  } else if (g.bold) {
    if (li !== -1) out = String.fromCodePoint(ALPHABET.bold + li);
    else if (isDigit) {
      out = String.fromCodePoint(
        (DIGITS.bold ?? 0) + g.base.charCodeAt(0) - 0x30,
      );
    }
  } else if (g.italic) {
    if (li !== -1) out = String.fromCodePoint(ALPHABET.italic + li);
  }
  return g.strike ? out + STRIKE : out;
}

/** Split text into glyphs, folding a following combining stroke into
 *  the character it strikes. */
function decodeAll(text: string): Glyph[] {
  const chars = Array.from(text);
  const out: Glyph[] = [];
  for (const ch of chars) {
    if (ch === STRIKE && out.length > 0) {
      out[out.length - 1].strike = true;
      continue;
    }
    out.push(decode(ch));
  }
  return out;
}

/** Whether a glyph can carry `style` at all (a space cannot be bold). */
function styleable(g: Glyph, style: InlineStyle): boolean {
  if (style === "strike") return !/\s/.test(g.base);
  const li = letterIndex(g.base);
  const isDigit = g.base >= "0" && g.base <= "9";
  return li !== -1 || (isDigit && style !== "italic");
}

function hasStyle(g: Glyph, style: InlineStyle): boolean {
  return style === "code" ? g.mono : g[style];
}

function setStyle(g: Glyph, style: InlineStyle, on: boolean): void {
  if (style === "code") {
    g.mono = on;
    // Monospace has no bold/italic forms; entering it drops them.
    if (on) g.bold = g.italic = false;
  } else {
    g[style] = on;
    if (on && style !== "strike") g.mono = false;
  }
}

/**
 * Toggle an inline style on the selection.
 *
 * If every styleable character in the selection already carries the
 * style, it is removed from all of them; otherwise it is applied to all
 * of them. The selection is returned covering the same characters (their
 * UTF-16 length changes, since the styled forms are astral code points).
 * An empty or whitespace-only selection is left alone: there is no
 * "start typing in bold" with Unicode forms, the words have to exist.
 */
export function toggleInlineStyle(
  text: string,
  sel: Selection,
  style: InlineStyle,
): Edit {
  let { start, end } = sel;
  if (start > end) [start, end] = [end, start];
  if (start === end) return { text, start, end };

  // Never split a surrogate pair or detach a combining stroke.
  if (start > 0 && /[\uDC00-\uDFFF]/.test(text[start])) start -= 1;
  if (end < text.length && /[\uDC00-\uDFFF]/.test(text[end])) end += 1;
  while (end < text.length && text[end] === STRIKE) end += 1;

  const glyphs = decodeAll(text.slice(start, end));
  const targets = glyphs.filter((g) => styleable(g, style));
  if (targets.length === 0) return { text, start, end };
  const on = !targets.every((g) => hasStyle(g, style));
  for (const g of targets) setStyle(g, style, on);
  const styled = glyphs.map(encode).join("");
  return {
    text: text.slice(0, start) + styled + text.slice(end),
    start,
    end: start + styled.length,
  };
}

// ── find & replace ───────────────────────────────────────────────────

export interface FindOptions {
  caseSensitive?: boolean;
}

/** Start offsets of every match of `query` in `text`. Empty query
 *  matches nothing (an empty needle "matches" at every offset, which is
 *  never what a find box means). Overlapping matches are not counted:
 *  the search resumes after each hit, as every editor does. */
export function findAll(
  text: string,
  query: string,
  opts: FindOptions = {},
): number[] {
  if (!query) return [];
  const hay = opts.caseSensitive ? text : text.toLowerCase();
  const needle = opts.caseSensitive ? query : query.toLowerCase();
  const out: number[] = [];
  let i = hay.indexOf(needle);
  while (i !== -1) {
    out.push(i);
    i = hay.indexOf(needle, i + needle.length);
  }
  return out;
}

/** Index into `matches` of the first match at or after `from`, wrapping
 *  to the first match; -1 when there are none. */
export function nextMatchIndex(matches: number[], from: number): number {
  if (matches.length === 0) return -1;
  const i = matches.findIndex((m) => m >= from);
  return i === -1 ? 0 : i;
}

/** Index of the last match strictly before `from`, wrapping to the last
 *  match; -1 when there are none. */
export function prevMatchIndex(matches: number[], from: number): number {
  if (matches.length === 0) return -1;
  for (let i = matches.length - 1; i >= 0; i--) {
    if (matches[i] < from) return i;
  }
  return matches.length - 1;
}

/** Replace the match starting at `at` (of length `query.length`) with
 *  `replacement`. The returned selection covers the replacement so the
 *  caller can show what changed. */
export function replaceAt(
  text: string,
  at: number,
  query: string,
  replacement: string,
): Edit {
  return {
    text: text.slice(0, at) + replacement + text.slice(at + query.length),
    start: at,
    end: at + replacement.length,
  };
}

/** Replace every match. Returns the new text and how many were replaced.
 *  Built right-to-left off `findAll` so earlier offsets stay valid. */
export function replaceAll(
  text: string,
  query: string,
  replacement: string,
  opts: FindOptions = {},
): { text: string; count: number } {
  const matches = findAll(text, query, opts);
  let out = text;
  for (let i = matches.length - 1; i >= 0; i--) {
    const at = matches[i];
    out = out.slice(0, at) + replacement + out.slice(at + query.length);
  }
  return { text: out, count: matches.length };
}
