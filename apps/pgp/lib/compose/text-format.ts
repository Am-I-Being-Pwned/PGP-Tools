/**
 * Pure (DOM-free) message-box editing: Unicode inline formatting and
 * find/replace. Unicode letter forms, not Markdown, because a PGP message
 * stays plain text on the other side and nothing renders `**markers**`.
 * Only Latin letters (and digits for bold/mono) have forms.
 */

export interface Selection {
  start: number;
  end: number;
}

export interface Edit extends Selection {
  text: string;
}

export type InlineStyle = "bold" | "italic" | "strike" | "code";

const STRIKE = "\u0336";

// Code point of 'A' per styled alphabet (52 letters, upper then lower) and
// of '0' where the style has digits (italic has none).
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

/** Missing combinations fall back (a bold-italic digit renders bold). */
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
 * Toggle a style: removed if every styleable char has it, else applied to
 * all. Returned selection covers the same chars (UTF-16 length changes).
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

/** Non-overlapping match offsets; an empty query matches nothing. */
export function findAll(
  text: string,
  query: string,
  opts: FindOptions = {},
): number[] {
  if (!query) return [];
  // Case-folded regex over the original, not indexOf on a lowercased copy:
  // lowercasing can change UTF-16 length (İ -> i̇) and shift every offset.
  const re = new RegExp(
    query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
    opts.caseSensitive ? "g" : "gi",
  );
  const out: number[] = [];
  for (const m of text.matchAll(re)) {
    if (m[0].length === 0) break;
    out.push(m.index);
  }
  return out;
}

/** First match at/after `from`, wrapping; -1 if none. */
export function nextMatchIndex(matches: number[], from: number): number {
  if (matches.length === 0) return -1;
  const i = matches.findIndex((m) => m >= from);
  return i === -1 ? 0 : i;
}

/** Last match before `from`, wrapping; -1 if none. */
export function prevMatchIndex(matches: number[], from: number): number {
  if (matches.length === 0) return -1;
  for (let i = matches.length - 1; i >= 0; i--) {
    if (matches[i] < from) return i;
  }
  return matches.length - 1;
}

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

/** Right-to-left so earlier offsets stay valid. */
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
