import { codePointLabel, INVISIBLE } from "~/lib/utils/lookalike";

/**
 * Characters in a message about to be SIGNED that the box does not show
 * (bidi controls, zero-width/format/tag/control chars, a lone CR): a
 * right-to-left override makes a signed "1000" read as "0001". ONE detector
 * for the workspace, over `INVISIBLE` (lookalike.ts). Verify/Decrypt only
 * report them (the text is the signer's); Sign asks first.
 *
 * Ordinary text never trips it: CRLF/tabs, a leading BOM, soft hyphens, and
 * the joiners/selectors real scripts and emoji use (incl. the three RGI
 * subdivision flags). Any other tag run can spell a hidden sentence.
 */

const INVISIBLE_ALL = new RegExp(INVISIBLE.source, "gu");
const PICTOGRAPHIC = /[\p{Extended_Pictographic}\p{Emoji_Modifier}]/u;
const EMOJI = /\p{Emoji}/u;
const LETTER = /[\p{L}\p{M}]/u;
/** Scripts that spell with ZWNJ / ZWJ. Elsewhere a joiner between letters
 *  is invisible and exactly how a word is made to differ from the screen. */
const JOINING_SCRIPT =
  /[\p{scx=Arabic}\p{scx=Syriac}\p{scx=Nko}\p{scx=Thaana}\p{scx=Mongolian}\p{scx=Devanagari}\p{scx=Bengali}\p{scx=Gurmukhi}\p{scx=Gujarati}\p{scx=Oriya}\p{scx=Tamil}\p{scx=Telugu}\p{scx=Kannada}\p{scx=Malayalam}\p{scx=Sinhala}\p{scx=Tibetan}\p{scx=Myanmar}\p{scx=Khmer}]/u;
const VARIANT_BASE = /[\p{Script=Han}\p{Script=Mongolian}]/u;
const BLACK_FLAG = 0x1f3f4;
const tagged = (letters: string) =>
  String.fromCodePoint(
    BLACK_FLAG,
    ...[...letters].map((c) => 0xe0000 + c.charCodeAt(0)),
    0xe007f,
  );
const SUBDIVISION_FLAGS = ["gbeng", "gbsct", "gbwls"].map(tagged);

function codePointBefore(text: string, at: number): string {
  if (at <= 0) return "";
  const lo = text.charCodeAt(at - 1);
  const start = lo >= 0xdc00 && lo <= 0xdfff && at >= 2 ? at - 2 : at - 1;
  return String.fromCodePoint(text.codePointAt(start) ?? 0);
}

function codePointAt(text: string, at: number): string {
  const cp = text.codePointAt(at);
  return cp === undefined ? "" : String.fromCodePoint(cp);
}

function isOrdinary(text: string, c: string, at: number): boolean {
  const cp = c.codePointAt(0) ?? 0;
  if (c === "\t" || c === "\n") return true;
  if (c === "\r") return text[at + 1] === "\n";
  if (cp === 0x00ad) return true;
  if (cp === 0xfeff) return at === 0;
  const before = codePointBefore(text, at);
  const after = codePointAt(text, at + c.length);
  if (cp === 0xfe0e || cp === 0xfe0f) {
    if (EMOJI.test(before)) return true;
  }
  if (cp === 0x200d) {
    if (
      (PICTOGRAPHIC.test(before) || before === "️") &&
      PICTOGRAPHIC.test(after)
    ) {
      return true;
    }
  }
  if (
    (cp === 0x200c || cp === 0x200d) &&
    LETTER.test(before) &&
    LETTER.test(after) &&
    JOINING_SCRIPT.test(before) &&
    JOINING_SCRIPT.test(after)
  ) {
    return true;
  }
  if (
    ((cp >= 0xfe00 && cp <= 0xfe0f) ||
      (cp >= 0xe0100 && cp <= 0xe01ef) ||
      (cp >= 0x180b && cp <= 0x180f)) &&
    VARIANT_BASE.test(before)
  ) {
    return true;
  }
  if (cp >= 0xe0020 && cp <= 0xe007f) {
    let i = at;
    // Bounded walk: a long tag run is not a flag, and walking it is quadratic.
    for (let steps = 0; i > 0 && steps <= 6; steps++) {
      const prev = codePointBefore(text, i);
      const p = prev.codePointAt(0) ?? 0;
      i -= prev.length;
      if (p === BLACK_FLAG) {
        return SUBDIVISION_FLAGS.some(
          (flag) => text.startsWith(flag, i) && at < i + flag.length,
        );
      }
      if (p < 0xe0020 || p > 0xe007e) return false;
    }
  }
  return false;
}

function* offending(text: string): Generator<{ c: string; at: number }> {
  INVISIBLE_ALL.lastIndex = 0;
  for (const m of text.matchAll(INVISIBLE_ALL)) {
    const at = m.index;
    if (!isOrdinary(text, m[0], at)) yield { c: m[0], at };
  }
}

/** For the Verify/Decrypt note; a lone CR is left out (reported on its own line). */
export function hasHiddenCharacters(text: string): boolean {
  for (const { c } of offending(text)) if (c !== "\r") return true;
  return false;
}

/** Distinct code-point labels ("U+202E"), in order of first appearance. */
export function hiddenCharactersToConfirm(text: string): string[] {
  const seen = new Set<string>();
  for (const { c } of offending(text)) seen.add(codePointLabel(c));
  return [...seen];
}

/** Each lone CR becomes a line break; everything else is dropped. */
export function withoutHiddenCharacters(text: string): string {
  let out = "";
  let from = 0;
  for (const { c, at } of offending(text)) {
    out += text.slice(from, at) + (c === "\r" ? "\n" : "");
    from = at + c.length;
  }
  return out + text.slice(from);
}
