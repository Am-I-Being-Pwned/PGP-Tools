import { codePointLabel, INVISIBLE } from "../../lib/utils/lookalike";

/**
 * The characters in a message about to be SIGNED that the message box
 * does not show: bidi controls (a right-to-left override makes a signed
 * "1000" read as "0001"), zero-width and other format characters, tag
 * characters, stray variation selectors, control characters, and a lone
 * CR (a line break on one screen, none on another).
 *
 * ONE detector for the whole workspace. Verify and Decrypt only report
 * these ({@link hasHiddenCharacters}), because there the text is the
 * signer's. Here it is about to become the USER's signed statement, and
 * it can have come from a web page's selection ("Open in PGP Tools") or
 * a paste, so Sign asks first (see `useWorkspaceOperations`). The set is
 * `INVISIBLE` (lookalike.ts) -- every default-ignorable, format and
 * control character, plus the blank-looking symbols -- so a variation
 * selector, a Hangul filler or an interlinear annotation mark counts
 * here exactly as it does in a contact's name.
 *
 * Ordinary text never trips it: CRLF, tabs and newlines; a byte-order
 * mark at the very start; a soft hyphen (copied from hyphenated pages,
 * it reorders nothing); and the joiners and selectors real scripts and
 * emoji are built from -- ZWJ inside an emoji sequence, VS15/VS16 after
 * an emoji, ZWNJ/ZWJ between letters of a script that uses them, a
 * variation selector after a Han or Mongolian character, and the tag
 * run of the three subdivision flags emoji actually defines (England,
 * Scotland, Wales). Any other tag run -- which can spell out a whole
 * sentence nobody sees, flag or no flag in front -- is reported.
 */

const INVISIBLE_ALL = new RegExp(INVISIBLE.source, "gu");
const PICTOGRAPHIC = /[\p{Extended_Pictographic}\p{Emoji_Modifier}]/u;
const EMOJI = /\p{Emoji}/u;
const LETTER = /[\p{L}\p{M}]/u;
/** Scripts whose spelling uses ZWNJ / ZWJ between letters. Anywhere
 *  else -- Latin, Cyrillic, Greek -- a joiner between letters does
 *  nothing visible, and is exactly how a word is made to differ from the
 *  one on screen. */
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
/** The RGI subdivision flags: 🏴 + tag letters + CANCEL TAG. */
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

/** Whether the invisible `c` at `at` is part of ordinary text. */
function isOrdinary(text: string, c: string, at: number): boolean {
  const cp = c.codePointAt(0) ?? 0;
  // Tab, LF; CR only as half of CRLF.
  if (c === "\t" || c === "\n") return true;
  if (c === "\r") return text[at + 1] === "\n";
  if (cp === 0x00ad) return true;
  if (cp === 0xfeff) return at === 0;
  const before = codePointBefore(text, at);
  const after = codePointAt(text, at + c.length);
  // Emoji presentation selectors after an emoji (or a selector run).
  if (cp === 0xfe0e || cp === 0xfe0f) {
    if (EMOJI.test(before)) return true;
  }
  // ZWJ sequences: 👩‍💻, and after VS16 / a skin-tone modifier.
  if (cp === 0x200d) {
    if (
      (PICTOGRAPHIC.test(before) || before === "️") &&
      PICTOGRAPHIC.test(after)
    ) {
      return true;
    }
  }
  // ZWNJ / ZWJ between letters of Persian, Indic and similar scripts.
  if (
    (cp === 0x200c || cp === 0x200d) &&
    LETTER.test(before) &&
    LETTER.test(after) &&
    JOINING_SCRIPT.test(before) &&
    JOINING_SCRIPT.test(after)
  ) {
    return true;
  }
  // Standardized / ideographic variation sequences: 葛󠄀, Mongolian FVS.
  if (
    ((cp >= 0xfe00 && cp <= 0xfe0f) ||
      (cp >= 0xe0100 && cp <= 0xe01ef) ||
      (cp >= 0x180b && cp <= 0x180f)) &&
    VARIANT_BASE.test(before)
  ) {
    return true;
  }
  // Part of one of the RGI subdivision flags, whole: back over the tag
  // characters to the 🏴, then the complete sequence must start there
  // and cover this one.
  if (cp >= 0xe0020 && cp <= 0xe007f) {
    let i = at;
    // No further back than the longest flag's tag run: a long run of
    // tags is not a flag, and walking it from every tag is quadratic.
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

/** Each offending character, in order, with where it sits. */
function* offending(text: string): Generator<{ c: string; at: number }> {
  INVISIBLE_ALL.lastIndex = 0;
  for (const m of text.matchAll(INVISIBLE_ALL)) {
    const at = m.index;
    if (!isOrdinary(text, m[0], at)) yield { c: m[0], at };
  }
}

/**
 * Whether `text` holds any of them, for the note under a Verify or
 * Decrypt verdict. A lone CR is left out: that card reports it on its
 * own line (`hasLoneCarriageReturn`), and saying it twice says nothing.
 */
export function hasHiddenCharacters(text: string): boolean {
  for (const { c } of offending(text)) if (c !== "\r") return true;
  return false;
}

/** The distinct hidden characters in `text` as code-point labels
 *  ("U+202E"), in order of first appearance. Empty for ordinary text. */
export function hiddenCharactersToConfirm(text: string): string[] {
  const seen = new Set<string>();
  for (const { c } of offending(text)) seen.add(codePointLabel(c));
  return [...seen];
}

/** `text` without them: each lone CR becomes a line break (what it was
 *  drawn as somewhere), everything else is dropped. */
export function withoutHiddenCharacters(text: string): string {
  let out = "";
  let from = 0;
  for (const { c, at } of offending(text)) {
    out += text.slice(from, at) + (c === "\r" ? "\n" : "");
    from = at + c.length;
  }
  return out + text.slice(from);
}
