/**
 * Mark the letters that make a word a lookalike.
 *
 * The same rule the engine uses to set `lookalike` (`mixes_scripts` in
 * gpg-wasm/src/lib.rs): a WORD whose letters come from more than one of
 * the scripts that imitate each other. Within such a word, the letters
 * outside its main script are the ones to point at -- the Cyrillic А in
 * "Аlice", the IPA ɑ in "ɑlice". A Cyrillic name with a Latin address is
 * two words in two scripts, which is ordinary, and nothing is marked.
 *
 * Computed from the text itself rather than read off the stored flag, so
 * it also marks names on contacts saved before the flag existed.
 */

export interface TextRun {
  text: string;
  /** A letter from a different alphabet than the rest of its word -- or
   *  an invisible character (see `invisible`). */
  odd: boolean;
  /** Characters that draw nothing at all (see {@link INVISIBLE}). Marked
   *  as `odd` too, but a highlight on nothing is still nothing, so the
   *  renderer shows a placeholder in their place. */
  invisible?: true;
  /** A letter of the address's own alphabet that passes for a different
   *  one (the dotless ı in "alıce@corp.com"; see {@link markWord}).
   *  Marked as `odd` too, with its own hover text: "from a different
   *  alphabet" would be wrong about it. */
  confusable?: true;
}

/**
 * Characters that render as nothing: every Default_Ignorable_Code_Point
 * (zero-width space and joiners, soft hyphen, variation selectors, tag
 * characters, the Hangul fillers, the combining grapheme joiner), every
 * format control (Cf: bidi overrides and isolates, Arabic number signs)
 * and every C0/C1 control; the line and paragraph separators; and the
 * symbols that draw as an empty cell without being ignorable (the
 * Braille blank U+2800, the object replacement character U+FFFC, the
 * musical null notehead U+1D159), which neither property covers. The
 * engine strips these from User IDs and key comments; this is the same
 * set on the TypeScript side (`INVISIBLE_RANGES` in gpg-wasm/src/lib.rs,
 * held to it by `lookalike.test.ts`), for text stored before it did and
 * for anything that reaches the screen another way. Inside a name or an
 * address, any one of them makes two different strings look identical.
 */
export const INVISIBLE =
  /[\p{Default_Ignorable_Code_Point}\p{Cf}\p{Cc}\u2028\u2029\u2800\uFFFC\u{1D159}]/u;
const INVISIBLE_ALL = new RegExp(INVISIBLE.source, "gu");

/** `s` with every {@link INVISIBLE} character taken out. */
export function stripInvisible(s: string): string {
  return s.replace(INVISIBLE_ALL, "");
}

/**
 * Letters that render like a Latin letter without being one, mapped to
 * it -- a hand-picked subset of the Unicode confusables data (UTS #39)
 * covering the scripts that imitate Latin names in practice: Cyrillic,
 * Greek, and the Latin look-alikes. Digits and pipes that pass for
 * letters ("Car0l", "|ane") are folded the same way.
 */
export const CONFUSABLE = new Map<string, string>([
  ["\u0030", "o"],
  ["\u0031", "l"],
  ["\u007c", "l"],
  ["\u0131", "i"],
  ["\u01c0", "l"],
  ["\u0251", "a"],
  ["\u0261", "g"],
  ["\u0269", "i"],
  ["\u0391", "a"],
  ["\u0392", "b"],
  ["\u0395", "e"],
  ["\u0396", "z"],
  ["\u0397", "h"],
  ["\u0399", "i"],
  ["\u039a", "k"],
  ["\u039c", "m"],
  ["\u039d", "n"],
  ["\u039f", "o"],
  ["\u03a1", "p"],
  ["\u03a4", "t"],
  ["\u03a5", "y"],
  ["\u03a7", "x"],
  ["\u03b1", "a"],
  ["\u03b9", "i"],
  ["\u03ba", "k"],
  ["\u03bd", "v"],
  ["\u03bf", "o"],
  ["\u03c1", "p"],
  ["\u03c4", "t"],
  ["\u03c5", "u"],
  ["\u03c7", "x"],
  ["\u0405", "s"],
  ["\u0406", "i"],
  ["\u0408", "j"],
  ["\u0410", "a"],
  ["\u0412", "b"],
  ["\u0415", "e"],
  ["\u041a", "k"],
  ["\u041c", "m"],
  ["\u041d", "h"],
  ["\u041e", "o"],
  ["\u0420", "p"],
  ["\u0421", "c"],
  ["\u0422", "t"],
  ["\u0423", "y"],
  ["\u0425", "x"],
  ["\u0430", "a"],
  ["\u0432", "b"],
  ["\u0435", "e"],
  ["\u043a", "k"],
  ["\u043c", "m"],
  ["\u043d", "h"],
  ["\u043e", "o"],
  ["\u0440", "p"],
  ["\u0441", "c"],
  ["\u0442", "t"],
  ["\u0443", "y"],
  ["\u0445", "x"],
  ["\u0455", "s"],
  ["\u0456", "i"],
  ["\u0457", "i"],
  ["\u0458", "j"],
  ["\u0491", "r"],
  ["\u04c0", "l"],
  ["\u04cf", "l"],
  ["\u0501", "d"],
  ["\u051b", "q"],
  ["\u051d", "w"],
  ["\u1d00", "a"],
  ["\u0262", "g"],
  ["\u0274", "n"],
  ["\u0280", "r"],
  ["\u028f", "y"],
  ["\u0299", "b"],
  ["\u029c", "h"],
  ["\u029f", "l"],
  ["\u026a", "i"],
  ["\u1d04", "c"],
  ["\u1d05", "d"],
  ["\u1d07", "e"],
  ["\u1d0a", "j"],
  ["\u1d0b", "k"],
  ["\u1d0d", "m"],
  ["\u1d0f", "o"],
  ["\u1d18", "p"],
  ["\u1d1b", "t"],
  ["\u1d1c", "u"],
  ["\u1d20", "v"],
  ["\u1d21", "w"],
  ["\u1d22", "z"],
  ["\ua731", "s"],
  ["\u212a", "k"],
  ["\u212b", "a"],
]);

const enum Script {
  Latin,
  Greek,
  Cyrillic,
  Armenian,
  Fullwidth,
  ExtendedLatin,
  Cherokee,
}

function scriptOf(c: string): Script | null {
  const cp = c.codePointAt(0) ?? 0;
  if (
    (cp >= 0x41 && cp <= 0x5a) ||
    (cp >= 0x61 && cp <= 0x7a) ||
    (cp >= 0xc0 && cp <= 0x24f) ||
    (cp >= 0x1e00 && cp <= 0x1eff)
  )
    return Script.Latin;
  if ((cp >= 0x370 && cp <= 0x3ff) || (cp >= 0x1f00 && cp <= 0x1fff))
    return Script.Greek;
  if (
    (cp >= 0x400 && cp <= 0x52f) ||
    (cp >= 0x1c80 && cp <= 0x1c8f) ||
    (cp >= 0x2de0 && cp <= 0x2dff) ||
    (cp >= 0xa640 && cp <= 0xa69f)
  )
    return Script.Cyrillic;
  if (cp >= 0x530 && cp <= 0x58f) return Script.Armenian;
  if (
    (cp >= 0xff21 && cp <= 0xff3a) ||
    (cp >= 0xff41 && cp <= 0xff5a) ||
    (cp >= 0x2100 && cp <= 0x214f) ||
    (cp >= 0x1d400 && cp <= 0x1d7ff)
  )
    return Script.Fullwidth;
  if (
    (cp >= 0x250 && cp <= 0x2af) ||
    (cp >= 0x1d00 && cp <= 0x1dbf) ||
    (cp >= 0xa720 && cp <= 0xa7ff)
  )
    return Script.ExtendedLatin;
  if (
    (cp >= 0x13a0 && cp <= 0x13ff) ||
    (cp >= 0xab70 && cp <= 0xabbf) ||
    (cp >= 0xa4d0 && cp <= 0xa4ff)
  )
    return Script.Cherokee;
  return null;
}

/** Word separators, as `mixes_scripts` splits on them. An email address
 *  is ONE word, so a domain label in another script next to a Latin one
 *  ("tim@аррӏе.com") counts as mixing. */
const SEPARATOR = /[\s<>()"',;:]/u;

/** Mark one word: the letters outside its main script, if it mixes,
 *  and every invisible character whether it mixes or not.
 *
 *  In an ADDRESS (a word with an "@"), also every non-ASCII letter that
 *  stands in for a Latin one ({@link CONFUSABLE}). Mixing scripts is not
 *  needed for those to deceive: the dotless ı is Latin, so "alıce" is a
 *  one-script word, and it reads as alice. A name may well be written in
 *  such letters (Turkish, Greek, Cyrillic); an address that otherwise
 *  reads as plain ASCII is where one is a disguise -- and it is the
 *  address the conflict check compares on its skeleton (see
 *  `identity/binding`), so it is marked where that check looks. */
function markWord(word: string): TextRun[] {
  const chars = [...word];
  const scripts = chars.map(scriptOf);
  const counts = new Map<Script, number>();
  for (const s of scripts) {
    if (s !== null) counts.set(s, (counts.get(s) ?? 0) + 1);
  }

  // The word's own script is the one most of its letters use; a tie goes
  // to plain Latin, which is what a lookalike is usually imitating.
  let main = Script.Latin;
  let best = -1;
  for (const [s, n] of counts) {
    if (n > best || (n === best && s === Script.Latin)) {
      main = s;
      best = n;
    }
  }
  // Only an address that otherwise reads as Latin: "иван@почта.рф" is
  // written in Cyrillic, and every one of its а and о is meant.
  const latinAddress = word.includes("@") && main === Script.Latin;
  const special = (c: string): TextRun | null =>
    INVISIBLE.test(c)
      ? { text: c, odd: true, invisible: true }
      : latinAddress && isConfusableLetter(c)
        ? { text: c, odd: true, confusable: true }
        : null;
  if (counts.size < 2) {
    if (!chars.some((c) => special(c) !== null))
      return [{ text: word, odd: false }];
    return chars.map((c) => special(c) ?? { text: c, odd: false });
  }
  return chars.map(
    (c, i) =>
      special(c) ?? {
        text: c,
        odd: scripts[i] !== null && scripts[i] !== main,
      },
  );
}

/** Characters that pass for the dot in an address ("corp・com"):
 *  middle dots, the hyphenation point, the dot operators. A name drops
 *  them with the rest of its punctuation; an address keeps its dots, so
 *  these are read as one (`addressSkeletons`) and marked inside it. */
export const DOT_LOOKALIKES = new Set([
  "\u00b7",
  "\u0387",
  "\u2027",
  "\u2219",
  "\u22c5",
  "\u30fb",
  "\uff65",
]);

/** A non-ASCII letter that stands in for a Latin one. ASCII entries in
 *  {@link CONFUSABLE} (the digits and the pipe) are left alone: "bob1"
 *  is an ordinary address. */
function isConfusableLetter(c: string): boolean {
  if ((c.codePointAt(0) ?? 0) < 0x80) return false;
  return (
    CONFUSABLE.has(c) ||
    CONFUSABLE.has(c.toLowerCase()) ||
    DOT_LOOKALIKES.has(c)
  );
}

/** Split `s` into runs, merging neighbours with the same marking. */
export function markLookalikes(s: string): TextRun[] {
  const runs: TextRun[] = [];
  let word = "";
  const push = (run: TextRun) => {
    const last = runs.at(-1);
    // Invisible characters stay one per run, so each gets its own
    // placeholder and its own code point in the hover text.
    if (
      last?.odd === run.odd &&
      !last.invisible &&
      !run.invisible &&
      last.confusable === run.confusable
    )
      last.text += run.text;
    else runs.push({ ...run });
  };
  const flush = () => {
    if (word) markWord(word).forEach(push);
    word = "";
  };
  for (const c of s) {
    if (SEPARATOR.test(c)) {
      flush();
      push({ text: c, odd: false });
    } else {
      word += c;
    }
  }
  flush();
  return runs;
}

/** "U+0410", for saying which character is marked. */
export function codePointLabel(c: string): string {
  return [...c]
    .map(
      (ch) =>
        `U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}`,
    )
    .join(" ");
}
