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
  /** A letter from a different alphabet than the rest of its word. */
  odd: boolean;
}

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

/** Mark one word: the letters outside its main script, if it mixes. */
function markWord(word: string): TextRun[] {
  const chars = [...word];
  const scripts = chars.map(scriptOf);
  const counts = new Map<Script, number>();
  for (const s of scripts) {
    if (s !== null) counts.set(s, (counts.get(s) ?? 0) + 1);
  }
  if (counts.size < 2) return [{ text: word, odd: false }];

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
  return chars.map((c, i) => ({
    text: c,
    odd: scripts[i] !== null && scripts[i] !== main,
  }));
}

/** Split `s` into runs, merging neighbours with the same marking. */
export function markLookalikes(s: string): TextRun[] {
  const runs: TextRun[] = [];
  let word = "";
  const push = (run: TextRun) => {
    const last = runs.at(-1);
    if (last?.odd === run.odd) last.text += run.text;
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
