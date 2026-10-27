import { describe, expect, it } from "vitest";

import {
  hasHiddenCharacters,
  hiddenCharactersToConfirm,
  withoutHiddenCharacters,
} from "./hidden-characters";

const cp = (...codes: number[]) => String.fromCodePoint(...codes);
const RLO = cp(0x202e);
const PDF = cp(0x202c);
const ZWSP = cp(0x200b);
const ZWJ = cp(0x200d);
const ZWNJ = cp(0x200c);
const VS16 = cp(0xfe0f);
const BLACK_FLAG = cp(0x1f3f4);
const CANCEL_TAG = cp(0xe007f);
/** `s` spelled in tag characters: invisible, but still in the text. */
const tags = (s: string) =>
  [...s].map((c) => cp(0xe0000 + (c.codePointAt(0) ?? 0))).join("");
const flag = (region: string) => `${BLACK_FLAG}${tags(region)}${CANCEL_TAG}`;

/** Text that draws as ordinary but is not: the reviewer's probes, and
 *  each range the old Verify/Decrypt check missed. */
const HIDDEN_CASES: [string, string, string[]][] = [
  [
    "a sentence in tags behind a black flag",
    `I agree ${flag("pay mallory 10k")}`,
    [...tags("pay mallory 10k"), CANCEL_TAG]
      .map((c) => `U+${(c.codePointAt(0) ?? 0).toString(16).toUpperCase()}`)
      .filter((v, i, a) => a.indexOf(v) === i),
  ],
  ["a flag-shaped run that is no flag", flag("zz"), ["U+E007A", "U+E007F"]],
  ["tags after a real flag", `${flag("gbeng")}${tags("x")}`, ["U+E0078"]],
  [
    "variation selectors smuggled after an emoji",
    `hello ${cp(0x1f600, 0xfe01, 0xfe02, 0xe0101, 0xe0150)}`,
    ["U+FE01", "U+FE02", "U+E0101", "U+E0150"],
  ],
  ["a ZWJ inside a Cyrillic word", `сч${ZWJ}ет`, ["U+200D"]],
  ["a Hangul filler", `Approved:${cp(0x3164)}NO`, ["U+3164"]],
  ["a halfwidth Hangul filler", `a${cp(0xffa0)}b`, ["U+FFA0"]],
  [
    "interlinear annotation marks",
    `pay ${cp(0xfff9)}100${cp(0xfffa)}1000${cp(0xfffb)}`,
    ["U+FFF9", "U+FFFA", "U+FFFB"],
  ],
  ["a combining grapheme joiner", `a${cp(0x34f)}b`, ["U+034F"]],
  ["a braille blank", `x${cp(0x2800)}y`, ["U+2800"]],
  ["an object replacement character", `x${cp(0xfffc)}y`, ["U+FFFC"]],
  ["a Mongolian selector off Mongolian", `a${cp(0x180b)}b`, ["U+180B"]],
  ["a Khmer inherent vowel", `a${cp(0x17b4)}b`, ["U+17B4"]],
  ["a shorthand format control", `a${cp(0x1bca0)}b`, ["U+1BCA0"]],
  ["a musical format control", `a${cp(0x1d173)}b`, ["U+1D173"]],
  ["an unassigned default-ignorable", `a${cp(0xe0080)}b`, ["U+E0080"]],
];

describe("hiddenCharactersToConfirm", () => {
  it("finds a right-to-left override that reverses a number", () => {
    expect(hiddenCharactersToConfirm(`Pay ${RLO}0001${PDF} EUR`)).toEqual([
      "U+202E",
      "U+202C",
    ]);
  });

  it("finds zero-width, tag, stray selector and control characters", () => {
    expect(hiddenCharactersToConfirm(`pay${ZWSP}pal`)).toEqual(["U+200B"]);
    expect(hiddenCharactersToConfirm(`ok${cp(0xe0041, 0xe0042)}`)).toEqual([
      "U+E0041",
      "U+E0042",
    ]);
    expect(hiddenCharactersToConfirm(`a${cp(0xfe00)}b`)).toEqual(["U+FE00"]);
    expect(hiddenCharactersToConfirm("bell\u0007")).toEqual(["U+0007"]);
    expect(hiddenCharactersToConfirm(`mid${cp(0xfeff)}dle`)).toEqual([
      "U+FEFF",
    ]);
  });

  it("finds a lone CR, but not CRLF", () => {
    expect(hiddenCharactersToConfirm("one\rtwo")).toEqual(["U+000D"]);
    expect(hiddenCharactersToConfirm("one\r\ntwo\r\n")).toEqual([]);
  });

  it("lists each character once", () => {
    expect(hiddenCharactersToConfirm(`${ZWSP}a${ZWSP}b`)).toEqual(["U+200B"]);
  });

  it.each([
    ["plain text", "Hello,\n\tworld.\r\n"],
    ["a leading byte-order mark", `${cp(0xfeff)}Hello`],
    ["a soft hyphen", `hy${cp(0xad)}phen`],
    ["an emoji with VS16", `I ${cp(0x2764)}${VS16} it`],
    ["a ZWJ emoji", `${cp(0x1f469)}${ZWJ}${cp(0x1f4bb)}`],
    [
      "a ZWJ emoji after a skin tone",
      `${cp(0x1f469, 0x1f3fd)}${ZWJ}${cp(0x1f4bb)}`,
    ],
    ["a ZWJ emoji after VS16", `${cp(0x2764)}${VS16}${ZWJ}${cp(0x1f525)}`],
    ["a keycap", `1${VS16}${cp(0x20e3)}`],
    ["Persian with ZWNJ", `می${ZWNJ}خواهم`],
    ["Hindi with ZWJ", `क्${ZWJ}ष`],
    ["an ideographic variation sequence", `葛${cp(0xe0100)}`],
    [
      "the flag of Scotland",
      cp(0x1f3f4, 0xe0067, 0xe0062, 0xe0073, 0xe0063, 0xe0074, 0xe007f),
    ],
  ])("leaves %s alone", (_name, text) => {
    expect(hiddenCharactersToConfirm(text)).toEqual([]);
  });

  it.each(HIDDEN_CASES)("finds %s", (_name, text, found) => {
    expect(hiddenCharactersToConfirm(text)).toEqual(found);
  });

  it.each([
    ["England", "gbeng"],
    ["Wales", "gbwls"],
  ])("leaves the flag of %s alone", (_name, region) => {
    expect(hiddenCharactersToConfirm(`go ${flag(region)}!`)).toEqual([]);
  });

  it("does not take long over a long run of tags", () => {
    const text = BLACK_FLAG + tags("a".repeat(200_000));
    const started = performance.now();
    expect(hiddenCharactersToConfirm(text)).toEqual(["U+E0061"]);
    expect(performance.now() - started).toBeLessThan(2_000);
  });

  it("still finds a ZWNJ between Latin letters", () => {
    expect(hiddenCharactersToConfirm(`pay${ZWNJ}pal`)).toEqual(["U+200C"]);
  });
});

describe("withoutHiddenCharacters", () => {
  it("drops them and turns a lone CR into a line break", () => {
    expect(withoutHiddenCharacters(`Pay ${RLO}0001${PDF}\rnow`)).toBe(
      "Pay 0001\nnow",
    );
  });

  it("keeps ordinary text byte for byte", () => {
    const text = `${cp(0x2764)}${VS16} ok\r\nmore`;
    expect(withoutHiddenCharacters(text)).toBe(text);
  });
});

describe("hasHiddenCharacters (the Verify and Decrypt note)", () => {
  it("spots a right-to-left override and zero-width characters", () => {
    expect(hasHiddenCharacters("pay \u202e0001\u202c to bob")).toBe(true);
    expect(hasHiddenCharacters("pa\u200by")).toBe(true);
  });

  it.each(HIDDEN_CASES)("spots %s", (_name, text) => {
    expect(hasHiddenCharacters(text)).toBe(true);
  });

  it("does not flag ordinary text, scripts, emoji or a real flag", () => {
    for (const text of [
      "Release 4.2\n\tsigned off\r\n",
      "Иван Петров, 報告",
      `${cp(0xfeff)}leading BOM`,
      `I ${cp(0x2764)}${VS16} it ${cp(0x1f469)}${ZWJ}${cp(0x1f4bb)}`,
      `می${ZWNJ}خواهم`,
      flag("gbsct"),
    ]) {
      expect(hasHiddenCharacters(text)).toBe(false);
    }
  });

  it("leaves a lone CR to its own note", () => {
    expect(hasHiddenCharacters("one\rtwo")).toBe(false);
    expect(hasHiddenCharacters(`one\r${ZWSP}two`)).toBe(true);
  });
});
