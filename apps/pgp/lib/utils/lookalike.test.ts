import { describe, expect, it } from "vitest";

import { codePointLabel, markLookalikes } from "./lookalike";

/** The marked letters, in order. */
const odd = (s: string) =>
  markLookalikes(s)
    .filter((r) => r.odd)
    .map((r) => r.text);

describe("markLookalikes", () => {
  it("marks the Cyrillic letter in an otherwise Latin word", () => {
    expect(odd("Аlice Smith <alice@example.com>")).toEqual(["А"]);
  });

  it("marks a lookalike inside an email address", () => {
    expect(odd("Alice <аlice@example.com>")).toEqual(["а"]);
  });

  it("marks fullwidth, IPA and Cherokee letters passing for Latin", () => {
    expect(odd("Ａlice")).toEqual(["Ａ"]);
    expect(odd("ɑlice")).toEqual(["ɑ"]);
    expect(odd("Ꭺlice")).toEqual(["Ꭺ"]);
  });

  it("marks small capitals, math bold, the Kelvin sign and Lisu", () => {
    expect(odd("\u1d00lice")).toEqual(["\u1d00"]);
    expect(odd("\u{1d400}lice")).toEqual(["\u{1d400}"]);
    expect(odd("\u212aevin")).toEqual(["\u212a"]);
    expect(odd("\ua4eelice")).toEqual(["\ua4ee"]);
  });

  it("marks a domain label in another script next to a Latin one", () => {
    // "apple" spelled in Cyrillic, under a Latin TLD.
    expect(odd("Tim <tim@\u0430\u0440\u0440\u04cf\u0435.com>").join("")).toBe(
      "\u0430\u0440\u0440\u04cf\u0435",
    );
  });

  it("marks a Latin letter slipped into a Cyrillic word", () => {
    // "Ивaн" with a Latin a: the Cyrillic letters are the majority.
    expect(odd("Ивaн")).toEqual(["a"]);
  });

  it("leaves ordinary names alone, whatever their alphabet", () => {
    for (const honest of [
      "Alice Smith <alice@example.com>",
      "Иван Петров <ivan@example.ru>",
      "Иван <иван@пример.рф>",
      "Νίκος Παπάς <nikos@example.gr>",
      "José Müller",
      "李雷 <li@example.cn>",
    ]) {
      expect(odd(honest), honest).toEqual([]);
    }
  });

  it("keeps every character, so the text reads exactly as before", () => {
    const s = "Bob <аlice@ex.com> (work)";
    expect(
      markLookalikes(s)
        .map((r) => r.text)
        .join(""),
    ).toBe(s);
  });
});

describe("codePointLabel", () => {
  it("names the code point", () => {
    expect(codePointLabel("А")).toBe("U+0410");
    expect(codePointLabel("ае")).toBe("U+0430 U+0435");
  });
});
