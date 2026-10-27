import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

import { codePointLabel, INVISIBLE, markLookalikes } from "./lookalike";

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

describe("markLookalikes - invisible characters", () => {
  const hidden = (s: string) =>
    markLookalikes(s)
      .filter((r) => r.invisible)
      .map((r) => codePointLabel(r.text));

  it("marks a character that draws nothing, wherever it is", () => {
    // In an otherwise ordinary address, where no script mixes.
    expect(hidden("<alice@corp.com\ufe0f>")).toEqual(["U+FE0F"]);
    expect(hidden("Ali\u200bce Smith")).toEqual(["U+200B"]);
    expect(hidden("Alice\u3164 <a@b.test>")).toEqual(["U+3164"]);
    expect(hidden("alice@corp.com\u{e0020}")).toEqual(["U+E0020"]);
    expect(hidden("Alice\u202e Smith")).toEqual(["U+202E"]);
  });

  it("gives each its own run, so each gets its own marker", () => {
    expect(hidden("a\u200b\u200cb")).toEqual(["U+200B", "U+200C"]);
  });

  it("marks one inside a mixed-script word as well as the odd letter", () => {
    const runs = markLookalikes("\u0410li\u200bce");
    expect(runs.filter((r) => r.odd).map((r) => r.text)).toEqual([
      "\u0410",
      "\u200b",
    ]);
  });

  it("leaves an ordinary name exactly as it was", () => {
    expect(markLookalikes("Alice Smith <alice@corp.com>")).toEqual([
      { text: "Alice Smith <alice@corp.com>", odd: false },
    ]);
  });
});

describe("look-alike letters inside an address", () => {
  it("marks a same-script stand-in, with its own reason", () => {
    // The dotless i is Latin, so nothing here mixes scripts.
    const runs = markLookalikes("<al\u0131ce@corp.com>");
    expect(runs.filter((r) => r.odd)).toEqual([
      { text: "\u0131", odd: true, confusable: true },
    ]);
  });

  it("marks a dot that is not one", () => {
    expect(odd("alice@corp\u30fbcom")).toEqual(["\u30fb"]);
  });

  it("leaves the same letter alone in a name, and digits in an address", () => {
    expect(odd("Ay\u015fe Y\u0131lmaz <ayse@example.com>")).toEqual([]);
    expect(odd("bob1@example.com")).toEqual([]);
  });

  it("leaves an address written in another script alone", () => {
    expect(
      odd(
        "\u0438\u0432\u0430\u043d@\u043f\u043e\u0447\u0442\u0430.\u0440\u0444",
      ),
    ).toEqual([]);
  });
});

describe("blank-looking characters", () => {
  it("marks each as invisible, inside an address too", () => {
    for (const c of ["\u2800", "\ufffc", "\u{1d159}"]) {
      expect(
        markLookalikes(`alice@corp.com${c}`).filter((r) => r.invisible),
        codePointLabel(c),
      ).toEqual([{ text: c, odd: true, invisible: true }]);
    }
  });
});

describe("INVISIBLE and the engine's INVISIBLE_RANGES", () => {
  // The engine strips one set from User IDs and key comments, and this
  // side strips and marks another; a character in only one of them is a
  // way past whichever side lacks it. Read the Rust table itself, so
  // adding a range there without adding it here (or the reverse) fails.
  const source = readFileSync(
    new URL("../../gpg-wasm/src/lib.rs", import.meta.url),
    "utf8",
  );
  const table = /const INVISIBLE_RANGES[^=]*=\s*&\[([\s\S]*?)\];/.exec(
    source,
  )?.[1];
  const ranges = [
    ...(table ?? "").matchAll(/\(0x([0-9A-Fa-f]+),\s*0x([0-9A-Fa-f]+)\)/g),
  ].map((m) => [parseInt(m[1], 16), parseInt(m[2], 16)] as const);

  it("agree on every code point", () => {
    expect(ranges.length).toBeGreaterThan(20);
    // Rust's `char::is_control` is general category Cc, which the
    // engine strips before it consults the table.
    const control = (cp: number) => cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f);
    const mismatched: string[] = [];
    for (let cp = 0; cp <= 0x10ffff; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      const engine =
        control(cp) || ranges.some(([lo, hi]) => cp >= lo && cp <= hi);
      if (engine !== INVISIBLE.test(String.fromCodePoint(cp))) {
        mismatched.push(codePointLabel(String.fromCodePoint(cp)));
      }
    }
    expect(mismatched).toEqual([]);
  });
});
