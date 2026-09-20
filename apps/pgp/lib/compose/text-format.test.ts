import { describe, expect, it } from "vitest";

import {
  findAll,
  nextMatchIndex,
  prevMatchIndex,
  replaceAll,
  replaceAt,
  toggleInlineStyle,
} from "./text-format";

describe("toggleInlineStyle", () => {
  const sel = (t: string, needle: string) => {
    const start = t.indexOf(needle);
    return { start, end: start + needle.length };
  };

  it("bolds a selection with sans-serif bold letters and keeps it selected", () => {
    const r = toggleInlineStyle(
      "hello world",
      sel("hello world", "world"),
      "bold",
    );
    expect(r.text).toBe("hello 𝘄𝗼𝗿𝗹𝗱");
    expect(r.text.slice(r.start, r.end)).toBe("𝘄𝗼𝗿𝗹𝗱");
  });

  it("a second press takes the style off again", () => {
    const first = toggleInlineStyle(
      "hello world",
      sel("hello world", "world"),
      "italic",
    );
    expect(first.text).toBe("hello 𝘸𝘰𝘳𝘭𝘥");
    const second = toggleInlineStyle(first.text, first, "italic");
    expect(second.text).toBe("hello world");
    expect(second.text.slice(second.start, second.end)).toBe("world");
  });

  it("bold on italic text gives bold italic; removing bold leaves italic", () => {
    const it = toggleInlineStyle("ab", { start: 0, end: 2 }, "italic");
    const both = toggleInlineStyle(it.text, it, "bold");
    expect(both.text).toBe("𝙖𝙗");
    const back = toggleInlineStyle(both.text, both, "bold");
    expect(back.text).toBe("𝘢𝘣");
  });

  it("styles digits where forms exist and leaves punctuation alone", () => {
    expect(toggleInlineStyle("a1!", { start: 0, end: 3 }, "bold").text).toBe(
      "𝗮𝟭!",
    );
    // Italic has no digit forms.
    expect(toggleInlineStyle("a1!", { start: 0, end: 3 }, "italic").text).toBe(
      "𝘢1!",
    );
    expect(toggleInlineStyle("a1!", { start: 0, end: 3 }, "code").text).toBe(
      "𝚊𝟷!",
    );
  });

  it("strikes through with a combining stroke after each character, skipping spaces", () => {
    const r = toggleInlineStyle("a b", { start: 0, end: 3 }, "strike");
    expect(r.text).toBe("a\u0336 b\u0336");
    const back = toggleInlineStyle(r.text, r, "strike");
    expect(back.text).toBe("a b");
  });

  it("strikethrough stacks with bold, and bold survives removing the strike", () => {
    const b = toggleInlineStyle("ab", { start: 0, end: 2 }, "bold");
    const bs = toggleInlineStyle(b.text, b, "strike");
    expect(bs.text).toBe("𝗮\u0336𝗯\u0336");
    const back = toggleInlineStyle(bs.text, bs, "strike");
    expect(back.text).toBe("𝗮𝗯");
  });

  it("applies when only some of the selection is styled, removes when all is", () => {
    const half = "𝗮b";
    const r = toggleInlineStyle(half, { start: 0, end: half.length }, "bold");
    expect(r.text).toBe("𝗮𝗯");
    const off = toggleInlineStyle(r.text, r, "bold");
    expect(off.text).toBe("ab");
  });

  it("does nothing to an empty or whitespace-only selection", () => {
    expect(toggleInlineStyle("ab", { start: 1, end: 1 }, "bold").text).toBe(
      "ab",
    );
    expect(toggleInlineStyle("a   b", { start: 1, end: 4 }, "bold").text).toBe(
      "a   b",
    );
  });

  it("tolerates a backwards selection", () => {
    const r = toggleInlineStyle("hello world", { start: 11, end: 6 }, "code");
    expect(r.text).toBe("hello 𝚠𝚘𝚛𝚕𝚍");
  });

  it("does not split a surrogate pair at the selection edge", () => {
    // Selecting the second half of 𝗮 and the following b.
    // The edge snaps back to include the whole 𝗮; it is then a mixed
    // selection, so bold is applied to the b.
    const t = "𝗮b";
    const r = toggleInlineStyle(t, { start: 1, end: 3 }, "bold");
    expect(r.text).toBe("𝗮𝗯");
    expect(r.start).toBe(0);
  });
});

describe("find", () => {
  it("finds every non-overlapping match, case-insensitively by default", () => {
    expect(findAll("Aa aa AA", "aa")).toEqual([0, 3, 6]);
    expect(findAll("Aa aa AA", "aa", { caseSensitive: true })).toEqual([3]);
    expect(findAll("aaaa", "aa")).toEqual([0, 2]);
  });

  it("matches nothing for an empty query", () => {
    expect(findAll("abc", "")).toEqual([]);
  });

  it("steps forward and backward with wrap-around", () => {
    const m = [2, 7, 12];
    expect(nextMatchIndex(m, 0)).toBe(0);
    expect(nextMatchIndex(m, 3)).toBe(1);
    expect(nextMatchIndex(m, 13)).toBe(0);
    expect(prevMatchIndex(m, 8)).toBe(1);
    expect(prevMatchIndex(m, 2)).toBe(2);
    expect(nextMatchIndex([], 0)).toBe(-1);
    expect(prevMatchIndex([], 0)).toBe(-1);
  });
});

describe("replace", () => {
  it("replaces one match and selects the replacement", () => {
    const r = replaceAt("a cat sat", 2, "cat", "dog");
    expect(r.text).toBe("a dog sat");
    expect(r.text.slice(r.start, r.end)).toBe("dog");
  });

  it("replaces every match, including when the replacement contains the query", () => {
    expect(replaceAll("a a a", "a", "aa")).toEqual({
      text: "aa aa aa",
      count: 3,
    });
    expect(replaceAll("x", "a", "b")).toEqual({ text: "x", count: 0 });
    expect(
      replaceAll("Cat cat", "cat", "dog", { caseSensitive: true }),
    ).toEqual({
      text: "Cat dog",
      count: 1,
    });
  });
});
