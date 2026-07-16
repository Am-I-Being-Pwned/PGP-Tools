import { describe, expect, it } from "vitest";

import type { HistoryEntry } from "./storage/history";
import {
  buildSnippet,
  countMatches,
  entryMatchesQuery,
  findMatch,
  splitHighlight,
} from "./history-search";

function entry(overrides: Partial<HistoryEntry> = {}): HistoryEntry {
  return {
    id: "1",
    ts: 0,
    op: "encrypt",
    recipients: [],
    ...overrides,
  };
}

describe("findMatch", () => {
  it("finds a case-insensitive match", () => {
    expect(findMatch("Hello World", "world")).toBe(6);
    expect(findMatch("hello world", "WORLD")).toBe(6);
  });

  it("returns undefined when absent", () => {
    expect(findMatch("hello", "goodbye")).toBeUndefined();
  });

  it("returns undefined for an empty query", () => {
    expect(findMatch("hello", "")).toBeUndefined();
  });

  it("returns undefined when the query is longer than the content", () => {
    expect(findMatch("hi", "hello there")).toBeUndefined();
  });

  it("finds a match at index 0", () => {
    expect(findMatch("hello world", "hello")).toBe(0);
  });
});

describe("countMatches", () => {
  it("counts non-overlapping occurrences", () => {
    expect(countMatches("abc abc abc", "abc")).toBe(3);
    expect(countMatches("aaaa", "aa")).toBe(2);
  });

  it("is case-insensitive", () => {
    expect(countMatches("Foo foo FOO", "foo")).toBe(3);
  });

  it("returns 0 for empty query or no match", () => {
    expect(countMatches("abc", "")).toBe(0);
    expect(countMatches("abc", "xyz")).toBe(0);
  });
});

describe("buildSnippet", () => {
  it("returns undefined when the query does not match", () => {
    expect(buildSnippet("hello", "xyz")).toBeUndefined();
    expect(buildSnippet("hello", "")).toBeUndefined();
    expect(buildSnippet("hi", "a much longer query")).toBeUndefined();
  });

  it("handles a match at the start of content", () => {
    const s = buildSnippet("secret plans for the meeting", "secret");
    expect(s).toMatchObject({
      before: "",
      match: "secret",
      truncatedStart: false,
      truncatedEnd: false,
      moreMatches: 0,
    });
    expect(s?.after).toBe(" plans for the meeting");
  });

  it("handles a match at the end of content", () => {
    const s = buildSnippet("plans for the secret", "secret");
    expect(s).toMatchObject({
      before: "plans for the ",
      match: "secret",
      after: "",
      truncatedStart: false,
      truncatedEnd: false,
    });
  });

  it("truncates long context on both sides", () => {
    const content = `${"a".repeat(100)}NEEDLE${"b".repeat(100)}`;
    const s = buildSnippet(content, "needle");
    expect(s).toBeDefined();
    expect(s?.before).toBe("a".repeat(40));
    expect(s?.after).toBe("b".repeat(40));
    expect(s?.match).toBe("NEEDLE");
    expect(s?.truncatedStart).toBe(true);
    expect(s?.truncatedEnd).toBe(true);
  });

  it("respects a custom context size", () => {
    const content = `${"a".repeat(100)}x${"b".repeat(100)}`;
    const s = buildSnippet(content, "x", 5);
    expect(s?.before).toBe("aaaaa");
    expect(s?.after).toBe("bbbbb");
  });

  it("preserves the original casing of the matched region", () => {
    const s = buildSnippet("say HeLLo there", "hello");
    expect(s?.match).toBe("HeLLo");
  });

  it("collapses whitespace so armored blocks stay on one line", () => {
    const content =
      "-----BEGIN PGP MESSAGE-----\n\nhQEMA1x\nSECRET\nabc\ndef\n-----END PGP MESSAGE-----";
    const s = buildSnippet(content, "secret");
    expect(s?.before).not.toMatch(/\n/);
    expect(s?.after).not.toMatch(/\n/);
    expect(s?.before).toContain("hQEMA1x ");
    expect(s?.after).toContain(" abc def ");
  });

  it("trims dangling whitespace at truncation cuts", () => {
    const content = `${"word ".repeat(30)}NEEDLE${" word".repeat(30)}`;
    const s = buildSnippet(content, "needle");
    expect(s?.before.startsWith(" ")).toBe(false);
    expect(s?.after.endsWith(" ")).toBe(false);
  });

  it("reports additional occurrences via moreMatches", () => {
    const s = buildSnippet("key key key", "key");
    expect(s?.moreMatches).toBe(2);
  });

  it("handles unicode content around the match", () => {
    const s = buildSnippet("héllo wörld 日本語 🔑 needle here", "needle");
    expect(s?.match).toBe("needle");
    expect(s?.before).toBe("héllo wörld 日本語 🔑 ");
    expect(s?.after).toBe(" here");
  });

  it("matches unicode queries case-insensitively", () => {
    const s = buildSnippet("un ÉCLAIR au chocolat", "éclair");
    expect(s?.match).toBe("ÉCLAIR");
  });
});

describe("splitHighlight", () => {
  /** Every split must be lossless: segments reassemble the input. */
  function expectLossless(text: string, query: string) {
    const segments = splitHighlight(text, query);
    expect(segments.map((s) => s.text).join("")).toBe(text);
    return segments;
  }

  it("splits a single match with surrounding text", () => {
    const segments = expectLossless("say hello there", "hello");
    expect(segments).toEqual([
      { text: "say ", match: false },
      { text: "hello", match: true },
      { text: " there", match: false },
    ]);
  });

  it("marks all occurrences, preserving original casing", () => {
    const segments = expectLossless("Key key KEY", "key");
    expect(segments.filter((s) => s.match).map((s) => s.text)).toEqual([
      "Key",
      "key",
      "KEY",
    ]);
  });

  it("handles matches at the very start and end", () => {
    expect(expectLossless("abc middle abc", "abc")[0]).toEqual({
      text: "abc",
      match: true,
    });
    expect(expectLossless("abc middle abc", "abc").at(-1)).toEqual({
      text: "abc",
      match: true,
    });
  });

  it("handles adjacent matches", () => {
    const segments = expectLossless("abab", "ab");
    expect(segments).toEqual([
      { text: "ab", match: true },
      { text: "ab", match: true },
    ]);
  });

  it("returns one plain segment when nothing matches", () => {
    expect(expectLossless("hello", "xyz")).toEqual([
      { text: "hello", match: false },
    ]);
  });

  it("returns the text unmarked for an empty query", () => {
    expect(splitHighlight("hello", "")).toEqual([
      { text: "hello", match: false },
    ]);
  });

  it("is lossless on unicode text", () => {
    expectLossless("日本語 🔑 héllo 🔑 日本語", "🔑");
    const segments = splitHighlight("日本語 🔑 héllo 🔑 日本語", "🔑");
    expect(segments.filter((s) => s.match)).toHaveLength(2);
  });
});

describe("entryMatchesQuery", () => {
  it("matches on op name", () => {
    expect(entryMatchesQuery(entry({ op: "decrypt" }), "decr")).toBe(true);
  });

  it("matches recipient names and fingerprints case-insensitively", () => {
    const e = entry({
      recipients: [{ name: "Alice", fingerprint: "ABCDEF1234" }],
    });
    expect(entryMatchesQuery(e, "alice")).toBe(true);
    expect(entryMatchesQuery(e, "abcdef")).toBe(true);
    expect(entryMatchesQuery(e, "bob")).toBe(false);
  });

  it("matches content case-insensitively", () => {
    expect(entryMatchesQuery(entry({ content: "The Plan" }), "plan")).toBe(
      true,
    );
  });

  it("matches file names", () => {
    const e = entry({ files: [{ name: "report.pdf", size: 10 }] });
    expect(entryMatchesQuery(e, "report")).toBe(true);
  });

  it("matches everything on an empty query", () => {
    expect(entryMatchesQuery(entry(), "")).toBe(true);
  });

  it("agrees with buildSnippet: a content match always yields a snippet", () => {
    const contents = [
      "needle",
      "the needle is here",
      `x${" ".repeat(50)}needle`,
      "NEEDLE at start",
      "ends with needle",
    ];
    for (const content of contents) {
      const e = entry({ content });
      expect(entryMatchesQuery(e, "needle")).toBe(true);
      expect(buildSnippet(content, "needle")).toBeDefined();
    }
    // And the converse: no filter match on content-only entries means
    // no snippet either.
    expect(entryMatchesQuery(entry({ content: "haystack" }), "needle")).toBe(
      false,
    );
    expect(buildSnippet("haystack", "needle")).toBeUndefined();
  });
});
