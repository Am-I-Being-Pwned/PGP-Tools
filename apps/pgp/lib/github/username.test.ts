import { describe, expect, it } from "vitest";

import { githubKeysUrl, isGithubUsername } from "./username";

const ORIGIN = "https://api.github.com";

describe("isGithubUsername", () => {
  const VALID = [
    "acorn221",
    "a",
    "A",
    "0",
    "torvalds",
    "a-b",
    "a-b-c",
    "github",
    "x".repeat(39),
    "1-2",
  ];

  const INVALID = [
    ["empty", ""],
    ["leading hyphen", "-abc"],
    ["trailing hyphen", "abc-"],
    ["double hyphen", "a--b"],
    ["40 chars", "x".repeat(40)],
    ["underscore", "a_b"],
    ["dot", "a.b"],
    ["slash", "a/b"],
    ["traversal", "../../orgs/x"],
    ["encoded slash", "a%2Fb"],
    ["query", "a?b=c"],
    ["fragment", "a#b"],
    ["at sign", "a@b"],
    ["backslash", "a\\b"],
    ["space", "a b"],
    ["newline", "a\nb"],
    ["trailing newline", "abc\n"],
    ["unicode", "étienne"],
    ["absolute url", "https://evil.example"],
    ["protocol relative", "//evil.example"],
    ["colon", "a:b"],
  ] as const;

  it.each(VALID)("accepts %s", (name) => {
    expect(isGithubUsername(name)).toBe(true);
  });

  it.each(INVALID)("rejects %s", (_label, name) => {
    expect(isGithubUsername(name)).toBe(false);
  });

  it.each([undefined, null, 42, {}, ["acorn221"]])(
    "rejects non-string %s",
    (value) => {
      expect(isGithubUsername(value)).toBe(false);
    },
  );
});

describe("githubKeysUrl", () => {
  it("builds the measured endpoint", () => {
    expect(githubKeysUrl("acorn221", ORIGIN).href).toBe(
      "https://api.github.com/users/acorn221/keys",
    );
  });

  it.each(["../../orgs/x", "a/../../gists", "..", "%2e%2e%2fgists"])(
    "throws rather than producing a traversal URL for %s",
    (name) => {
      expect(() => githubKeysUrl(name, ORIGIN)).toThrow();
    },
  );

  it.each([
    "acorn221?leak=x",
    "acorn221#frag",
    "evil.example/x",
    "//evil.example",
    "user:pass@evil.example",
  ])("throws for %s rather than leaving the intended path", (name) => {
    expect(() => githubKeysUrl(name, ORIGIN)).toThrow();
  });

  it("never leaves api.github.com for any accepted username", () => {
    for (const name of ["a", "acorn221", "a-b-c", "x".repeat(39)]) {
      const url = githubKeysUrl(name, ORIGIN);
      expect(url.origin).toBe(ORIGIN);
      expect(url.pathname).toBe(`/users/${name}/keys`);
      expect(url.search).toBe("");
      expect(url.hash).toBe("");
    }
  });
});
