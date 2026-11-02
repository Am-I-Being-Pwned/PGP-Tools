import { describe, expect, it } from "vitest";

import { classifyLookup } from "./lookup";

const FP = "D477040C70C2156A5C298549BB7E9101495E6BF7";

describe("classifyLookup", () => {
  it("sends an account name to GitHub", () => {
    for (const name of ["octocat", "a", "some-user-99", "A".repeat(39)]) {
      expect(classifyLookup(name)).toEqual({
        target: "github",
        username: name,
      });
    }
  });

  it("sends an address to the keyserver", () => {
    expect(classifyLookup(" Alice@Example.com ")).toEqual({
      target: "keyserver",
      query: { kind: "email", value: "alice@example.com" },
    });
  });

  it("sends a fingerprint to the keyserver even though it is a legal username", () => {
    // THE ONE AMBIGUITY: 40 hex is also a legal account name; the keyserver wins
    // (see `classifyLookup`).
    expect(classifyLookup(FP.toLowerCase())).toEqual({
      target: "keyserver",
      query: { kind: "fingerprint", value: FP },
    });
    expect(classifyLookup("BB7E9101495E6BF7")).toEqual({
      target: "keyserver",
      query: { kind: "keyid", value: "BB7E9101495E6BF7" },
    });
  });

  it("lets 0x say `fingerprint` out loud", () => {
    // `0x` is the explicit escape hatch.
    expect(classifyLookup(`0x${FP}`)).toEqual({
      target: "keyserver",
      query: { kind: "fingerprint", value: FP },
    });
  });

  it("still routes hex of a non-fingerprint length to GitHub", () => {
    // A short key id isn't looked up but IS a plausible account name.
    expect(classifyLookup("deadbeef")).toEqual({
      target: "github",
      username: "deadbeef",
    });
  });

  it("returns null rather than guess", () => {
    for (const input of [
      "",
      "   ",
      "not a username",
      "-leading-hyphen",
      "trailing-hyphen-",
      "double--hyphen",
      // Too long for an account, not hex.
      "Z".repeat(40),
      "alice@example.com/../gists",
      "https://github.com/octocat",
      "../../etc/passwd",
    ]) {
      expect(classifyLookup(input)).toBeNull();
    }
  });
});
