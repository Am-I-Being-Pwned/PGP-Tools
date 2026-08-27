/**
 * The routing rule is the part of key discovery a user can be surprised
 * by, so every case it decides is named here -- including the one real
 * ambiguity (hex that is also a legal GitHub username).
 */
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
    // THE ONE AMBIGUITY. 40 hex characters satisfy GitHub's account-name
    // rule too; nobody's account is called this and everybody's
    // fingerprint is, so the keyserver wins. Read the doc comment on
    // `classifyLookup` before changing this.
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
    // `0x` is not a legal GitHub username character, so this is the
    // escape hatch for anyone who disagrees with the rule above.
    expect(classifyLookup(`0x${FP}`)).toEqual({
      target: "keyserver",
      query: { kind: "fingerprint", value: FP },
    });
  });

  it("still routes hex of a non-fingerprint length to GitHub", () => {
    // 8 hex characters is a short key id, which this app does not look
    // up -- and IS a plausible account name. It goes to GitHub and comes
    // back "no such account", which is a better answer than a request to
    // an endpoint we do not have.
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
      // 40 characters, too long for an account name -- and not hex, so
      // not a fingerprint either. (`"A".repeat(40)` would BE a
      // fingerprint; see the ambiguity case above.)
      "Z".repeat(40),
      "alice@example.com/../gists",
      "https://github.com/octocat",
      "../../etc/passwd",
    ]) {
      expect(classifyLookup(input)).toBeNull();
    }
  });
});
