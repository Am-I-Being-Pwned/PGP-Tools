/**
 * The query is the security boundary of this feature: it is user text
 * that becomes a URL path. So the cases below are mostly about what must
 * NOT parse, and about `keyserverKeyUrl` refusing to build a URL that is
 * not the one the shape promised.
 */
import { describe, expect, it } from "vitest";

import {
  isKeyserverQuery,
  keyserverKeyUrl,
  parseKeyserverQuery,
} from "./query";

const ORIGIN = "https://keys.openpgp.org";
const FP = "D477040C70C2156A5C298549BB7E9101495E6BF7";

describe("parseKeyserverQuery", () => {
  it("takes an address and lowercases it", () => {
    // Canonicalised so two lookups for the same person cannot produce
    // two contacts -- the value IS the contact's upsert identity.
    expect(parseKeyserverQuery("Alice@Example.COM")).toEqual({
      kind: "email",
      value: "alice@example.com",
    });
  });

  it("takes a fingerprint however it was pasted", () => {
    for (const typed of [
      FP,
      FP.toLowerCase(),
      `0x${FP}`,
      "D477 040C 70C2 156A 5C29  8549 BB7E 9101 495E 6BF7",
    ]) {
      expect(parseKeyserverQuery(typed)).toEqual({
        kind: "fingerprint",
        value: FP,
      });
    }
  });

  it("takes a long key id", () => {
    expect(parseKeyserverQuery("bb7e9101495e6bf7")).toEqual({
      kind: "keyid",
      value: "BB7E9101495E6BF7",
    });
  });

  it("refuses the separators that would make this an arbitrary GET", () => {
    // Every one of these is a way to leave the path segment the URL
    // builder intends. None may parse -- the builder's assertions are the
    // second line of defence, not the first.
    for (const hostile of [
      "alice@example.com/../../gists",
      "alice@example.com?x=1",
      "alice@example.com#frag",
      "alice@example.com\\x",
      "user:pass@example.com",
      "alice@example.com:8080",
      "alice @example.com",
      "../../../etc/passwd",
      "//evil.tld",
      "https://evil.tld/x",
    ]) {
      expect(parseKeyserverQuery(hostile)).toBeNull();
    }
  });

  it("refuses hex of the wrong length", () => {
    // A 32-character hex string is a v3 fingerprint or a truncated
    // paste; neither is an endpoint we have, and guessing which would
    // send a request the user did not ask for.
    expect(parseKeyserverQuery("D477040C70C2156A5C298549BB7E9101")).toBeNull();
    expect(parseKeyserverQuery("BB7E9101495E6BF")).toBeNull();
    expect(parseKeyserverQuery(`${FP}0`)).toBeNull();
  });

  it("refuses an address longer than an address can be", () => {
    const long = `${"a".repeat(250)}@example.com`;
    expect(parseKeyserverQuery(long)).toBeNull();
  });

  it("refuses empty and whitespace-only input", () => {
    expect(parseKeyserverQuery("")).toBeNull();
    expect(parseKeyserverQuery("   ")).toBeNull();
  });
});

describe("isKeyserverQuery", () => {
  it("accepts what parseKeyserverQuery produces", () => {
    expect(isKeyserverQuery({ kind: "email", value: "a@b.com" })).toBe(true);
    expect(isKeyserverQuery({ kind: "fingerprint", value: FP })).toBe(true);
  });

  it("rejects a non-canonical value", () => {
    // The worker re-derives rather than trusting: a value the panel says
    // is canonical but is not never reaches the URL builder. Without
    // this, `value` is whatever the message said it was.
    expect(isKeyserverQuery({ kind: "email", value: "A@B.com" })).toBe(false);
    expect(isKeyserverQuery({ kind: "fingerprint", value: `0x${FP}` })).toBe(
      false,
    );
  });

  it("rejects a value whose kind was relabelled", () => {
    // The kind chooses the endpoint. A fingerprint labelled `email`
    // would be sent to /by-email; the reparse is what catches it.
    expect(isKeyserverQuery({ kind: "email", value: FP })).toBe(false);
    expect(isKeyserverQuery({ kind: "keyid", value: FP })).toBe(false);
  });

  it("rejects non-objects and missing fields", () => {
    for (const v of [null, undefined, "a@b.com", 42, {}, { kind: "email" }]) {
      expect(isKeyserverQuery(v)).toBe(false);
    }
  });
});

describe("keyserverKeyUrl", () => {
  it("builds the documented path for each kind", () => {
    expect(
      keyserverKeyUrl({ kind: "email", value: "alice@example.com" }, ORIGIN)
        .href,
    ).toBe(`${ORIGIN}/vks/v1/by-email/alice%40example.com`);
    expect(
      keyserverKeyUrl({ kind: "fingerprint", value: FP }, ORIGIN).href,
    ).toBe(`${ORIGIN}/vks/v1/by-fingerprint/${FP}`);
    expect(
      keyserverKeyUrl({ kind: "keyid", value: "BB7E9101495E6BF7" }, ORIGIN)
        .href,
    ).toBe(`${ORIGIN}/vks/v1/by-keyid/BB7E9101495E6BF7`);
  });

  it("percent-encodes the address rather than interpolating it", () => {
    // `+` and `%` are legal in a local part and are syntax in a URL. The
    // encoded form is what keys.openpgp.org matches on (measured: %40
    // returns 200), so this is not merely defensive.
    const url = keyserverKeyUrl(
      { kind: "email", value: "a+b%c@example.com" },
      ORIGIN,
    );
    expect(url.href).toBe(`${ORIGIN}/vks/v1/by-email/a%2Bb%25c%40example.com`);
    expect(url.search).toBe("");
  });

  it("throws on a query it would not itself have produced", () => {
    expect(() =>
      keyserverKeyUrl(
        { kind: "email", value: "alice@example.com/../gists" },
        ORIGIN,
      ),
    ).toThrow(/invalid query/);
    expect(() =>
      keyserverKeyUrl({ kind: "fingerprint", value: "not-hex" }, ORIGIN),
    ).toThrow(/invalid query/);
  });

  it("throws rather than issue a request to another origin", () => {
    // Unreachable today -- the origin is a module constant in
    // fetch-key.ts -- but this is the assertion that makes it safe for it
    // to stop being one.
    expect(() =>
      keyserverKeyUrl(
        { kind: "keyid", value: "BB7E9101495E6BF7" },
        "not-a-url",
      ),
    ).toThrow();
  });
});
