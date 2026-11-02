/** The query is user text that becomes a URL path: mostly what must NOT
 *  parse, and `keyserverKeyUrl` refusing a URL the shape did not promise. */
import { describe, expect, it } from "vitest";

import {
  isKeyserverQuery,
  keyserverKeyUrl,
  parseKeyserverQuery,
} from "~/lib/keyserver/query";

const ORIGIN = "https://keys.openpgp.org";
const FP = "D477040C70C2156A5C298549BB7E9101495E6BF7";

describe("parseKeyserverQuery", () => {
  it("takes an address and lowercases it", () => {
    // The value is the contact's upsert identity.
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
    // Parsing is the first line of defence; the builder is the second.
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
    expect(isKeyserverQuery({ kind: "email", value: "A@B.com" })).toBe(false);
    expect(isKeyserverQuery({ kind: "fingerprint", value: `0x${FP}` })).toBe(
      false,
    );
  });

  it("rejects a value whose kind was relabelled", () => {
    // The kind chooses the endpoint.
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
    // Also what keys.openpgp.org matches on (measured).
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
    expect(() =>
      keyserverKeyUrl(
        { kind: "keyid", value: "BB7E9101495E6BF7" },
        "not-a-url",
      ),
    ).toThrow();
  });
});
