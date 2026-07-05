import { describe, expect, it } from "vitest";

import {
  bucketFor,
  isCanonicalPadding,
  padPlaintext,
  unpadPlaintext,
} from "./padding";

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

describe("bucketFor", () => {
  it("floors small inputs at the minimum bucket", () => {
    expect(bucketFor(0)).toBe(2048);
    expect(bucketFor(1)).toBe(2048);
    expect(bucketFor(2048)).toBe(2048);
  });

  it("grows in powers of two", () => {
    expect(bucketFor(2049)).toBe(4096);
    expect(bucketFor(6700)).toBe(8192);
    expect(bucketFor(42_000)).toBe(65_536);
  });

  it("is stable across small deltas within a bucket", () => {
    // Adding a key that keeps you inside a bucket must not change size.
    expect(bucketFor(9000)).toBe(bucketFor(15_000));
  });
});

describe("padPlaintext / unpadPlaintext round-trip", () => {
  const json = enc(JSON.stringify([{ keyId: "abc", userIds: ["A <a@x>"] }]));

  it("pads to a bucket and recovers the exact JSON", () => {
    const padded = padPlaintext(json, true);
    expect(padded.length).toBe(2048);
    expect(dec(unpadPlaintext(padded))).toBe(dec(json));
  });

  it("does not pad when disabled (sync), and still round-trips", () => {
    const notPadded = padPlaintext(json, false);
    expect(notPadded.length).toBe(json.length);
    expect(dec(unpadPlaintext(notPadded))).toBe(dec(json));
  });

  it("reads a legacy unpadded blob (no delimiter) whole", () => {
    // Pre-padding blobs were pure JSON with no NUL terminator.
    expect(dec(unpadPlaintext(json))).toBe(dec(json));
  });

  it("keeps padded size constant as content grows within a bucket", () => {
    const a = padPlaintext(enc("a".repeat(100)), true);
    const b = padPlaintext(enc("a".repeat(1500)), true);
    expect(a.length).toBe(b.length); // both land in the 2048 bucket
  });

  it("NUL delimiter is unambiguous: JSON never contains a raw 0x00", () => {
    // A NUL *character* in a value is escaped by JSON.stringify (to
    // a 6-char \\u0000 sequence), so the encoded bytes hold no raw
    // 0x00 to collide with the delimiter.
    const nul = String.fromCharCode(0);
    const withNul = enc(JSON.stringify([{ userIds: ["x" + nul + "y"] }]));
    expect(withNul.includes(0)).toBe(false);
    const padded = padPlaintext(withNul, true);
    expect(dec(unpadPlaintext(padded))).toBe(dec(withNul));
  });
});

describe("isCanonicalPadding (one-time normalization gate)", () => {
  const json = enc(JSON.stringify([{ keyId: "abc" }]));

  it("reports a correctly-padded local blob as canonical (no re-pad)", () => {
    const padded = padPlaintext(json, true);
    expect(isCanonicalPadding(padded, true)).toBe(true);
  });

  it("reports an unpadded blob on local as non-canonical (needs re-pad)", () => {
    expect(isCanonicalPadding(json, true)).toBe(false);
  });

  it("reports an unpadded blob on sync as canonical (sync never pads)", () => {
    expect(isCanonicalPadding(json, false)).toBe(true);
  });

  it("re-padding a non-canonical blob preserves the exact JSON bytes", () => {
    // The safety guarantee: normalization changes only the envelope.
    const repadded = padPlaintext(unpadPlaintext(json), true);
    expect(dec(unpadPlaintext(repadded))).toBe(dec(json));
    expect(isCanonicalPadding(repadded, true)).toBe(true);
  });

  it("is idempotent: a normalized blob needs no further re-pad", () => {
    const once = padPlaintext(unpadPlaintext(json), true);
    const twice = padPlaintext(unpadPlaintext(once), true);
    expect(twice.length).toBe(once.length);
    expect(isCanonicalPadding(once, true)).toBe(true);
  });
});
