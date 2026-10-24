import { describe, expect, it } from "vitest";

import { AVATAR_SIZE, fingerprintBytes, keyAvatar } from "./key-avatar";

const ALICE = "1D2DFAC2C18051E9C11037A6E3AA99801E250E69";
const BOB = "6E98DB9F375D81CD0C0A2F4B1E3D5A7C9B8E6F10";

describe("fingerprintBytes", () => {
  it("decodes a hex OpenPGP fingerprint", () => {
    const b = fingerprintBytes(ALICE);
    expect(b).toHaveLength(20);
    expect(b[0]).toBe(0x1d);
    expect(b[19]).toBe(0x69);
  });

  it("ignores spacing and case", () => {
    expect(
      fingerprintBytes("1d2d fac2 c180 51e9 c110 37a6 e3aa 9980 1e25 0e69"),
    ).toEqual(fingerprintBytes(ALICE));
  });

  it("decodes an OpenSSH SHA256 fingerprint", () => {
    const b = fingerprintBytes(
      "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
    );
    expect(b).toHaveLength(32);
  });

  it("stretches anything else deterministically", () => {
    const a = fingerprintBytes("not-a-fingerprint");
    expect(a.length).toBeGreaterThanOrEqual(14);
    expect(fingerprintBytes("not-a-fingerprint")).toEqual(a);
    expect(fingerprintBytes("")).toHaveLength(20);
  });
});

describe("keyAvatar", () => {
  it("draws a full 16x16 grid of colours", () => {
    const { cells } = keyAvatar(ALICE);
    expect(cells).toHaveLength(AVATAR_SIZE * AVATAR_SIZE);
    for (const c of cells) expect(c).toMatch(/^(#|oklch\()/);
  });

  it("is stable for the same key", () => {
    expect(keyAvatar(ALICE)).toEqual(keyAvatar(ALICE));
  });

  it("differs between keys", () => {
    expect(keyAvatar(ALICE).cells).not.toEqual(keyAvatar(BOB).cells);
  });

  it("gives a two-word nickname", () => {
    expect(keyAvatar(ALICE).nickname).toMatch(/^[A-Z][a-z]+ [A-Z][a-z]+$/);
  });
});
