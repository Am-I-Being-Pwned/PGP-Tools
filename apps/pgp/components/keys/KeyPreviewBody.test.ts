/**
 * Fingerprint layout for reading and COPYING. GnuPG's 4-char grouping is
 * damage on an OpenSSH fingerprint, and a mangled copy silently defeats
 * the out-of-band check (T-GITHUB-KEY-SUBSTITUTION).
 */

import { describe, expect, it } from "vitest";

import { fingerprintLines } from "./fingerprint-lines";

const PGP_FP = "3A9E1F5C7B2D48E6A0C1938574FD62B0E4A75C11";
const SSH_FP = "SHA256:IoCz+8Ykvdvfq1sQ2pQm5oYtxK3n0uWJZ9hVbGfR7Ac";

function clipboardValue(fp: string): string {
  return fingerprintLines(fp).join(" ");
}

describe("fingerprintLines - hex fingerprints (unchanged)", () => {
  it("groups a 40-hex OpenPGP fingerprint into 4-char blocks, 5 per line", () => {
    expect(fingerprintLines(PGP_FP)).toEqual([
      "3A9E 1F5C 7B2D 48E6 A0C1",
      "9385 74FD 62B0 E4A7 5C11",
    ]);
  });

  it("accepts lowercase hex too", () => {
    expect(fingerprintLines(PGP_FP.toLowerCase())).toEqual([
      "3a9e 1f5c 7b2d 48e6 a0c1",
      "9385 74fd 62b0 e4a7 5c11",
    ]);
  });

  it("copies a hex fingerprint as the grouped form on one line", () => {
    expect(clipboardValue(PGP_FP)).toBe(
      "3A9E 1F5C 7B2D 48E6 A0C1 9385 74FD 62B0 E4A7 5C11",
    );
  });
});

describe("fingerprintLines - non-hex fingerprints", () => {
  it("returns an OpenSSH fingerprint as one unbroken line", () => {
    expect(fingerprintLines(SSH_FP)).toEqual([SSH_FP]);
  });

  it("never splits the SHA256: prefix", () => {
    expect(fingerprintLines(SSH_FP)[0]).not.toMatch(/SHA2\s/);
  });

  it("puts the EXACT canonical fingerprint on the clipboard", () => {
    // Byte-for-byte what `ssh-keygen -lf` prints.
    const copied = clipboardValue(SSH_FP);
    expect(copied).toBe(SSH_FP);
    expect(copied).not.toContain(" ");
    expect(copied.replace(/\s/g, "")).toBe(copied);
  });

  it("leaves any other non-hex shape alone rather than guessing", () => {
    expect(fingerprintLines("BLAKE3:zzz-not-hex-at-all")).toEqual([
      "BLAKE3:zzz-not-hex-at-all",
    ]);
  });
});
