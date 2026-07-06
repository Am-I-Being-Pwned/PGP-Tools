import { describe, expect, it } from "vitest";

import { binaryKeyToArmored, looksLikeBinaryKey } from "./binary-armor";

// Old-format public-key packet header (tag 6, 2-byte length), the
// `gpg --export` default, followed by dummy body bytes.
const BINARY_PUBLIC = new Uint8Array([0x99, 0x02, 0x0d, 0x04, 0x64, 0xf9]);
// Old-format secret-key packet header (tag 5).
const BINARY_PRIVATE = new Uint8Array([0x95, 0x01, 0x00, 0x04, 0x64, 0xf9]);

describe("looksLikeBinaryKey", () => {
  it("detects raw public and secret key exports", () => {
    expect(looksLikeBinaryKey(BINARY_PUBLIC)).toBe(true);
    expect(looksLikeBinaryKey(BINARY_PRIVATE)).toBe(true);
  });

  it("rejects armored text, BOM'd text, and other binary", () => {
    const armored = new TextEncoder().encode(
      "-----BEGIN PGP PUBLIC KEY BLOCK-----",
    );
    expect(looksLikeBinaryKey(armored)).toBe(false);
    // UTF-8 BOM has the high bit set but is not a key packet tag.
    expect(looksLikeBinaryKey(new Uint8Array([0xef, 0xbb, 0xbf, 0x2d]))).toBe(
      false,
    );
    // PNG magic: high bit set, new-format tag 9 (not a key).
    expect(looksLikeBinaryKey(new Uint8Array([0x89, 0x50, 0x4e, 0x47]))).toBe(
      false,
    );
    expect(looksLikeBinaryKey(new Uint8Array([]))).toBe(false);
  });
});

describe("binaryKeyToArmored", () => {
  it("armors a public key export with a valid CRC-24 line", () => {
    const armored = binaryKeyToArmored(BINARY_PUBLIC);
    expect(armored).toContain("-----BEGIN PGP PUBLIC KEY BLOCK-----");
    expect(armored).toContain("-----END PGP PUBLIC KEY BLOCK-----");
    // Body then a 4-char base64 CRC line prefixed with '='.
    expect(armored).toMatch(/\n=[A-Za-z0-9+/]{4}\n/);
  });

  it("labels a secret key export as a private block", () => {
    expect(binaryKeyToArmored(BINARY_PRIVATE)).toContain(
      "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    );
  });

  it("returns null for non-key bytes", () => {
    expect(binaryKeyToArmored(new TextEncoder().encode("hello"))).toBeNull();
  });
});
