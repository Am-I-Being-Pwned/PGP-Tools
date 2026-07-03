import { describe, expect, it } from "vitest";

import {
  looksLikeCollapsedArmor,
  reconstructArmor,
  recoverArmorIfNeeded,
} from "./armor-recovery";

// 64-char base64 lines like real armor output.
const LINE_A = "A".repeat(64);
const LINE_B = "B".repeat(64);

function collapse(armor: string): string {
  return armor.replace(/\s+/g, " ");
}

const ARMOR_WITH_HEADERS = [
  "-----BEGIN PGP MESSAGE-----",
  "Version: Encryption Desktop 10.4.1",
  "Comment: https://example.com",
  "",
  LINE_A,
  LINE_B,
  "CCCC",
  "=AbCd",
  "-----END PGP MESSAGE-----",
].join("\n");

const ARMOR_NO_HEADERS = [
  "-----BEGIN PGP PUBLIC KEY BLOCK-----",
  "",
  LINE_A,
  "=AbCd",
  "-----END PGP PUBLIC KEY BLOCK-----",
].join("\n");

describe("looksLikeCollapsedArmor", () => {
  it("detects a collapsed armor block", () => {
    expect(looksLikeCollapsedArmor(collapse(ARMOR_WITH_HEADERS))).toBe(true);
  });

  it("rejects intact armor", () => {
    expect(looksLikeCollapsedArmor(ARMOR_WITH_HEADERS)).toBe(false);
  });

  it("rejects text without a BEGIN marker", () => {
    expect(looksLikeCollapsedArmor("hello world")).toBe(false);
  });
});

describe("reconstructArmor", () => {
  it("round-trips collapsed armor with multi-word header values", () => {
    expect(reconstructArmor(collapse(ARMOR_WITH_HEADERS))).toBe(
      ARMOR_WITH_HEADERS,
    );
  });

  it("round-trips collapsed armor without headers", () => {
    expect(reconstructArmor(collapse(ARMOR_NO_HEADERS))).toBe(ARMOR_NO_HEADERS);
  });

  it("handles armor without a CRC line (OpenPGP v6 omits it)", () => {
    const armor = [
      "-----BEGIN PGP MESSAGE-----",
      "",
      LINE_A,
      "-----END PGP MESSAGE-----",
    ].join("\n");
    expect(reconstructArmor(collapse(armor))).toBe(armor);
  });

  it("re-wraps base64 data to 64 chars per line", () => {
    const result = reconstructArmor(collapse(ARMOR_WITH_HEADERS));
    const dataLines = result
      .split("\n")
      .filter((l) => /^[AB C]+$/.test(l) && l.length > 0);
    for (const line of dataLines) {
      expect(line.length).toBeLessThanOrEqual(64);
    }
  });

  it("round-trips a detached signature block", () => {
    const armor = [
      "-----BEGIN PGP SIGNATURE-----",
      "",
      LINE_A,
      "=AbCd",
      "-----END PGP SIGNATURE-----",
    ].join("\n");
    expect(reconstructArmor(collapse(armor))).toBe(armor);
  });

  it("never rewraps a cleartext-signed message body", () => {
    // The free-text body of a cleartext-signed message must not be
    // reconstructed as base64. The BEGIN type (SIGNED MESSAGE) never
    // matches the first END type (SIGNATURE), so it passes through.
    const signed = collapse(
      [
        "-----BEGIN PGP SIGNED MESSAGE-----",
        "Hash: SHA256",
        "",
        "This human-readable text must survive untouched.",
        "-----BEGIN PGP SIGNATURE-----",
        "",
        LINE_A,
        "=AbCd",
        "-----END PGP SIGNATURE-----",
      ].join("\n"),
    );
    expect(reconstructArmor(signed)).toBe(signed);
  });

  it("bails on mismatched BEGIN/END block types", () => {
    const mismatched = collapse(
      ARMOR_WITH_HEADERS.replace(
        "-----END PGP MESSAGE-----",
        "-----END PGP PUBLIC KEY BLOCK-----",
      ),
    );
    expect(reconstructArmor(mismatched)).toBe(mismatched);
  });

  it("bails when there is no plausible base64 data", () => {
    const junk =
      "-----BEGIN PGP MESSAGE----- not actual armor -----END PGP MESSAGE-----";
    expect(reconstructArmor(junk)).toBe(junk);
  });

  it("returns non-armor text unchanged", () => {
    expect(reconstructArmor("plain text")).toBe("plain text");
  });
});

describe("recoverArmorIfNeeded", () => {
  it("reconstructs collapsed armor", () => {
    expect(recoverArmorIfNeeded(collapse(ARMOR_WITH_HEADERS))).toBe(
      ARMOR_WITH_HEADERS,
    );
  });

  it("passes intact armor through untouched", () => {
    expect(recoverArmorIfNeeded(ARMOR_WITH_HEADERS)).toBe(ARMOR_WITH_HEADERS);
  });

  it("passes plain text through untouched", () => {
    expect(recoverArmorIfNeeded("just some text")).toBe("just some text");
  });
});
