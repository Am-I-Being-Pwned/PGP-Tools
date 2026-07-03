import { describe, expect, it } from "vitest";

import {
  formatAlgorithm,
  formatFileSize,
  formatFingerprint,
} from "./formatting";

describe("formatAlgorithm", () => {
  it("splits camelCase suffixes", () => {
    expect(formatAlgorithm("ed25519Legacy")).toBe("ed25519 Legacy");
  });

  it("leaves plain names alone", () => {
    expect(formatAlgorithm("rsa4096")).toBe("rsa4096");
    expect(formatAlgorithm("ed25519")).toBe("ed25519");
  });
});

describe("formatFingerprint", () => {
  it("groups into 4-char blocks", () => {
    expect(formatFingerprint("ABCD1234EF567890")).toBe("ABCD 1234 EF56 7890");
  });

  it("keeps a trailing partial block", () => {
    expect(formatFingerprint("ABCD12")).toBe("ABCD 12");
  });

  it("returns empty input unchanged", () => {
    expect(formatFingerprint("")).toBe("");
  });
});

describe("formatFileSize", () => {
  it("formats bytes", () => {
    expect(formatFileSize(0)).toBe("0 B");
    expect(formatFileSize(1023)).toBe("1023 B");
  });

  it("formats kilobytes", () => {
    expect(formatFileSize(1024)).toBe("1.0 KB");
    expect(formatFileSize(1536)).toBe("1.5 KB");
  });

  it("formats megabytes", () => {
    expect(formatFileSize(1024 * 1024)).toBe("1.0 MB");
    expect(formatFileSize(2.5 * 1024 * 1024)).toBe("2.5 MB");
  });
});
