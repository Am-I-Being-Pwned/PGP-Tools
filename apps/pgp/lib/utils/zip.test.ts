import { describe, expect, it } from "vitest";

import { isZipArchive, zipFiles } from "./zip";

describe("isZipArchive", () => {
  it("recognises the PK\\x03\\x04 magic", () => {
    expect(isZipArchive(new Uint8Array([0x50, 0x4b, 0x03, 0x04, 0xff]))).toBe(
      true,
    );
  });

  it("rejects other data", () => {
    expect(isZipArchive(new Uint8Array([0x50, 0x4b, 0x05, 0x06]))).toBe(false);
    expect(isZipArchive(new TextEncoder().encode("hello"))).toBe(false);
  });

  it("rejects inputs shorter than the magic", () => {
    expect(isZipArchive(new Uint8Array([0x50, 0x4b]))).toBe(false);
    expect(isZipArchive(new Uint8Array(0))).toBe(false);
  });
});

describe("zipFiles", () => {
  it("produces a zip archive from files", async () => {
    const files = [
      new File([new TextEncoder().encode("first")], "a.txt"),
      new File([new TextEncoder().encode("second")], "b.txt"),
    ];
    const archive = await zipFiles(files);
    expect(isZipArchive(archive)).toBe(true);
    // Entry names are stored verbatim in the archive.
    const text = new TextDecoder("latin1").decode(archive);
    expect(text).toContain("a.txt");
    expect(text).toContain("b.txt");
  });
});
