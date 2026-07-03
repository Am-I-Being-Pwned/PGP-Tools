import { describe, expect, it } from "vitest";

import { outputFileName } from "./output-name";

describe("outputFileName", () => {
  it("defaults for text input", () => {
    expect(outputFileName("encrypt", [], true)).toBe("output.gpg");
    expect(outputFileName("decrypt", [], true)).toBe("output.gpg");
  });

  it("appends .gpg when encrypting a single file", () => {
    expect(outputFileName("encrypt", ["report.pdf"], true)).toBe(
      "report.pdf.gpg",
    );
  });

  it("appends .asc when signing a single file", () => {
    expect(outputFileName("sign", ["notes.txt"], true)).toBe("notes.txt.asc");
  });

  it("strips the encryption extension when decrypting", () => {
    expect(outputFileName("decrypt", ["report.pdf.gpg"], true)).toBe(
      "report.pdf",
    );
    expect(outputFileName("decrypt", ["msg.asc"], true)).toBe("msg");
    expect(outputFileName("decrypt", ["data.PGP"], true)).toBe("data");
  });

  it("keeps the name when there is no known extension to strip", () => {
    expect(outputFileName("decrypt", ["report.bin"], true)).toBe("report.bin");
  });

  it("keeps the name when stripping would leave nothing", () => {
    expect(outputFileName("decrypt", [".gpg"], true)).toBe(".gpg");
  });

  it("names the combined archive for zipped multi-file input", () => {
    const files = ["a.txt", "b.txt"];
    expect(outputFileName("encrypt", files, true)).toBe(
      "encrypted-files.zip.gpg",
    );
    expect(outputFileName("decrypt", files, true)).toBe("decrypted-files.zip");
  });

  it("uses the first file's name for unzipped multi-file input", () => {
    expect(outputFileName("encrypt", ["a.txt", "b.txt"], false)).toBe(
      "a.txt.gpg",
    );
  });
});
