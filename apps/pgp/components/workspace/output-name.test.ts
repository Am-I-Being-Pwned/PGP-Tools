import { describe, expect, it } from "vitest";

import { outputFileName } from "./output-name";

// Fixed clock: 16 Jul 2026, 14:32 local.
const NOW = new Date(2026, 6, 16, 14, 32);
const AT = { now: NOW };
const TS = "2026-07-16-1432";

describe("outputFileName", () => {
  it("names text-input encrypt output with recipient and timestamp", () => {
    expect(outputFileName("encrypt", [], true, AT)).toBe(`message.${TS}.gpg`);
    expect(
      outputFileName("encrypt", [], true, { ...AT, recipients: ["Alice"] }),
    ).toBe(`message.to-alice.${TS}.gpg`);
    expect(outputFileName("decrypt", [], true)).toBe("output.gpg");
  });

  it("tags a single-file encrypt with recipient and timestamp", () => {
    expect(
      outputFileName("encrypt", ["report.pdf"], true, {
        ...AT,
        recipients: ["Alice"],
      }),
    ).toBe(`report.pdf.to-alice.${TS}.gpg`);
  });

  it("counts extra recipients instead of listing them", () => {
    expect(
      outputFileName("encrypt", [], true, {
        ...AT,
        recipients: ["Alice", "Bob", "Carol"],
      }),
    ).toBe(`message.to-alice+2.${TS}.gpg`);
  });

  it("slugifies hostile recipient names and caps their length", () => {
    expect(
      outputFileName("encrypt", [], true, {
        ...AT,
        recipients: ["CERT.br - Computer Emergency Response Team Brazil"],
      }),
    ).toBe(`message.to-cert-br-computer-emergen.${TS}.gpg`);
    expect(
      outputFileName("encrypt", [], true, { ...AT, recipients: ["!!!"] }),
    ).toBe(`message.to-recipient.${TS}.gpg`);
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
    expect(
      outputFileName("encrypt", files, true, { ...AT, recipients: ["Alice"] }),
    ).toBe(`files.to-alice.${TS}.zip.gpg`);
    expect(outputFileName("decrypt", files, true)).toBe("decrypted-files.zip");
  });

  it("uses the first file's name for unzipped multi-file input", () => {
    expect(
      outputFileName("encrypt", ["a.txt", "b.txt"], false, {
        ...AT,
        recipients: ["Alice"],
      }),
    ).toBe(`a.txt.to-alice.${TS}.gpg`);
  });
});
