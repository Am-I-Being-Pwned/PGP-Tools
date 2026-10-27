import { describe, expect, it } from "vitest";

import {
  displayFileName,
  hasHiddenCharacters,
  safeFileName,
} from "./file-name";

describe("safeFileName", () => {
  it("removes a right-to-left override that disguises the extension", () => {
    // Shown raw, "inv\u202ecsa.exe" reads as "invexe.asc".
    expect(safeFileName("inv\u202ecsa.exe")).toBe("invcsa.exe");
  });

  it("removes zero-width, bidi isolates, line breaks and control characters", () => {
    expect(safeFileName("re\u200bport\u2066.pdf\u2069\n\t\u0000.asc")).toBe(
      "report.pdf.asc",
    );
  });

  it("leaves ordinary names, in any script, alone", () => {
    for (const name of ["release-4.2.tar.gz.asc", "отчёт.pdf", "報告.txt"]) {
      expect(safeFileName(name)).toBe(name);
    }
  });
});

describe("displayFileName", () => {
  it("shortens from the middle so the extension stays visible", () => {
    const shown = displayFileName(`${"a".repeat(100)}.tar.gz.asc`, 40);
    expect([...shown]).toHaveLength(40);
    expect(shown.endsWith(".tar.gz.asc")).toBe(true);
    expect(shown).toContain("…");
  });
});

describe("hasHiddenCharacters", () => {
  it("spots a right-to-left override and zero-width characters", () => {
    expect(hasHiddenCharacters("pay \u202e0001\u202c to bob")).toBe(true);
    expect(hasHiddenCharacters("pa\u200by")).toBe(true);
  });

  it("does not flag ordinary text, line breaks or tabs", () => {
    expect(hasHiddenCharacters("Release 4.2\n\tsigned off\r\n")).toBe(false);
    expect(hasHiddenCharacters("Иван Петров, 報告")).toBe(false);
  });
});
