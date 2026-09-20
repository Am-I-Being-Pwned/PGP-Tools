import { afterEach, describe, expect, it } from "vitest";

import { formatDate, formatDateShort, formatRelative } from "./format";

interface Chrome {
  chrome?: { i18n?: { getUILanguage: () => string } };
}
const setLang = (tag: string) => {
  (globalThis as Chrome).chrome = {
    i18n: { ...(globalThis as Chrome).chrome?.i18n, getUILanguage: () => tag },
  };
};
const original = (globalThis as Chrome).chrome;
afterEach(() => {
  (globalThis as Chrome).chrome = original;
});

const d = Date.UTC(2026, 8, 20, 12);

describe("formatDate", () => {
  it("follows the UI language", () => {
    setLang("en-US");
    expect(formatDate(d)).toBe("September 20, 2026");
    setLang("de");
    expect(formatDate(d)).toBe("20. September 2026");
  });
  it("survives a bogus tag", () => {
    setLang("not a tag");
    expect(formatDate(d)).toContain("2026");
  });
  it("has a short form", () => {
    setLang("en-US");
    expect(formatDateShort(d)).toBe("Sep 20, 2026");
  });
});

describe("formatRelative", () => {
  it("renders past and future with the largest fitting unit", () => {
    setLang("en-US");
    const now = d;
    expect(formatRelative(d - 3 * 24 * 3600 * 1000, now)).toBe("3 days ago");
    expect(formatRelative(d + 2 * 3600 * 1000, now)).toBe("in 2 hours");
    expect(formatRelative(d + 400 * 24 * 3600 * 1000, now)).toBe("next year");
    expect(formatRelative(d + 10 * 1000, now)).toBe("now");
  });
  it("localises", () => {
    setLang("fr");
    expect(formatRelative(d - 3 * 24 * 3600 * 1000, d)).toBe("il y a 3 jours");
  });
});
