import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// A private bundle so the tests do not depend on which real keys exist.
vi.mock("./messages.generated", () => ({
  PLACEHOLDER_ORDER: {
    greet: ["name", "n"],
    items_one: ["count"],
    items_other: ["count"],
    items_few: ["count"],
  },
}));

const BUNDLE: Partial<Record<string, string>> = {
  plain: "Plain text",
  greet: "Hello $1, you have $2",
  items_one: "$1 item",
  items_other: "$1 items",
  items_few: "$1 items (few)",
};

let lang = "en";
const getMessage = vi.fn((key: string, subs?: string[]) => {
  const m = BUNDLE[key];
  if (m === undefined) return "";
  return m.replace(/\$(\d)/g, (_, i: string) => subs?.[Number(i) - 1] ?? "");
});

interface Chrome {
  chrome?: { i18n?: unknown };
}
let saved: unknown;

beforeEach(() => {
  saved = (globalThis as Chrome).chrome?.i18n;
  (globalThis as Chrome).chrome = {
    i18n: { getMessage, getUILanguage: () => lang },
  };
  getMessage.mockClear();
});
afterEach(() => {
  (globalThis as Chrome).chrome = { i18n: saved };
  lang = "en";
});

// Cast through unknown: the real key types come from the generated file,
// which this test replaces.
const T = async () =>
  (await import("./index")) as unknown as {
    t: (k: string, s?: Record<string, string | number>) => string;
    tn: (k: string, n: number, s?: Record<string, string | number>) => string;
    uiLanguage: () => string;
  };

describe("t", () => {
  it("returns the message", async () => {
    expect((await T()).t("plain")).toBe("Plain text");
  });
  it("orders named substitutions the way the bundle numbered them", async () => {
    expect((await T()).t("greet", { n: 3, name: "Ada" })).toBe(
      "Hello Ada, you have 3",
    );
    expect(getMessage).toHaveBeenLastCalledWith("greet", ["Ada", "3"]);
  });
  it("falls back to the key for an unknown message", async () => {
    expect((await T()).t("nope")).toBe("nope");
  });
  it("returns the key when chrome is absent (node without the shim)", async () => {
    (globalThis as Chrome).chrome = undefined;
    expect((await T()).t("plain")).toBe("plain");
  });
});

describe("tn", () => {
  it("picks _one and _other in English", async () => {
    const { tn } = await T();
    expect(tn("items", 1)).toBe("1 item");
    expect(tn("items", 2)).toBe("2 items");
    expect(tn("items", 0)).toBe("0 items");
  });
  it("uses a locale-only category when the bundle has it", async () => {
    lang = "ru";
    const { tn } = await T();
    expect(tn("items", 3)).toBe("3 items (few)");
    expect(tn("items", 5)).toBe("5 items");
  });
  it("falls back to _other when the category is missing", async () => {
    lang = "ar"; // has "two"; the bundle does not
    expect((await T()).tn("items", 2)).toBe("2 items");
  });
});

describe("uiLanguage", () => {
  it("defaults to en when chrome reports nothing", async () => {
    lang = "";
    expect((await T()).uiLanguage()).toBe("en");
  });
});
