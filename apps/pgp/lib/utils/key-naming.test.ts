import { describe, expect, it } from "vitest";

import { formatKeyDisplayName, parseUserId } from "./key-naming";

describe("parseUserId", () => {
  it("parses name and email", () => {
    expect(parseUserId("Alice Example <alice@example.com>")).toEqual({
      name: "Alice Example",
      comment: undefined,
      email: "alice@example.com",
    });
  });

  it("parses name, comment, and email", () => {
    expect(parseUserId("Alice (work) <alice@example.com>")).toEqual({
      name: "Alice",
      comment: "work",
      email: "alice@example.com",
    });
  });

  it("falls back to the raw string without an email", () => {
    expect(parseUserId("just a name")).toEqual({
      name: "just a name",
      email: "",
    });
  });

  it("handles undefined", () => {
    expect(parseUserId(undefined)).toEqual({ name: "Unknown", email: "" });
  });
});

describe("formatKeyDisplayName", () => {
  it("uses the email as detail", () => {
    expect(formatKeyDisplayName("Alice <alice@example.com>")).toEqual({
      name: "Alice",
      detail: "alice@example.com",
    });
  });

  it("prefixes the comment when present", () => {
    expect(formatKeyDisplayName("Alice (work) <alice@example.com>")).toEqual({
      name: "Alice",
      detail: "work - alice@example.com",
    });
  });
});
