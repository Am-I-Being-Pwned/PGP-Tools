import { describe, expect, it } from "vitest";

import { confirmTextMatches } from "./confirm-text";

describe("confirmTextMatches", () => {
  it("matches exact text", () => {
    expect(confirmTextMatches("Alice", "Alice")).toBe(true);
  });

  it("forgives leading/trailing whitespace", () => {
    expect(confirmTextMatches("Alice", "  Alice ")).toBe(true);
    expect(confirmTextMatches("delete 3 keys", "delete 3 keys\n")).toBe(true);
  });

  it("is case-sensitive", () => {
    expect(confirmTextMatches("Alice", "alice")).toBe(false);
    expect(confirmTextMatches("Alice", "ALICE")).toBe(false);
  });

  it("rejects partial or different text", () => {
    expect(confirmTextMatches("Alice", "Alic")).toBe(false);
    expect(confirmTextMatches("Alice", "Alice Smith")).toBe(false);
    expect(confirmTextMatches("Alice", "")).toBe(false);
  });

  it("does not trim inner whitespace", () => {
    expect(confirmTextMatches("delete 3 keys", "delete 3  keys")).toBe(false);
  });
});
