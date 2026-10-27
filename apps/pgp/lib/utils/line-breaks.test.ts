import { describe, expect, it } from "vitest";

import { hasLoneCarriageReturn, showLoneCarriageReturns } from "./line-breaks";

describe("lone carriage returns", () => {
  it("finds a CR that no LF follows, and only that", () => {
    expect(hasLoneCarriageReturn("Approved:\rNO")).toBe(true);
    expect(hasLoneCarriageReturn("trailing\r")).toBe(true);
    expect(hasLoneCarriageReturn("Approved:\r\nNO")).toBe(false);
    expect(hasLoneCarriageReturn("Approved:\nNO")).toBe(false);
  });

  it("draws each lone CR as a symbol and a line break, nothing else", () => {
    expect(showLoneCarriageReturns("Approved:\rNO")).toBe(
      "Approved:\u240d\nNO",
    );
    expect(showLoneCarriageReturns("a\r\nb\rc")).toBe("a\r\nb\u240d\nc");
    const plain = "no carriage returns\nhere";
    expect(showLoneCarriageReturns(plain)).toBe(plain);
  });
});
