import { describe, expect, it } from "vitest";

import { EXPIRY_SECONDS, expiryToSeconds } from "./expiry";

const NOW = Date.UTC(2026, 0, 1);

describe("expiryToSeconds", () => {
  it("maps the fixed spans", () => {
    expect(expiryToSeconds("never", undefined, NOW)).toBe(0);
    expect(expiryToSeconds("1y", undefined, NOW)).toBe(365 * 86_400);
    expect(expiryToSeconds("3y", undefined, NOW)).toBe(EXPIRY_SECONDS["3y"]);
  });

  it("counts a custom date from now, whole seconds", () => {
    const date = new Date(NOW + 10 * 86_400_000 + 999);
    expect(expiryToSeconds("custom", date, NOW)).toBe(10 * 86_400);
  });

  it("never yields a past or missing custom date as an expiry", () => {
    expect(expiryToSeconds("custom", new Date(NOW - 1000), NOW)).toBe(0);
    expect(expiryToSeconds("custom", new Date(NOW), NOW)).toBe(0);
    expect(expiryToSeconds("custom", undefined, NOW)).toBe(0);
  });
});
