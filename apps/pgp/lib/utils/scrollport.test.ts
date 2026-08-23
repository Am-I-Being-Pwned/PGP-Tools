import { describe, expect, it } from "vitest";

import { isFullyVisible } from "./scrollport";

/** The scrollport is offset from the viewport (a header sits above it),
 *  so "visible" is measured against the port's own bounds -- comparing
 *  against 0/innerHeight would call a card hidden behind the header
 *  visible and skip the scroll that would reveal it. */
const port = { top: 90, bottom: 500 };

describe("isFullyVisible", () => {
  it("accepts a card inside the port", () => {
    expect(isFullyVisible({ top: 200, bottom: 280 }, port)).toBe(true);
  });

  it("accepts a card flush with either edge", () => {
    expect(isFullyVisible({ top: 90, bottom: 170 }, port)).toBe(true);
    expect(isFullyVisible({ top: 420, bottom: 500 }, port)).toBe(true);
  });

  it("rejects a card below the fold", () => {
    expect(isFullyVisible({ top: 560, bottom: 640 }, port)).toBe(false);
  });

  it("rejects a card scrolled off the top", () => {
    expect(isFullyVisible({ top: -53, bottom: 27 }, port)).toBe(false);
  });

  it("rejects a card only PARTLY in view", () => {
    // The case a naive intersection test gets wrong: the top edge is in
    // the port, so the card is "on screen" -- but its fingerprint line
    // and the details arrow are not, which is what the reveal is for.
    expect(isFullyVisible({ top: 460, bottom: 540 }, port)).toBe(false);
    expect(isFullyVisible({ top: 60, bottom: 140 }, port)).toBe(false);
  });
});
