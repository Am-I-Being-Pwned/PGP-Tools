import { describe, expect, it } from "vitest";

import { forgetLastRegExpMatch } from "./regexp-residue";

describe("forgetLastRegExpMatch", () => {
  it("replaces the realm's last-match subject", () => {
    /secret/.exec("a secret message");
    // The legacy static reads the same slot V8 retains.
    expect((RegExp as unknown as { input: string }).input).toBe(
      "a secret message",
    );
    forgetLastRegExpMatch();
    expect((RegExp as unknown as { input: string }).input).toBe("-");
  });
});
