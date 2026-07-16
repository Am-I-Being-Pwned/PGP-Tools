import { describe, expect, it } from "vitest";

import {
  matchesRecipientSearch,
  orderRecipients,
  RECENT_RECIPIENTS_CAP,
  updateRecentRecipients,
} from "./recipient-ordering";

function key(id: string, name: string) {
  return { keyId: id, userIds: [`${name} <${name.toLowerCase()}@x.io>`] };
}

const ALICE = key("A", "Alice");
const BOB = key("B", "Bob");
const CAROL = key("C", "Carol");
const DAVE = key("D", "Dave");

describe("orderRecipients", () => {
  it("puts recents first in recency order, rest alphabetical", () => {
    const { recent, rest } = orderRecipients(
      [DAVE, CAROL, ALICE, BOB],
      ["C", "A"],
    );
    expect(recent).toEqual([CAROL, ALICE]);
    expect(rest).toEqual([BOB, DAVE]);
  });

  it("returns everything alphabetical when there are no recents", () => {
    const { recent, rest } = orderRecipients([DAVE, BOB, ALICE], []);
    expect(recent).toEqual([]);
    expect(rest).toEqual([ALICE, BOB, DAVE]);
  });

  it("ignores recents with no matching item", () => {
    const { recent, rest } = orderRecipients([ALICE, BOB], ["gone", "B"]);
    expect(recent).toEqual([BOB]);
    expect(rest).toEqual([ALICE]);
  });

  it("caps the recent section and keeps overflow in the rest", () => {
    const items = Array.from({ length: 12 }, (_, i) =>
      key(`K${i}`, `Name${String(i).padStart(2, "0")}`),
    );
    const recents = items.map((k) => k.keyId);
    const { recent, rest } = orderRecipients(items, recents);
    expect(recent).toHaveLength(RECENT_RECIPIENTS_CAP);
    expect(recent.map((k) => k.keyId)).toEqual(recents.slice(0, 10));
    expect(rest.map((k) => k.keyId)).toEqual(["K10", "K11"]);
  });

  it("respects an explicit cap", () => {
    const { recent, rest } = orderRecipients(
      [ALICE, BOB, CAROL],
      ["B", "C"],
      1,
    );
    expect(recent).toEqual([BOB]);
    expect(rest).toEqual([ALICE, CAROL]);
  });

  it("does not duplicate an item listed twice in recents", () => {
    const { recent, rest } = orderRecipients([ALICE, BOB], ["A", "A", "B"]);
    expect(recent).toEqual([ALICE, BOB]);
    expect(rest).toEqual([]);
  });
});

describe("updateRecentRecipients", () => {
  it("moves used fingerprints to the front", () => {
    expect(updateRecentRecipients(["A", "B", "C"], ["C"])).toEqual([
      "C",
      "A",
      "B",
    ]);
  });

  it("keeps the relative order of a multi-recipient encrypt", () => {
    expect(updateRecentRecipients(["A"], ["B", "C"])).toEqual(["B", "C", "A"]);
  });

  it("collapses duplicates", () => {
    expect(updateRecentRecipients(["A", "B"], ["B", "B"])).toEqual(["B", "A"]);
  });

  it("caps the stored list", () => {
    const current = Array.from({ length: 10 }, (_, i) => `K${i}`);
    const next = updateRecentRecipients(current, ["NEW"]);
    expect(next).toHaveLength(RECENT_RECIPIENTS_CAP);
    expect(next[0]).toBe("NEW");
    expect(next).not.toContain("K9");
  });

  it("handles an empty current list", () => {
    expect(updateRecentRecipients([], ["A"])).toEqual(["A"]);
  });
});

describe("matchesRecipientSearch", () => {
  const alice = {
    keyId: "0123ABCD",
    userIds: ["Alice Smith (work) <alice@example.com>"],
  };

  it("matches everything on an empty or blank query", () => {
    expect(matchesRecipientSearch(alice, "")).toBe(true);
    expect(matchesRecipientSearch(alice, "   ")).toBe(true);
  });

  it("matches name, email, comment and key id, case-insensitively", () => {
    expect(matchesRecipientSearch(alice, "alice")).toBe(true);
    expect(matchesRecipientSearch(alice, "SMITH")).toBe(true);
    expect(matchesRecipientSearch(alice, "example.com")).toBe(true);
    expect(matchesRecipientSearch(alice, "work")).toBe(true);
    expect(matchesRecipientSearch(alice, "0123abcd")).toBe(true);
  });

  it("requires every token to match", () => {
    expect(matchesRecipientSearch(alice, "alice example")).toBe(true);
    expect(matchesRecipientSearch(alice, "alice bob")).toBe(false);
  });

  it("rejects non-matching queries", () => {
    expect(matchesRecipientSearch(alice, "carol")).toBe(false);
  });

  it("falls back to the key id for keys without user ids", () => {
    const bare = { keyId: "DEADBEEF", userIds: [] };
    expect(matchesRecipientSearch(bare, "beef")).toBe(true);
    expect(matchesRecipientSearch(bare, "alice")).toBe(false);
  });
});
