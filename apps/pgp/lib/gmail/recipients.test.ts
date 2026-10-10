import { describe, expect, it } from "vitest";

import type { PublicContactKey } from "../storage/contacts";
import {
  addressesToAdd,
  matchRecipients,
  primaryEmailOf,
  uncoveredRecipients,
} from "./recipients";

function contact(
  keyId: string,
  userIds: string[],
  extra: Partial<PublicContactKey> = {},
): PublicContactKey {
  return {
    keyId,
    userIds,
    algorithm: "ed25519",
    armoredPublicKey: "",
    addedAt: 0,
    lastUsedAt: 0,
    ...extra,
  };
}

describe("matchRecipients", () => {
  const alice = contact("A1", ["Alice <alice@example.com>"]);
  const bob = contact("B1", ["Bob (work) <Bob@Example.org>", "bob@home.net"]);

  it("matches by the email in any User ID, case-insensitively", () => {
    expect(
      matchRecipients(["alice@example.com", "bob@example.org"], [alice, bob]),
    ).toEqual({ ids: ["A1", "B1"], missing: [] });
    expect(matchRecipients(["BOB@HOME.NET"], [alice, bob]).ids).toEqual(["B1"]);
  });

  it("matches a bare-address User ID", () => {
    const bare = contact("C1", ["carol@example.com"]);
    expect(matchRecipients(["carol@example.com"], [bare]).ids).toEqual(["C1"]);
  });

  it("reports addresses no contact claims", () => {
    expect(
      matchRecipients(["alice@example.com", "dave@example.com"], [alice]),
    ).toEqual({ ids: ["A1"], missing: ["dave@example.com"] });
  });

  it("never preselects a contact that cannot encrypt", () => {
    const signOnly = contact("S1", ["Sam <sam@example.com>"], {
      usableForEncryption: false,
    });
    expect(matchRecipients(["sam@example.com"], [signOnly])).toEqual({
      ids: [],
      missing: ["sam@example.com"],
    });
  });

  it("prefers the most recently used key when two claim an address", () => {
    const oldKey = contact("OLD", ["Alice <alice@example.com>"], {
      lastUsedAt: 10,
    });
    const newKey = contact("NEW", ["Alice <alice@example.com>"], {
      lastUsedAt: 20,
    });
    expect(
      matchRecipients(["alice@example.com"], [oldKey, newKey]).ids,
    ).toEqual(["NEW"]);
  });

  it("treats the user's own addresses as covered, not missing", () => {
    expect(
      matchRecipients(
        ["me@example.com", "alice@example.com"],
        [alice],
        ["Me <me@example.com>"],
      ),
    ).toEqual({ ids: ["A1"], missing: [] });
  });

  it("de-duplicates a contact addressed twice", () => {
    expect(
      matchRecipients(["bob@example.org", "bob@home.net"], [bob]).ids,
    ).toEqual(["B1"]);
  });
});

describe("uncoveredRecipients", () => {
  const alice = contact("A1", ["Alice <alice@example.com>"]);

  it("follows the selection, not the first match", () => {
    const to = ["alice@example.com", "bob@example.org"];
    expect(uncoveredRecipients(to, [alice])).toEqual(["bob@example.org"]);
    // Alice removed from the picker: her address is uncovered again.
    expect(uncoveredRecipients(to, [])).toEqual(to);
  });

  it("counts a hand-picked key under a different identity only if it names the address", () => {
    const work = contact("W1", ["Bob <bob@work.example>", "bob@example.org"]);
    expect(uncoveredRecipients(["bob@example.org"], [work])).toEqual([]);
  });

  it("never reports the user's own address", () => {
    expect(
      uncoveredRecipients(["Me@Example.com"], [], ["Me <me@example.com>"]),
    ).toEqual([]);
  });
});

describe("addressesToAdd", () => {
  it("adds a picked contact the draft doesn't address, by its first address", () => {
    const carol = contact("C1", ["Carol <Carol@Example.com>", "c@home.net"]);
    expect(addressesToAdd(["alice@example.com"], [carol])).toEqual([
      "carol@example.com",
    ]);
  });

  it("skips anyone already on the draft under any of their addresses", () => {
    const bob = contact("B1", ["Bob <bob@work.example>", "bob@example.org"]);
    expect(addressesToAdd(["bob@example.org"], [bob])).toEqual([]);
  });

  it("skips keys with no address", () => {
    const ssh = contact("S1", ["deploy@host"]);
    const nameOnly = contact("N1", ["Just A Name"]);
    expect(addressesToAdd([], [nameOnly])).toEqual([]);
    expect(addressesToAdd([], [ssh])).toEqual([]);
    // An SSH comment that looks like an address is still an address.
    expect(primaryEmailOf(ssh.userIds)).toBe("deploy@host");
  });
});
