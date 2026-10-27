import { describe, expect, it } from "vitest";

import {
  addressSkeletons,
  contactClashes,
  emailOf,
  emailsOf,
  identityClashes,
  identityConflict,
  nameOf,
  nameSkeleton,
} from "./binding";

const carol = { keyId: "AAAA", userIds: ["Carol Lane <carol@example.com>"] };

describe("emailOf / nameOf", () => {
  it("reads the address and name of a User ID", () => {
    expect(emailOf("Carol Lane <Carol@Example.com>")).toBe("carol@example.com");
    expect(emailOf("carol@example.com")).toBe("carol@example.com");
    expect(emailOf("Carol Lane")).toBeNull();
    expect(nameOf("Carol Lane (work) <carol@example.com>")).toBe("Carol Lane");
  });

  it("reads an address wherever it sits, and a name around it", () => {
    expect(emailsOf("Carol Lane carol@example.com")).toEqual([
      "carol@example.com",
    ]);
    expect(emailsOf("Carol <carol@example.com> (alt: c@d.test)")).toEqual([
      "carol@example.com",
      "c@d.test",
    ]);
    expect(nameOf("Carol Lane <carol@example.com> (work)")).toBe("Carol Lane");
    expect(nameOf("Carol Lane carol@example.com")).toBe("Carol Lane");
    expect(nameOf("Carol Lane <carol@example.com")).toBe("Carol Lane");
  });
});

describe("invisible characters in addresses", () => {
  // Each draws nothing, so each makes a different string read as
  // alice@corp.com: a variation selector, a tag character, a zero-width
  // space, a soft hyphen, a bidi isolate, a combining grapheme joiner,
  // a Hangul filler, a Mongolian vowel separator, an Arabic letter mark,
  // and the symbols that draw as an empty cell without being ignorable:
  // the Braille blank, the object replacement character, the musical
  // null notehead, and a line separator.
  const hidden = [
    "\ufe0f",
    "\u{e0020}",
    "\u200b",
    "\u00ad",
    "\u2066",
    "\u034f",
    "\u3164",
    "\u180e",
    "\u061c",
    "\u2800",
    "\ufffc",
    "\u{1d159}",
    "\u2028",
  ];

  it("reads every one of them as the address it looks like", () => {
    for (const h of hidden) {
      expect(emailsOf(`<alice@corp.com${h}>`), JSON.stringify(h)).toEqual([
        "alice@corp.com",
      ]);
      expect(emailsOf(`Al <ali${h}ce@corp.com>`), JSON.stringify(h)).toEqual([
        "alice@corp.com",
      ]);
    }
  });

  it("folds compatibility forms and a trailing dot", () => {
    expect(emailsOf("\uff41lice\uff20corp.com.")).toEqual(["alice@corp.com"]);
  });

  it("flags an address-only User ID hiding one, by its address", () => {
    // The name part is empty (or only the invisible character), so the
    // address check is the one that has to catch it.
    const alice = { keyId: "ALICE", userIds: ["Alice Smith <alice@corp.com>"] };
    for (const h of hidden) {
      const evil = { keyId: "EVIL", userIds: [`<alice@corp.com${h}>`] };
      expect(identityConflict(evil, [alice])?.kind, JSON.stringify(h)).toBe(
        "address",
      );
      expect(contactClashes([alice, evil], []).size, JSON.stringify(h)).toBe(2);
    }
  });

  it("reads a name the same way", () => {
    expect(nameOf("Alice\ufe0f Smith <a@b.test>")).toBe("Alice Smith");
    expect(nameSkeleton("Alice Smith\u3164")).toBe(nameSkeleton("Alice Smith"));
    expect(nameSkeleton("Al\u{e0041}ice Smith")).toBe(
      nameSkeleton("Alice Smith"),
    );
  });
});

describe("nameSkeleton", () => {
  it("reads look-alike letters, case, accents and spacing as the same name", () => {
    const plain = nameSkeleton("Carol Lane");
    // Cyrillic C, a, o; fullwidth L; a zero-width space; a digit zero.
    expect(nameSkeleton("\u0421\u0430r\u043el Lane")).toBe(plain);
    expect(nameSkeleton("Carol \uff2cane")).toBe(plain);
    expect(nameSkeleton("Car\u200bol  LANE")).toBe(plain);
    expect(nameSkeleton("Car0l Lane")).toBe(plain);
    expect(nameSkeleton("Carol L\u00e1ne")).toBe(plain);
  });

  it("keeps genuinely different names apart", () => {
    expect(nameSkeleton("Carol Lane")).not.toBe(nameSkeleton("Carl Lane"));
    expect(nameSkeleton("Иван")).not.toBe(nameSkeleton("Ivan"));
  });
});

describe("identityConflict", () => {
  it("flags a different key claiming a contact's address", () => {
    // The advisory: a new key copying the contact's name and email.
    const conflict = identityConflict(
      { keyId: "BBBB", userIds: ["Carol Lane <CAROL@example.com>"] },
      [carol],
    );
    expect(conflict).toEqual({ kind: "address", holders: [carol] });
  });

  it("flags a look-alike name under a different address", () => {
    const conflict = identityConflict(
      {
        keyId: "BBBB",
        userIds: ["\u0421\u0430rol Lane <carol.lane@mail.example>"],
      },
      [carol],
    );
    expect(conflict?.kind).toBe("name");
  });

  it("is never a conflict for the same key (an update)", () => {
    expect(
      identityConflict({ keyId: "aaaa", userIds: carol.userIds }, [carol]),
    ).toBeNull();
  });

  it("ignores a revoked key, and unrelated people", () => {
    expect(
      identityConflict({ keyId: "BBBB", userIds: carol.userIds }, [
        { ...carol, revoked: true },
      ]),
    ).toBeNull();
    expect(
      identityConflict(
        { keyId: "BBBB", userIds: ["Dave Hill <dave@example.com>"] },
        [carol],
      ),
    ).toBeNull();
  });
});

describe("identityClashes", () => {
  it("marks BOTH keys that claim one address, each against the other", () => {
    // The contact list shows the clash on each card, not just the newer.
    const rival = { keyId: "BBBB", userIds: carol.userIds };
    const clashes = identityClashes([carol, rival]);
    expect(clashes.get("AAAA")).toEqual({ kind: "address", holders: [rival] });
    expect(clashes.get("BBBB")).toEqual({ kind: "address", holders: [carol] });
  });

  it("marks a look-alike name on both cards", () => {
    const lookalike = {
      keyId: "BBBB",
      userIds: ["\u0421\u0430rol Lane <carol.lane@mail.example>"],
    };
    const clashes = identityClashes([carol, lookalike]);
    expect(clashes.get("AAAA")?.kind).toBe("name");
    expect(clashes.get("BBBB")?.kind).toBe("name");
  });

  it("leaves out unrelated people, and a contact listed only once", () => {
    const dave = { keyId: "DDDD", userIds: ["Dave Hill <dave@example.com>"] };
    expect(identityClashes([carol, dave]).size).toBe(0);
    // A holder never clashes with itself.
    expect(identityClashes([carol]).size).toBe(0);
  });

  it("never marks a revoked key, nor anyone against it", () => {
    const retired = { keyId: "BBBB", userIds: carol.userIds, revoked: true };
    expect(identityClashes([carol, retired]).size).toBe(0);
  });

  it("lists every holder when three keys claim one address", () => {
    const b = { keyId: "BBBB", userIds: carol.userIds };
    const c = { keyId: "CCCC", userIds: ["carol@example.com"] };
    const clashes = identityClashes([carol, b, c]);
    expect([...clashes.keys()]).toEqual(["AAAA", "BBBB", "CCCC"]);
    expect(clashes.get("AAAA")?.holders).toEqual([b, c]);
  });
});

describe("contactClashes", () => {
  it("marks a contact wearing the user's own identity, never the own key", () => {
    const mine = { keyId: "MINE", userIds: carol.userIds };
    const impostor = { keyId: "BBBB", userIds: ["Carol Lane <c@evil.test>"] };
    const clashes = contactClashes([impostor], [mine]);
    expect(clashes.get("BBBB")).toMatchObject({
      kind: "name",
      holders: [{ keyId: "MINE", own: true }],
    });
    expect(clashes.has("MINE")).toBe(false);
  });

  it("does not mark the user's own key held as a contact too", () => {
    const mine = { keyId: "AAAA", userIds: carol.userIds };
    expect(contactClashes([carol], [mine]).size).toBe(0);
  });
});

describe("look-alike addresses", () => {
  const alice = { keyId: "ALICE", userIds: ["alice@corp.com"] };
  const named = { keyId: "ALICE", userIds: ["Alice <alice@corp.com>"] };
  // A dotless i, a Greek omicron in the domain, a Cyrillic а, a digit one
  // and a capital I passing for l, and rn passing for m.
  const lookalikes = [
    "al\u0131ce@corp.com",
    "alice@c\u03bfrp.com",
    "\u0430lice@corp.com",
    "a1ice@corp.com",
    "AIice@corp.com",
    "al\u00edce@corp.com",
    "alice@corp\uff65com",
    "alice@corp\u00b7com",
  ];

  it("reads each as the address it imitates", () => {
    for (const a of lookalikes) {
      expect(addressSkeletons(a), a).toContain(
        addressSkeletons("alice@corp.com")[0],
      );
    }
    expect(addressSkeletons("rnallory@corp.com")).toEqual(
      addressSkeletons("mallory@corp.com"),
    );
  });

  it("flags one against an address-only User ID, and a named one", () => {
    for (const a of lookalikes) {
      const evil = { keyId: "EVIL", userIds: [a] };
      for (const holder of [alice, named]) {
        expect(identityConflict(evil, [holder]), a).toEqual({
          kind: "address",
          lookalike: true,
          holders: [holder],
        });
      }
      expect(contactClashes([named, evil], []).get("EVIL")?.lookalike, a).toBe(
        true,
      );
    }
  });

  it("still calls the very same address an address conflict", () => {
    expect(
      identityConflict({ keyId: "EVIL", userIds: ["ALICE@corp.com"] }, [alice]),
    ).toEqual({ kind: "address", holders: [alice] });
  });

  it("keeps addresses that only share their letters apart", () => {
    for (const a of [
      "a.lice@corp.com",
      "alice@corp.co",
      "alice@corp-com.test",
    ]) {
      expect(
        identityConflict({ keyId: "EVIL", userIds: [a] }, [alice]),
        a,
      ).toBeNull();
    }
  });
});
