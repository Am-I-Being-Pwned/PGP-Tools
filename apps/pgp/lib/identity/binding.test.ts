import { describe, expect, it } from "vitest";

import {
  addressSkeletons,
  contactClash,
  contactClashes,
  emailOf,
  emailsOf,
  identityClashes,
  identityConflict,
  nameOf,
  nameSkeleton,
  namesLookAlike,
  noteKeyId,
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
    const impostor = {
      keyId: "BBBB",
      userIds: ["Car\u043el Lane <c@evil.test>"],
    };
    const clashes = contactClashes([impostor], [mine]);
    expect(clashes.get("BBBB")).toMatchObject({
      kind: "name",
      holders: [{ keyId: "MINE", own: true }],
    });
    expect(clashes.has("MINE")).toBe(false);
  });

  it("does not mark a contact who merely shares the user's name", () => {
    const mine = { keyId: "MINE", userIds: carol.userIds };
    const namesake = { keyId: "BBBB", userIds: ["Carol Lane <c@other.test>"] };
    expect(contactClashes([namesake], [mine]).size).toBe(0);
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

describe("namesLookAlike: a name that only reads as another's", () => {
  const alike = (a: string, b: string) =>
    namesLookAlike(`${a} <a@one.test>`, `${b} <b@two.test>`);

  it.each([
    ["Cherokee \u13AA", "\u13AAlice"],
    ["Lisu \uA4E2", "\uA4E2am"],
    ["Armenian \u054F", "\u054Fam"],
    ["a stroked \u0142", "A\u0142ice"],
    ["a stroked \u0167", "Ma\u0167t"],
    ["a stroked \u0111", "E\u0111"],
    ["a stroked \u0127", "\u0127ana"],
    ["a slashed \u00f8", "R\u00f8b"],
    ["a dotless \u0131", "L\u0131z"],
    ["a dotless \u0237", "\u0237ane"],
    ["a Latin alpha \u0251", "\u0251nna"],
    ["Coptic \u2C9E", "R\u2C9Fb"],
    ["Greek \u03B7 for n", "A\u03B7na"],
    ["a Greek capital iota for an l", "A\u0399ice"],
    ["a capital I for an l", "AIice"],
    ["a fullwidth letter", "\uFF21lice"],
    ["rn for m", "Rnary"],
    ["an invisible character", "Ali\u200Bce"],
  ])("sees %s", (_label, claimed) => {
    const plain: Record<string, string> = {
      "\u13AAlice": "Alice",
      "\uA4E2am": "Sam",
      "\u054Fam": "Sam",
      "A\u0142ice": "Alice",
      "Ma\u0167t": "Matt",
      "E\u0111": "Ed",
      "\u0127ana": "hana",
      "R\u00f8b": "Rob",
      "L\u0131z": "Liz",
      "\u0237ane": "Jane",
      "\u0251nna": "Anna",
      "R\u2C9Fb": "Rob",
      "A\u03B7na": "Anna",
      "A\u0399ice": "Alice",
      AIice: "Alice",
      "\uFF21lice": "Alice",
      Rnary: "Mary",
      "Ali\u200Bce": "Alice",
    };
    expect(alike(claimed, plain[claimed])).toBe(true);
    expect(alike(plain[claimed], claimed)).toBe(true);
  });

  it.each([
    ["the same name", "Alice Lane", "Alice Lane"],
    ["case", "alice lane", "ALICE LANE"],
    ["spacing and punctuation", "Alice  Lane.", '"Alice Lane"'],
    ["accents", "Zo\u00eb", "Zoe"],
  ])("lets two people share a name differing only in %s", (_label, a, b) => {
    expect(alike(a, b)).toBe(false);
  });

  it("keeps different names apart", () => {
    expect(alike("Alice", "Alicia")).toBe(false);
    expect(alike("\u0141ukasz", "Lucas")).toBe(false);
  });

  it("treats a letter from another alphabet that the table does not map as wild", () => {
    // Cherokee \u13AF is not in CONFUSABLE, but it is a Cherokee letter
    // in a Latin word, which the highlighter marks -- and nobody writes
    // their own name that way.
    expect(alike("\u13AFlice", "Alice")).toBe(true);
    expect(alike("Alice", "\u13AFlice")).toBe(true);
    expect(alike("\u13AFlice", "Alicia")).toBe(false);
  });

  it("does not let wildcards match on next to nothing", () => {
    // One real letter, or more wildcards than real letters: too little
    // to say whose name it imitates.
    expect(alike("A\u13AF", "Al")).toBe(false);
    expect(alike("A\u13AF\u13AF\u13AF", "Alex")).toBe(false);
  });

  it("does not treat a whole word in another script as wild", () => {
    // A Cherokee word is written in Cherokee: nothing in it is odd.
    expect(alike("\u13AF\u13B0\u13B1", "Ann")).toBe(false);
  });
});

describe("identityConflict: the name rule", () => {
  it("is not a conflict for the very same name under another address", () => {
    expect(
      identityConflict(
        { keyId: "BBBB", userIds: ["Carol Lane <carol@other.example>"] },
        [carol],
      ),
    ).toBeNull();
  });

  it("is a name conflict for a Cherokee or Lisu lookalike of it", () => {
    for (const name of ["\u13DFarol Lane", "Carol \uA4E1ane"]) {
      expect(
        identityConflict(
          { keyId: "BBBB", userIds: [`${name} <carol@other.example>`] },
          [carol],
        )?.kind,
      ).toBe("name");
    }
  });

  it("still asks when one of several User IDs looks alike", () => {
    expect(
      identityConflict(
        {
          keyId: "BBBB",
          userIds: [
            "Carol Lane <carol@other.example>",
            "C\u0430rol Lane <carol@third.example>",
          ],
        },
        [carol],
      )?.kind,
    ).toBe("name");
  });
});

describe("noteKeyId", () => {
  it("shortens an SSH fingerprint inside a sentence, and nothing else", () => {
    const ssh = "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
    expect(noteKeyId(ssh)).toBe("SHA256:abcdefghijkl\u2026");
    expect(noteKeyId("SHA256:short")).toBe("SHA256:short");
    expect(noteKeyId("3A9E1F5C7B2D48E6A0C1938574FD62B0E4A75C11")).toBe(
      "74FD62B0E4A75C11",
    );
  });
});

describe("the same name, plainly written (the user's policy)", () => {
  const holder = (userIds: string[], keyId = "AAAA") => ({ keyId, userIds });
  const conflict = (mine: string[], theirs: string[]) =>
    identityConflict(holder(mine, "BBBB"), [holder(theirs)]);

  it("does not flag two people sharing a name under different addresses", () => {
    expect(
      conflict(
        ["Carol Lane <carol@corp-mail.com>"],
        ["Carol Lane <carol@corp.com>"],
      ),
    ).toBeNull();
    expect(
      conflict(
        ["Carol Lane (Finance) <x@y.z>"],
        ["Carol Lane <carol@corp.com>"],
      ),
    ).toBeNull();
    // An accent is how a name is written, not a lookalike.
    expect(
      conflict(["Jos\u00e9 Ruiz <j@a.test>"], ["Jose Ruiz <j@b.test>"]),
    ).toBeNull();
    expect(
      conflict(["Jose\u0301 Ruiz <j@a.test>"], ["Jos\u00e9 Ruiz <j@b.test>"]),
    ).toBeNull();
  });

  it("flags the same name when either side has no address to tell them apart", () => {
    expect(
      conflict(["Carol Lane"], ["Carol Lane <carol@corp.com>"]),
    ).toMatchObject({ kind: "name", sameName: true });
    expect(
      conflict(["Carol Lane <carol@corp.com>"], ["Carol Lane"]),
    ).toMatchObject({ kind: "name", sameName: true });
    expect(conflict(["carol lane"], ["Carol Lane"])).toMatchObject({
      kind: "name",
      sameName: true,
    });
    // The accent rule holds here too: still the same name.
    expect(conflict(["Jos\u00e9"], ["Jose <j@b.test>"])).toMatchObject({
      sameName: true,
    });
    expect(conflict(["Carol Lane"], [])).toBeNull();
  });

  it("marks both cards on the contact list", () => {
    const clashes = contactClashes(
      [holder(["Carol Lane <carol@corp.com>"]), holder(["Carol Lane"], "BBBB")],
      [],
    );
    expect(clashes.size).toBe(2);
    expect(clashes.get("BBBB")).toMatchObject({ kind: "name", sameName: true });
  });

  it("reads a canonical singleton as a lookalike, not as the same name", () => {
    // The Kelvin sign and the Ohm sign decompose (NFD) to K and the
    // Greek Omega: equal after NFD, but a different character on screen.
    expect(
      namesLookAlike("\u212aate Bell <k@a.test>", "Kate Bell <k@b.test>"),
    ).toBe(true);
    expect(
      conflict(["\u212aate Bell <k@a.test>"], ["Kate Bell <k@corp.com>"]),
    ).toMatchObject({ kind: "name" });
    expect(
      conflict(["\u212aate Bell <k@a.test>"], ["Kate Bell <k@corp.com>"])
        ?.sameName,
    ).toBeUndefined();
    expect(
      namesLookAlike(
        "\u2126mega Lane <o@a.test>",
        "\u03a9mega Lane <o@b.test>",
      ),
    ).toBe(true);
    // Without an address it is caught either way.
    expect(conflict(["\u212aate Bell"], ["Kate Bell <k@corp.com>"])?.kind).toBe(
      "name",
    );
  });

  it("reads a dotted capital I as an accent on an I", () => {
    // \u0130 is I with a dot above (NFD), not a singleton: the same name as
    // Ivan under another address, and flagged when there is none.
    expect(
      conflict(["\u0130van <i@a.test>"], ["Ivan <i@corp.com>"]),
    ).toBeNull();
    expect(conflict(["\u0130van"], ["Ivan <i@corp.com>"])).toMatchObject({
      kind: "name",
      sameName: true,
    });
  });

  it("reads a combining grapheme joiner as a hidden difference, not an accent", () => {
    expect(
      namesLookAlike("Carol Lane <c@a.com>", "Carol\u034f Lane <c@b.com>"),
    ).toBe(true);
    expect(
      namesLookAlike("Carol Lane <c@a.com>", "Carol Lane\u200b <c@b.com>"),
    ).toBe(true);
    expect(namesLookAlike("Carol Lane <c@a.com>", "carol lane <c@b.com>")).toBe(
      false,
    );
  });
});

describe("aliases are names too", () => {
  const sshAlice = {
    keyId: "SHA256:alice",
    userIds: [],
    alias: "Alice",
  };

  it("checks a comment against a comment-less contact the user named", () => {
    expect(
      identityConflict({ keyId: "SHA256:evil", userIds: ["Alice"] }, [
        sshAlice,
      ]),
    ).toMatchObject({ kind: "name", sameName: true, holders: [sshAlice] });
    expect(
      identityConflict({ keyId: "SHA256:evil", userIds: ["\u0410lice"] }, [
        sshAlice,
      ]),
    ).toMatchObject({ kind: "name", holders: [sshAlice] });
    expect(
      contactClashes(
        [sshAlice, { keyId: "SHA256:evil", userIds: ["\u0410lice"] }],
        [],
      ).size,
    ).toBe(2);
  });

  it("does not let an alias turn a shared name into a clash", () => {
    // Alice's PGP key, named "Alice" by the user: a different Alice with
    // her own address is still two people.
    const alice = {
      keyId: "AAAA",
      userIds: ["Alice <alice@corp.com>"],
      alias: "Alice",
    };
    expect(
      identityConflict(
        { keyId: "BBBB", userIds: ["Alice <alice@home.test>"] },
        [alice],
      ),
    ).toBeNull();
  });
});

describe("confusables from scripts no table listed", () => {
  const dan = { keyId: "AAAA", userIds: ["Dan Cole <dan@corp.com>"] };

  it("flags Dan C\u0966le and dan@corp.c\u0966m", () => {
    expect(namesLookAlike("Dan Cole <a@a>", "Dan C\u0966le <b@b>")).toBe(true);
    for (const c of ["\u0e50", "\u0d20", "\u0c66", "\u0ce6"])
      expect(namesLookAlike("Dan Cole <a@a>", `Dan C${c}le <b@b>`), c).toBe(
        true,
      );
    expect(namesLookAlike("Dan Young <a@a>", "Dan \u10e7oung <b@b>")).toBe(
      true,
    );
    expect(
      identityConflict({ keyId: "BBBB", userIds: ["dan@corp.c\u0966m"] }, [
        dan,
      ]),
    ).toMatchObject({ kind: "address", lookalike: true });
    expect(
      identityConflict({ keyId: "BBBB", userIds: ["dan@corp.c\u0d20m"] }, [
        dan,
      ]),
    ).toMatchObject({ kind: "address", lookalike: true });
  });

  it("wildcards a letter from any other script, in a name or an address", () => {
    // Tifinagh: in no table, but a different script from its word's.
    expect(namesLookAlike("Dan Cole <a@a>", "Dan C\u2d30le <b@b>")).toBe(true);
    expect(
      identityConflict({ keyId: "BBBB", userIds: ["dan@corp.c\u2d30m"] }, [
        dan,
      ]),
    ).toMatchObject({ kind: "address", lookalike: true });
  });
});

describe("addresses: ideographic dots and quoted local parts", () => {
  const carol = { keyId: "AAAA", userIds: ["Carol <carol@corp.com>"] };
  const claim = (u: string) =>
    identityConflict({ keyId: "BBBB", userIds: [`Mallory ${u}`] }, [carol]);

  it("reads an ideographic full stop as a dot", () => {
    for (const dot of ["\u3002", "\uff0e", "\uff61"]) {
      expect(claim(`<carol@corp${dot}com>`)?.kind, dot).toBe("address");
    }
    expect(claim("<carol@corp\u3002com>")?.lookalike).toBe(true);
  });

  it("reads a quoted local part as the address it shows", () => {
    expect(emailsOf('Mallory <"carol"@corp.com>')).toEqual(["carol@corp.com"]);
    expect(claim('<"carol"@corp.com>')).toMatchObject({ kind: "address" });
    expect(claim('<"carol"@corp.com>')?.lookalike).toBeUndefined();
    expect(claim('carol"@corp.com')).toMatchObject({ kind: "address" });
    expect(nameOf('Mallory "carol"@corp.com')).toBe("Mallory");
  });
});

describe("contactClash", () => {
  it("is contactClashes for one key", () => {
    const own = [{ keyId: "MINE", userIds: ["Carol Lane <carol@corp.com>"] }];
    const contacts = [
      { keyId: "AAAA", userIds: ["Car\u043el Lane <c@evil.test>"] },
      { keyId: "BBBB", userIds: ["Dan <dan@corp.com>"] },
      { keyId: "CCCC", userIds: ["Dan <dan@corp.com>"], revoked: true },
    ];
    const all = contactClashes(contacts, own);
    for (const c of contacts)
      expect(contactClash(c.keyId, contacts, own), c.keyId).toEqual(
        all.get(c.keyId),
      );
    expect(contactClash("NOPE", contacts, own)).toBeUndefined();
  });
});

describe("contactClashes: performance", () => {
  it("checks 1000 contacts in well under a second", () => {
    const contacts = Array.from({ length: 1000 }, (_, i) => ({
      keyId: i.toString(16).padStart(40, "0"),
      userIds: [
        `Person Number${i} <p${i}@example${i % 7}.com>`,
        `P ${i} <alt${i}@work.org>`,
      ],
    }));
    // A few that clash, and a wildcard name, so every index is used.
    contacts.push(
      { keyId: "E".repeat(40), userIds: ["Person Number1 <x@evil.test>"] },
      { keyId: "F".repeat(40), userIds: ["Pers\u2d30n Number2 <y@evil.test>"] },
      { keyId: "D".repeat(40), userIds: ["p3@example3.com"] },
    );
    const start = performance.now();
    const clashes = contactClashes(contacts, []);
    const elapsed = performance.now() - start;
    expect(clashes.get("F".repeat(40))?.kind).toBe("name");
    expect(clashes.get("D".repeat(40))?.kind).toBe("address");
    expect(clashes.has("E".repeat(40))).toBe(false);
    expect(elapsed).toBeLessThan(500);
  });
});
