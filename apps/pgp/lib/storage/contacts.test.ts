/**
 * The multi-recipient contact model.
 *
 * A contact is a PERSON, and a person commonly has several keys (three
 * SSH keys on a GitHub account is unremarkable). Encrypting to that
 * contact must reach all of them, because we cannot know which machine
 * they are reading from.
 *
 * What is pinned here is the migration property the whole design rests
 * on -- `recipients` absent MEANS "the single key in the top-level
 * fields", enforced on BOTH sides:
 *
 *  - read: `contactRecipients` synthesises the one-element list, so no
 *    call site sees the difference;
 *  - write: `recipientsField` emits nothing at length 1, so today's
 *    contacts serialise byte-for-byte as they already do and an older
 *    build still reads every record.
 *
 * Plus the head-agreement invariant that makes a downgrade merely
 * degraded rather than wrong, and the source-based upsert identity that
 * stops a re-fetch from filing a second contact for the same person.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { ContactRecipient, PublicContactKey } from "./contacts";
import {
  activeRecipients,
  contactRecipients,
  contactSource,
  disabledField,
  isRecipientDisabled,
  loadContacts,
  recipientsField,
  removeContact,
  sameSource,
  saveContact,
  withRecipientDisabled,
} from "./contacts";
import { invalidateLocationCache } from "./engine";
import {
  fakeDecryptContacts,
  fakeDecryptStore,
  fakeEncryptContacts,
  fakeEncryptStore,
} from "./fake-store-crypto";

const wasmMock = vi.hoisted(() => ({ session: true }));

vi.mock("../pgp/wasm", () => ({
  hasContactsSession: () => Promise.resolve(wasmMock.session),
  encryptStore: (domain: string, plaintext: Uint8Array) =>
    Promise.resolve(fakeEncryptStore(domain, plaintext)),
  decryptStore: (domain: string, ciphertext: Uint8Array) =>
    Promise.resolve(fakeDecryptStore(domain, ciphertext)),
  encryptContacts: (plaintext: Uint8Array) =>
    Promise.resolve(fakeEncryptContacts(plaintext)),
  decryptContacts: (ciphertext: Uint8Array) =>
    Promise.resolve(fakeDecryptContacts(ciphertext)),
}));

function fakeArea() {
  const store = new Map<string, unknown>();
  return {
    store,
    get: (keys?: string | string[] | null) => {
      if (keys == null) return Promise.resolve(Object.fromEntries(store));
      const list = Array.isArray(keys) ? keys : [keys];
      const out: Record<string, unknown> = {};
      for (const k of list) if (store.has(k)) out[k] = store.get(k);
      return Promise.resolve(out);
    },
    set: (items: Record<string, unknown>) => {
      for (const [k, v] of Object.entries(items)) store.set(k, v);
      return Promise.resolve();
    },
    remove: (keys: string | string[]) => {
      const list = Array.isArray(keys) ? keys : [keys];
      for (const k of list) store.delete(k);
      return Promise.resolve();
    },
  };
}

beforeEach(() => {
  vi.stubGlobal("chrome", { storage: { local: fakeArea(), sync: fakeArea() } });
  wasmMock.session = true;
  invalidateLocationCache();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** A record exactly as one is written TODAY: no `kind`, no `recipients`,
 *  no `source`. Every contact on a user's disk looks like this. */
function legacyContact(over: Partial<PublicContactKey> = {}): PublicContactKey {
  return {
    keyId: "CCCC",
    userIds: ["Carol <c@d.test>"],
    algorithm: "ed25519",
    armoredPublicKey: "-----BEGIN PGP PUBLIC KEY BLOCK----- carol",
    addedAt: 1,
    lastUsedAt: 1,
    ...over,
  };
}

function sshRecipient(n: number): ContactRecipient {
  return {
    keyId: `SHA256:key${n}`,
    armored: `ssh-ed25519 AAAAkey${n} dev@host${n}`,
    algorithm: "ssh-ed25519",
  };
}

/** A GitHub-sourced contact holding `count` keys, assembled the way the
 *  importer has to assemble one: the head key duplicated into the
 *  top-level fields, `recipients` written only through the field
 *  helper. */
function multiContact(count: number, user = "octocat"): PublicContactKey {
  const list = Array.from({ length: count }, (_, i) => sshRecipient(i));
  const head = list[0];
  return {
    kind: "ssh",
    keyId: head.keyId,
    userIds: [user],
    algorithm: head.algorithm,
    armoredPublicKey: head.armored,
    addedAt: 1,
    lastUsedAt: 1,
    source: { type: "github", user, fetchedAt: 100 },
    ...recipientsField(list),
  };
}

describe("contactRecipients - absent means the single top-level key", () => {
  it("returns exactly one entry for a legacy record", () => {
    const c = legacyContact();
    expect(contactRecipients(c)).toEqual([
      {
        keyId: "CCCC",
        armored: "-----BEGIN PGP PUBLIC KEY BLOCK----- carol",
        algorithm: "ed25519",
      },
    ]);
  });

  it("returns all three for a 3-recipient record, head first", () => {
    const c = multiContact(3);
    const list = contactRecipients(c);
    expect(list).toHaveLength(3);
    expect(list[0].keyId).toBe(c.keyId);
    expect(list[0].armored).toBe(c.armoredPublicKey);
    expect(list.map((r) => r.keyId)).toEqual([
      "SHA256:key0",
      "SHA256:key1",
      "SHA256:key2",
    ]);
  });

  it("reads source as null when absent", () => {
    expect(contactSource(legacyContact())).toBeNull();
    expect(contactSource(multiContact(2))).toEqual({
      type: "github",
      user: "octocat",
      fetchedAt: 100,
    });
  });
});

describe("the write rule - recipients only above length 1", () => {
  it("omits the field entirely for a single key", () => {
    expect(recipientsField([sshRecipient(0)])).toEqual({});
    expect("recipients" in recipientsField([sshRecipient(0)])).toBe(false);
    expect(recipientsField([])).toEqual({});
  });

  it("writes the field from two keys up", () => {
    const two = [sshRecipient(0), sshRecipient(1)];
    expect(recipientsField(two).recipients).toEqual(two);
    expect(multiContact(2).recipients).toHaveLength(2);
  });

  it("serialises a one-key contact byte-identically to a pre-field one", () => {
    const before = legacyContact();
    // The same record, assembled the new way. If `recipientsField` ever
    // emitted `recipients: [...]` (or `recipients: undefined`) at length
    // 1, this JSON would differ and every existing user's contacts blob
    // would be rewritten on first touch.
    const after: PublicContactKey = {
      ...legacyContact(),
      ...recipientsField(contactRecipients(before)),
    };
    expect(JSON.stringify(after)).toBe(JSON.stringify(before));
  });

  it("round-trips a one-key contact through storage without the field", async () => {
    await saveContact(legacyContact());
    const [stored] = await loadContacts();
    expect("recipients" in stored).toBe(false);
    expect("source" in stored).toBe(false);
    expect(JSON.stringify(stored)).toBe(JSON.stringify(legacyContact()));
  });

  it("round-trips a multi-key contact with all its keys", async () => {
    await saveContact(multiContact(3));
    const [stored] = await loadContacts();
    expect(contactRecipients(stored)).toHaveLength(3);
    expect(contactSource(stored)?.user).toBe("octocat");
  });
});

describe("isValidContact - the head-agreement invariant", () => {
  /** The validator isn't exported; it runs on every LOAD, so a rejected
   *  record simply doesn't come back. */
  async function survivesLoad(c: PublicContactKey): Promise<boolean> {
    await saveContact(c);
    return (await loadContacts()).some((x) => x.keyId === c.keyId);
  }

  it("accepts a record whose recipients[0] agrees", async () => {
    expect(await survivesLoad(multiContact(3))).toBe(true);
  });

  it("rejects a recipients[0] whose keyId disagrees", async () => {
    const bad = multiContact(3);
    bad.recipients = [
      { ...sshRecipient(0), keyId: "SHA256:someone-else" },
      sshRecipient(1),
    ];
    expect(await survivesLoad(bad)).toBe(false);
  });

  it("rejects a recipients[0] whose armored line disagrees", async () => {
    const bad = multiContact(3);
    bad.recipients = [
      { ...sshRecipient(0), armored: "ssh-ed25519 AAAAother other@host" },
      sshRecipient(1),
    ];
    expect(await survivesLoad(bad)).toBe(false);
  });

  it("rejects an empty or malformed recipients list", async () => {
    expect(await survivesLoad({ ...multiContact(3), recipients: [] })).toBe(
      false,
    );
    const malformed = multiContact(3);
    (malformed as { recipients: unknown }).recipients = [
      { keyId: multiContact(3).keyId },
    ];
    expect(await survivesLoad(malformed)).toBe(false);
  });
});

describe("sameSource - identity, and the absence of one", () => {
  it("matches two fetches of the same GitHub user", () => {
    expect(
      sameSource(multiContact(2, "octocat"), {
        source: { type: "github", user: "octocat", fetchedAt: 999 },
      }),
    ).toBe(true);
  });

  it("does not match a different user", () => {
    expect(
      sameSource(multiContact(2, "octocat"), multiContact(2, "hubot")),
    ).toBe(false);
  });

  it("never matches when either side is source-less", () => {
    expect(sameSource(legacyContact(), legacyContact())).toBe(false);
    expect(sameSource(legacyContact(), multiContact(2))).toBe(false);
    expect(sameSource(multiContact(2), legacyContact())).toBe(false);
  });
});

describe("saveContact - upsert identity", () => {
  it("replaces by matching source even when the head key changed", async () => {
    await saveContact(multiContact(3));

    // The upstream user deleted their first key: recipients[0] moves on,
    // and with it the record id. A keyId-only upsert would leave the old
    // record behind and produce two contacts for one person.
    const refetched: PublicContactKey = {
      ...multiContact(3),
      keyId: sshRecipient(1).keyId,
      armoredPublicKey: sshRecipient(1).armored,
      ...recipientsField([sshRecipient(1), sshRecipient(2)]),
      source: { type: "github", user: "octocat", fetchedAt: 200 },
    };
    await saveContact(refetched);

    const all = await loadContacts();
    expect(all).toHaveLength(1);
    expect(all[0].keyId).toBe("SHA256:key1");
    expect(contactRecipients(all[0])).toHaveLength(2);
  });

  it("still replaces by keyId when there is no source", async () => {
    await saveContact(legacyContact());
    await saveContact(legacyContact({ algorithm: "rsa4096" }));
    const all = await loadContacts();
    expect(all).toHaveLength(1);
    expect(all[0].algorithm).toBe("rsa4096");
  });

  it("does NOT merge two source-less contacts with different keyIds", async () => {
    await saveContact(legacyContact());
    await saveContact(legacyContact({ keyId: "DDDD", userIds: ["Dave"] }));
    const all = await loadContacts();
    expect(all.map((c) => c.keyId).sort()).toEqual(["CCCC", "DDDD"]);
  });

  it("keeps two different GitHub users apart", async () => {
    await saveContact(multiContact(2, "octocat"));
    await saveContact({
      ...multiContact(2, "hubot"),
      keyId: "SHA256:hubot0",
      armoredPublicKey: "ssh-ed25519 AAAAhubot0 hubot@host",
      ...recipientsField([
        {
          keyId: "SHA256:hubot0",
          armored: "ssh-ed25519 AAAAhubot0 hubot@host",
          algorithm: "ssh-ed25519",
        },
        sshRecipient(1),
      ]),
    });
    expect(await loadContacts()).toHaveLength(2);
  });

  it("removes a multi-key contact by its record id", async () => {
    await saveContact(multiContact(3));
    await removeContact("SHA256:key0");
    expect(await loadContacts()).toEqual([]);
  });
});

/**
 * Turning one of a contact's keys off.
 *
 * `disabled` follows the same absent-means-default convention as `kind`
 * and `recipients`, and for the same reason: a contact with nothing
 * turned off must serialise byte-for-byte the way it did before the
 * field existed, so no user's blob is rewritten and an older build still
 * reads every record (it ignores the flag and encrypts to all the keys
 * -- degraded, never encrypting to nobody).
 *
 * The invariant this file guards is that `activeRecipients` NEVER
 * returns an empty list. The UI half (refusing to disable the last
 * enabled key) lives in `KeyDetailsPage`; this is the other end.
 */
describe("disabled recipients - absent means enabled", () => {
  /** `multiContact`, with the keys at `off` turned off. */
  function withDisabled(count: number, off: number[]): PublicContactKey {
    const list = Array.from({ length: count }, (_, i) => ({
      ...sshRecipient(i),
      ...disabledField(off.includes(i)),
    }));
    return { ...multiContact(count), ...recipientsField(list) };
  }

  it("reads a missing flag as enabled", () => {
    expect(isRecipientDisabled(sshRecipient(0))).toBe(false);
    expect(isRecipientDisabled({ ...sshRecipient(0), disabled: true })).toBe(
      true,
    );
    // Strict `=== true`: anything else on the record means enabled, so a
    // stray value can never silently stop encrypting to a key.
    expect(
      isRecipientDisabled({
        ...sshRecipient(0),
        disabled: false,
      } as unknown as ContactRecipient),
    ).toBe(false);
  });

  it("excludes the disabled keys from activeRecipients", () => {
    const c = withDisabled(3, [1]);
    expect(activeRecipients(c).map((r) => r.keyId)).toEqual([
      "SHA256:key0",
      "SHA256:key2",
    ]);
  });

  it("keeps ALL of them in contactRecipients", () => {
    // The display list. A key the user cannot see is a key they can
    // never turn back on.
    const c = withDisabled(3, [1]);
    expect(contactRecipients(c)).toHaveLength(3);
    expect(contactRecipients(c).map((r) => r.keyId)).toEqual([
      "SHA256:key0",
      "SHA256:key1",
      "SHA256:key2",
    ]);
  });

  it("returns every key when none is disabled", () => {
    expect(activeRecipients(multiContact(3))).toHaveLength(3);
    expect(activeRecipients(legacyContact())).toHaveLength(1);
  });

  it("falls back to the full list when a record has EVERY key off", () => {
    // Not reachable through the UI; a hand-edited blob could produce it.
    // Empty here would mean encrypting to nobody, silently.
    const c = withDisabled(3, [0, 1, 2]);
    expect(activeRecipients(c).map((r) => r.keyId)).toEqual([
      "SHA256:key0",
      "SHA256:key1",
      "SHA256:key2",
    ]);
    expect(activeRecipients(c)).not.toHaveLength(0);
  });

  it("never writes `disabled: false`", () => {
    expect(disabledField(false)).toEqual({});
    expect("disabled" in disabledField(false)).toBe(false);
    expect(disabledField(true)).toEqual({ disabled: true });
  });

  it("removes the flag on re-enable rather than writing false", () => {
    const off = withRecipientDisabled(
      [sshRecipient(0), sshRecipient(1)],
      "SHA256:key1",
      true,
    );
    expect(off[1].disabled).toBe(true);
    const back = withRecipientDisabled(off, "SHA256:key1", false);
    expect("disabled" in back[1]).toBe(false);
    // Byte-identical to the list before it was ever touched: that is
    // what keeps a round trip through the toggle from rewriting the
    // record's shape.
    expect(JSON.stringify(back)).toBe(
      JSON.stringify([sshRecipient(0), sshRecipient(1)]),
    );
  });

  it("preserves order, so recipients[0] keeps agreeing with keyId", () => {
    const c = withDisabled(3, [0]);
    expect(c.recipients?.[0].keyId).toBe(c.keyId);
    expect(c.recipients?.[0].armored).toBe(c.armoredPublicKey);
  });

  it("serialises a contact with nothing disabled byte-identically", () => {
    // The whole migration rule in one assertion: writing every recipient
    // through `disabledField` must produce exactly the JSON a build that
    // predates the field wrote.
    const before = multiContact(3);
    const after: PublicContactKey = {
      ...multiContact(3),
      ...recipientsField(
        contactRecipients(before).map((r) => ({
          ...r,
          ...disabledField(false),
        })),
      ),
    };
    expect(JSON.stringify(after)).toBe(JSON.stringify(before));
    // And the single-key case, which must not grow a `recipients` field
    // either.
    const legacyAfter: PublicContactKey = {
      ...legacyContact(),
      ...recipientsField(
        contactRecipients(legacyContact()).map((r) => ({
          ...r,
          ...disabledField(false),
        })),
      ),
    };
    expect(JSON.stringify(legacyAfter)).toBe(JSON.stringify(legacyContact()));
  });

  it("round-trips a disabled key through storage", async () => {
    await saveContact(withDisabled(3, [1]));
    const [stored] = await loadContacts();
    expect(contactRecipients(stored)).toHaveLength(3);
    expect(activeRecipients(stored).map((r) => r.keyId)).toEqual([
      "SHA256:key0",
      "SHA256:key2",
    ]);
  });

  it("does not reject a record carrying a stray `disabled: false`", async () => {
    // This build never writes it, but dropping the whole PERSON over a
    // field we read leniently anyway would be the worse failure.
    const c = multiContact(3);
    (c.recipients as unknown as Record<string, unknown>[])[1].disabled = false;
    await saveContact(c);
    const [stored] = await loadContacts();
    expect(stored).toBeDefined();
    expect(activeRecipients(stored)).toHaveLength(3);
  });
});
