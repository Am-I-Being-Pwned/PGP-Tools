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
import { STORAGE_CONTACTS } from "../constants";
import {
  activeRecipients,
  contactRecipients,
  contactSource,
  disabledField,
  isRecipientDisabled,
  aliasField,
  loadContacts,
  recipientsField,
  removeContact,
  sameSource,
  saveContact,
  setContactRecipientDisabled,
  updateContact,
  updateContactAlias,
  upsertContacts,
  withAlias,
  withRecipientDisabled,
  withRecipients,
} from "./contacts";
import { displayUserId } from "../utils/key-naming";
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

let local: ReturnType<typeof fakeArea>;

beforeEach(() => {
  local = fakeArea();
  vi.stubGlobal("chrome", { storage: { local, sync: fakeArea() } });
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

describe("the head-agreement invariant - repaired, never rejected", () => {
  /** The validator isn't exported; it runs on every LOAD, so a rejected
   *  record simply doesn't come back -- and the next write persists the
   *  filtered array, i.e. the person is gone from disk. Repair is the
   *  remedy precisely because rejection here is permanent deletion. */
  async function reload(c: PublicContactKey): Promise<PublicContactKey> {
    await saveContact(c);
    const [stored] = await loadContacts();
    return stored;
  }

  it("leaves a record whose recipients[0] agrees exactly as it was", async () => {
    const c = multiContact(3);
    expect(JSON.stringify(await reload(c))).toBe(JSON.stringify(c));
  });

  it("re-heads a list whose head names another key, keeping every key", async () => {
    const bad = multiContact(3);
    // key1 is the record's own key, but it is not at the head.
    bad.keyId = sshRecipient(1).keyId;
    bad.armoredPublicKey = sshRecipient(1).armored;

    const stored = await reload(bad);
    expect(stored).toBeDefined();
    const list = contactRecipients(stored);
    expect(list[0].keyId).toBe(stored.keyId);
    expect(list[0].armored).toBe(stored.armoredPublicKey);
    // Nobody was dropped on the way: still three keys, re-ordered.
    expect(list.map((r) => r.keyId).sort()).toEqual([
      "SHA256:key0",
      "SHA256:key1",
      "SHA256:key2",
    ]);
  });

  it("restores the record's own key as head when no entry matches", async () => {
    const bad = multiContact(3);
    bad.recipients = [
      { ...sshRecipient(0), armored: "ssh-ed25519 AAAAother other@host" },
      sshRecipient(1),
    ];

    const stored = await reload(bad);
    const list = contactRecipients(stored);
    expect(list[0]).toEqual({
      keyId: bad.keyId,
      armored: bad.armoredPublicKey,
      algorithm: bad.algorithm,
    });
    // The entry claiming this fingerprint with DIFFERENT bytes is the one
    // thing dropped -- one of the two has to be wrong, and the top-level
    // copy is the one every older build already encrypts to.
    expect(list.map((r) => r.keyId)).toEqual(["SHA256:key0", "SHA256:key1"]);
  });

  it("keeps the person when the list is empty or full of junk", async () => {
    const empty = await reload({ ...multiContact(3), recipients: [] });
    expect(empty.keyId).toBe(multiContact(3).keyId);
    expect(contactRecipients(empty)).toHaveLength(1);
    // Back to the single-key shape, byte-for-byte: no stale field left.
    expect("recipients" in empty).toBe(false);

    const malformed = multiContact(3);
    (malformed as { recipients: unknown }).recipients = [
      { keyId: malformed.keyId },
      sshRecipient(1),
    ];
    const stored = await reload(malformed);
    expect(stored.keyId).toBe(malformed.keyId);
    expect(contactRecipients(stored).map((r) => r.keyId)).toEqual([
      "SHA256:key0",
      "SHA256:key1",
    ]);
  });

  it("does not delete the person on the write that follows the bad read", async () => {
    // The failure this replaces: the bad record is filtered out on load,
    // and the very next save persists the list without it.
    const bad = multiContact(3);
    bad.recipients = [
      { ...sshRecipient(0), keyId: "SHA256:someone-else" },
      sshRecipient(1),
    ];
    await saveContact(bad);
    await saveContact(legacyContact());

    const all = await loadContacts();
    expect(all.map((c) => c.keyId).sort()).toEqual(["CCCC", "SHA256:key0"]);
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

/**
 * The guard, and the reason it has to exist.
 *
 * `loadEncryptedArray` returns `[]` with no contacts session, which is
 * indistinguishable from an empty store -- so an unguarded delete
 * computes "nothing left", takes the empty-store shortcut and removes
 * the sealed blob. Every contact the user has, destroyed, without the
 * vault ever being opened; and reachable on the ordinary auto-lock path,
 * because the master lock drops the contacts session without awaiting it
 * while a mutation is already queued behind the UI's mutex.
 *
 * These assert on STORAGE, not on a return value: a delete that reports
 * success having wiped the blob is the exact failure being prevented.
 */
describe("mutating a locked contacts store", () => {
  async function seed(): Promise<unknown> {
    await saveContact(legacyContact());
    await saveContact(multiContact(3));
    return local.store.get(STORAGE_CONTACTS);
  }

  it("does NOT delete the blob when the last contact is removed while locked", async () => {
    await saveContact(legacyContact());
    const sealed = local.store.get(STORAGE_CONTACTS);

    wasmMock.session = false;
    await expect(removeContact("CCCC")).rejects.toThrow(/vault is locked/);
    expect(local.store.has(STORAGE_CONTACTS)).toBe(true);
    expect(local.store.get(STORAGE_CONTACTS)).toBe(sealed);

    wasmMock.session = true;
    expect((await loadContacts()).map((c) => c.keyId)).toEqual(["CCCC"]);
  });

  it("does not overwrite the blob on any locked mutation", async () => {
    const sealed = await seed();

    wasmMock.session = false;
    await expect(saveContact(legacyContact({ keyId: "DDDD" }))).rejects.toThrow(
      /vault is locked/,
    );
    await expect(removeContact("SHA256:key0")).rejects.toThrow(
      /vault is locked/,
    );
    await expect(
      setContactRecipientDisabled("SHA256:key0", "SHA256:key1", true),
    ).rejects.toThrow(/vault is locked/);
    await expect(
      updateContact("CCCC", (c) => ({ ...c, userIds: ["gone"] })),
    ).rejects.toThrow(/vault is locked/);
    expect(local.store.get(STORAGE_CONTACTS)).toBe(sealed);

    wasmMock.session = true;
    expect(await loadContacts()).toHaveLength(2);
  });

  it("still removes the blob when the store genuinely empties", async () => {
    await saveContact(legacyContact());
    await removeContact("CCCC");
    expect(local.store.has(STORAGE_CONTACTS)).toBe(false);
  });
});

/**
 * `disabled` is the one field on a contact that carries a SECURITY
 * decision, and a refresh is the one path that would discard it: a
 * re-fetch builds its record purely from what GitHub just returned, and
 * the upsert replaces wholesale on a source match. Carried forward in
 * the STORE rather than at each call site, so no fetch path can forget.
 */
describe("saveContact - a refresh keeps the user's decisions", () => {
  /** The same person, re-fetched: fresh timestamps, no `disabled`. */
  function refetched(keys: number[], user = "octocat"): PublicContactKey {
    const list = keys.map(sshRecipient);
    return {
      ...multiContact(3, user),
      keyId: list[0].keyId,
      armoredPublicKey: list[0].armored,
      addedAt: 5000,
      lastUsedAt: 5000,
      source: { type: "github", user, fetchedAt: 5000 },
      ...recipientsField(list),
    };
  }

  it("keeps a disabled key disabled across a re-fetch", async () => {
    await saveContact(multiContact(3));
    await setContactRecipientDisabled("SHA256:key0", "SHA256:key1", true);

    await saveContact(refetched([0, 1, 2]));

    const [stored] = await loadContacts();
    expect(contactRecipients(stored).map(isRecipientDisabled)).toEqual([
      false,
      true,
      false,
    ]);
    expect(activeRecipients(stored).map((r) => r.keyId)).toEqual([
      "SHA256:key0",
      "SHA256:key2",
    ]);
  });

  it("carries the flag by keyId, not by position", async () => {
    await saveContact(multiContact(3));
    await setContactRecipientDisabled("SHA256:key0", "SHA256:key2", true);

    // key0 is gone upstream, so every key shifts one place along.
    await saveContact(refetched([1, 2]));

    const [stored] = await loadContacts();
    const list = contactRecipients(stored);
    expect(list.map((r) => r.keyId)).toEqual(["SHA256:key1", "SHA256:key2"]);
    expect(list.map(isRecipientDisabled)).toEqual([false, true]);
  });

  it("leaves a newly published key enabled", async () => {
    await saveContact(multiContact(3));
    await setContactRecipientDisabled("SHA256:key0", "SHA256:key1", true);

    await saveContact(refetched([0, 1, 2, 3]));

    const [stored] = await loadContacts();
    expect(
      contactRecipients(stored)
        .filter(isRecipientDisabled)
        .map((r) => r.keyId),
    ).toEqual(["SHA256:key1"]);
  });

  it("does not carry a decision across to a different person", async () => {
    // Two GitHub accounts publishing the same key collide by keyId
    // alone. Neither the disable decision nor "known since" belongs to
    // the other account.
    await saveContact(multiContact(3, "octocat"));
    await setContactRecipientDisabled("SHA256:key0", "SHA256:key1", true);

    await saveContact(refetched([0, 1, 2], "hubot"));

    const [stored] = await loadContacts();
    expect(contactSource(stored)?.user).toBe("hubot");
    expect(contactRecipients(stored).some(isRecipientDisabled)).toBe(false);
    expect(stored.addedAt).toBe(5000);
  });

  it("keeps `addedAt` from the record it replaces", async () => {
    await saveContact(multiContact(3)); // addedAt: 1
    await saveContact(refetched([0, 1, 2])); // addedAt: 5000
    const [stored] = await loadContacts();
    expect(stored.addedAt).toBe(1);
    expect(contactSource(stored)?.fetchedAt).toBe(5000);
  });

  it("writes nothing extra when nothing was disabled", async () => {
    await saveContact(legacyContact());
    await saveContact(legacyContact({ lastUsedAt: 9 }));
    const [stored] = await loadContacts();
    expect(JSON.stringify(stored)).toBe(
      JSON.stringify(legacyContact({ lastUsedAt: 9 })),
    );
  });
});

/**
 * A hand-pasted key is not a reason to lose a person.
 *
 * Upsert by keyId means a pasted key whose fingerprint equals a fetched
 * contact's HEAD would replace that whole record with a one-key,
 * source-less contact -- the person's other keys silently dropped.
 */
describe("upsertContacts - a pasted key never replaces a fetched person", () => {
  it("leaves the fetched record intact", async () => {
    await saveContact(multiContact(3));
    await saveContact(
      legacyContact({
        keyId: "SHA256:key0",
        armoredPublicKey: sshRecipient(0).armored,
        userIds: ["pasted"],
      }),
    );

    const all = await loadContacts();
    expect(all).toHaveLength(1);
    expect(contactRecipients(all[0])).toHaveLength(3);
    expect(contactSource(all[0])?.user).toBe("octocat");
  });

  it("still lets a fetch replace a source-less record with the same key", async () => {
    await saveContact(
      legacyContact({
        keyId: "SHA256:key0",
        armoredPublicKey: sshRecipient(0).armored,
      }),
    );
    await saveContact(multiContact(3));
    const all = await loadContacts();
    expect(all).toHaveLength(1);
    expect(contactRecipients(all[0])).toHaveLength(3);
  });

  it("is the same function the UI's optimistic list uses", () => {
    // Pure, so the hook can reach exactly the answer storage will.
    const existing = [multiContact(3)];
    const pasted = legacyContact({ keyId: "SHA256:key0" });
    expect(upsertContacts(existing, pasted)).toEqual(existing);
    expect(upsertContacts([], pasted)).toEqual([pasted]);
  });
});

/**
 * Every write goes through the store's lock, and every write that
 * touches ONE field re-reads the record rather than republishing a
 * snapshot. The recipient toggle reaches the store from a component the
 * contacts hook's mutex does not cover, so serialisation has to live
 * here.
 */
describe("serialised writes", () => {
  it("does not lose either of two concurrent saves", async () => {
    await saveContact(legacyContact());
    await Promise.all([
      saveContact(legacyContact({ keyId: "DDDD", userIds: ["Dave"] })),
      saveContact(legacyContact({ keyId: "EEEE", userIds: ["Erin"] })),
    ]);
    expect((await loadContacts()).map((c) => c.keyId).sort()).toEqual([
      "CCCC",
      "DDDD",
      "EEEE",
    ]);
  });

  it("toggles a key without republishing a stale snapshot", async () => {
    await saveContact(multiContact(3));
    const snapshot = (await loadContacts())[0];

    // Something else edits the record after the details page captured it
    // -- the expiry backfill does exactly this, one contact at a time.
    await updateContact(snapshot.keyId, (c) => ({ ...c, expiresAt: null }));

    await setContactRecipientDisabled(snapshot.keyId, "SHA256:key1", true);

    const [stored] = await loadContacts();
    expect(stored.expiresAt).toBeNull();
    expect(contactRecipients(stored).map(isRecipientDisabled)).toEqual([
      false,
      true,
      false,
    ]);
  });

  it("interleaves a toggle and a full-record save without losing one", async () => {
    await saveContact(multiContact(3));
    await Promise.all([
      setContactRecipientDisabled("SHA256:key0", "SHA256:key1", true),
      updateContact("SHA256:key0", (c) => ({ ...c, lastUsedAt: 4242 })),
    ]);
    const [stored] = await loadContacts();
    expect(stored.lastUsedAt).toBe(4242);
    expect(contactRecipients(stored)[1].disabled).toBe(true);
  });

  it("no-ops when the contact is gone", async () => {
    await saveContact(legacyContact());
    await expect(
      setContactRecipientDisabled("MISSING", "MISSING", true),
    ).resolves.toBeUndefined();
    expect(await loadContacts()).toHaveLength(1);
  });
});

/**
 * `recipientsField` returns `{}` at length 1, so spreading it over an
 * existing record cannot clear a list that SHRINKS back to one key --
 * the stale array would survive and disagree with the top-level fields.
 * Nothing shrinks a list today, which is why the contract has to be
 * enforced rather than remembered.
 */
describe("withRecipients - a shrinking list clears the field", () => {
  it("drops the array when the list falls back to one key", () => {
    const c = multiContact(3);
    const one = withRecipients(c, [sshRecipient(0)]);
    expect("recipients" in one).toBe(false);
    // Byte-identical to a record that never had the field.
    expect(JSON.parse(JSON.stringify(one))).toEqual(
      JSON.parse(
        JSON.stringify({
          ...multiContact(1),
          source: c.source,
        }),
      ),
    );
  });

  it("keeps the field, in place, when the list is still plural", () => {
    const c = multiContact(3);
    const two = withRecipients(c, [sshRecipient(0), sshRecipient(1)]);
    expect(two.recipients).toHaveLength(2);
    expect(JSON.stringify(Object.keys(two))).toBe(JSON.stringify(Object.keys(c)));
  });
});

/**
 * A contact's local display name.
 *
 * The same field, with the same rules, `ProtectedKeyBlob.alias` has for
 * the user's own keys -- and for the same reason: a contact is otherwise
 * stuck with whatever `userIds[0]` it was imported with, which for an
 * SSH key is a key comment that may be `user@laptop`, may differ between
 * one person's keys, or may not exist at all.
 *
 * What is pinned here is the convention every optional field on this
 * record follows: ABSENT means "fall back", `""` is never written, and a
 * contact without one serialises byte-for-byte the way it did before the
 * field existed.
 */
describe("alias - absent means the derived name", () => {
  it("falls back to the first User ID when there is no alias", () => {
    expect(displayUserId(legacyContact())).toBe("Carol <c@d.test>");
    expect("alias" in legacyContact()).toBe(false);
  });

  it("wins over the User IDs when set", () => {
    const named = withAlias(legacyContact(), "Carol's laptop");
    expect(displayUserId(named)).toBe("Carol's laptop");
    // The identity itself is untouched: an alias is a local label, never
    // a change to the key.
    expect(named.userIds).toEqual(["Carol <c@d.test>"]);
  });

  it("trims, and omits the field entirely when nothing is left", () => {
    expect(aliasField("  Carol  ")).toEqual({ alias: "Carol" });
    expect(aliasField("")).toEqual({});
    expect("alias" in aliasField("   ")).toBe(false);
  });

  it("REMOVES the field on clear rather than writing an empty string", () => {
    const named = withAlias(legacyContact(), "Carol's laptop");
    const cleared = withAlias(named, "  ");
    expect("alias" in cleared).toBe(false);
    expect(displayUserId(cleared)).toBe("Carol <c@d.test>");
  });

  it("serialises a contact with no alias byte-identically to a pre-field one", () => {
    const before = legacyContact();
    // The same record, put through the write helper. If `aliasField`
    // ever emitted `alias: ""` (or `alias: undefined`), this JSON would
    // differ and every existing user's contacts blob would be rewritten
    // on first touch.
    const after = withAlias(before, "");
    expect(JSON.stringify(after)).toBe(JSON.stringify(before));
  });

  it("round-trips through storage, and clears back to the stored shape", async () => {
    await saveContact(legacyContact());
    await updateContactAlias("CCCC", "  Carol's laptop  ");
    const [named] = await loadContacts();
    expect(named.alias).toBe("Carol's laptop");
    expect(displayUserId(named)).toBe("Carol's laptop");

    await updateContactAlias("CCCC", "");
    const [cleared] = await loadContacts();
    expect("alias" in cleared).toBe(false);
    expect(JSON.stringify(cleared)).toBe(JSON.stringify(legacyContact()));
  });

  it("touches nothing else on the record", async () => {
    await saveContact(multiContact(3));
    const before = (await loadContacts())[0];
    await updateContactAlias(before.keyId, "Octocat");
    const after = (await loadContacts())[0];
    expect(contactRecipients(after)).toHaveLength(3);
    expect(contactSource(after)?.user).toBe("octocat");
    expect(JSON.stringify(withAlias(after, ""))).toBe(JSON.stringify(before));
  });
});
