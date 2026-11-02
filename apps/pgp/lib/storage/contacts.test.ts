/**
 * The multi-recipient contact model. Pins the migration rule: absent
 * `recipients` MEANS the single top-level key, on read
 * (`contactRecipients`) and write (`recipientsField` emits nothing at
 * length 1); plus head agreement and source-based upsert identity.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { STORAGE_CONTACTS } from "~/lib/constants";
import { displayUserId } from "~/lib/utils/key-naming";
import {
  activeRecipients,
  aliasField,
  contactRecipients,
  contactSource,
  disabledField,
  hasActiveRecipient,
  isRecipientDisabled,
  loadContacts,
  recipientsField,
  removeContact,
  sameSource,
  saveContact,
  setContactRecipientDisabled,
  setContactVerified,
  updateContact,
  updateContactAlias,
  upsertContacts,
  withAlias,
  withRecipientDisabled,
  withRecipients,
  type ContactRecipient,
  type PublicContactKey,
} from "./contacts";
import { stubChromeStorage, type FakeArea } from "./fake-area";
import { createLiveList } from "./live-list";

const wasmMock = vi.hoisted(() => ({ session: true }));

vi.mock("../pgp/wasm", async () =>
  (await import("./fake-store-crypto")).fakeStoreWasm(() => wasmMock.session),
);

let local: FakeArea;

beforeEach(() => {
  ({ local } = stubChromeStorage());
  wasmMock.session = true;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** A record as written today: no `kind`, `recipients` or `source`. */
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

/** A GitHub-sourced contact with `count` keys, built as the importer does. */
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

  it("writes it for ONE key the user turned off, to carry the flag", () => {
    const off = { ...sshRecipient(0), disabled: true as const };
    expect(recipientsField([off]).recipients).toEqual([off]);
  });

  it("writes the field from two keys up", () => {
    const two = [sshRecipient(0), sshRecipient(1)];
    expect(recipientsField(two).recipients).toEqual(two);
    expect(multiContact(2).recipients).toHaveLength(2);
  });

  it("serialises a one-key contact byte-identically to a pre-field one", () => {
    const before = legacyContact();
    // Any `recipients` emitted at length 1 would rewrite every user's blob.
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
  /** Round-trip through LOAD, where a rejected record is permanently
   *  deleted on the next write -- hence repair, not reject. */
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
    // Only the entry claiming this fingerprint with DIFFERENT bytes is dropped;
    // the top-level copy wins.
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

    // First key deleted upstream: the record id moves; must not duplicate.
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
 * `disabled`: absent means enabled, never written as `false`.
 * `activeRecipients` is EMPTY when every key is off; refusing that is the
 * encrypt path's job (`buildEncryptRecipients`).
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
    // The display list keeps disabled keys, or they could never be re-enabled.
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

  it("is empty when a record has EVERY key off", () => {
    // Never falls back to the full list; empty is refused at encrypt time.
    const c = withDisabled(3, [0, 1, 2]);
    expect(activeRecipients(c)).toEqual([]);
    expect(hasActiveRecipient(c)).toBe(false);
    expect(hasActiveRecipient(withDisabled(3, [0, 1]))).toBe(true);
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
    // Writing through `disabledField` must produce the pre-field JSON exactly.
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
    // Never written by this build, but must not drop the whole PERSON.
    const c = multiContact(3);
    (c.recipients as unknown as Record<string, unknown>[])[1].disabled = false;
    await saveContact(c);
    const [stored] = await loadContacts();
    expect(stored).toBeDefined();
    expect(activeRecipients(stored)).toHaveLength(3);
  });
});

/**
 * With no session `loadEncryptedArray` returns `[]`; an unguarded delete
 * would wipe the sealed blob. Asserts on STORAGE, not return values.
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

  it("keeps a sealed empty store when it genuinely empties", async () => {
    // Never removed: a missing store looks like a deletion attack.
    await saveContact(legacyContact());
    await removeContact("CCCC");
    expect(local.store.has(STORAGE_CONTACTS)).toBe(true);
    expect(await loadContacts()).toEqual([]);
  });
});

/** `disabled` is a SECURITY decision a re-fetch would discard; the STORE
 *  carries it forward so no fetch path can forget. */
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
    // Two accounts sharing a key collide by keyId; nothing carries across.
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

  it("never turns keys back on when the refresh keeps only disabled ones", async () => {
    // Both remaining keys were turned off: they stay off (nothing to encrypt
    // to) rather than turning back on.
    await saveContact(multiContact(3));
    await setContactRecipientDisabled("SHA256:key0", "SHA256:key1", true);
    await setContactRecipientDisabled("SHA256:key0", "SHA256:key2", true);

    await saveContact(refetched([1, 2]));
    const [two] = await loadContacts();
    expect(contactRecipients(two).map(isRecipientDisabled)).toEqual([
      true,
      true,
    ]);
    expect(activeRecipients(two)).toEqual([]);

    // Down to ONE disabled key: the flag must survive.
    // (`refetched` spreads a 3-key record, so drop its list as the store would.)
    await saveContact(withRecipients(refetched([2]), [sshRecipient(2)]));
    const [one] = await loadContacts();
    expect(one.keyId).toBe("SHA256:key2");
    expect(contactRecipients(one).map(isRecipientDisabled)).toEqual([true]);
    expect(activeRecipients(one)).toEqual([]);
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

/** The on-screen list must follow store writes made elsewhere (the
 *  details-page toggle), or a refresh classifies against a stale list. */
describe("the live contacts list follows writes made elsewhere", () => {
  function watched() {
    const list = createLiveList(STORAGE_CONTACTS, loadContacts);
    const renders = vi.fn();
    const stop = list.subscribe(renders);
    return { list, renders, stop };
  }

  it("reloads to the record as it is on disk", async () => {
    await saveContact(multiContact(2));
    const { list, stop } = watched();
    await list.refresh();

    await setContactRecipientDisabled("SHA256:key0", "SHA256:key1", true);
    const [onDisk] = await loadContacts();
    await vi.waitFor(() => expect(list.get().items).toEqual([onDisk]));
    stop();
    expect(
      contactRecipients(list.get().items[0]).map(isRecipientDisabled),
    ).toEqual([false, true]);
  });

  it("does not reload when the write did not happen", async () => {
    await saveContact(multiContact(2));
    const { list, renders, stop } = watched();
    await list.refresh();
    renders.mockClear();

    await updateContact("nobody", (c) => c);
    wasmMock.session = false;
    await expect(
      setContactRecipientDisabled("SHA256:key0", "SHA256:key1", true),
    ).rejects.toThrow(/vault is locked/);
    stop();

    expect(renders).not.toHaveBeenCalled();
  });

  it("keeps a refresh down to turned-off keys at 0 of 1 on screen", async () => {
    await saveContact(multiContact(2));
    const { list, stop } = watched();
    await list.refresh();

    await setContactRecipientDisabled("SHA256:key0", "SHA256:key1", true);
    // GitHub now lists only the key the user turned off.
    const refreshed: PublicContactKey = {
      ...multiContact(2),
      keyId: "SHA256:key1",
      armoredPublicKey: sshRecipient(1).armored,
      recipients: undefined,
    };
    await saveContact(refreshed);
    await list.refresh();
    stop();

    const onScreen = list.get().items;
    expect(onScreen).toHaveLength(1);
    expect(contactRecipients(onScreen[0]).map(isRecipientDisabled)).toEqual([
      true,
    ]);
    expect(activeRecipients(onScreen[0])).toEqual([]);
  });
});

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

  it("still lets a newer copy of a fetched PGP key land, keeping the source", async () => {
    // The owner's revocation, sent by email, for a contact found on
    // keys.openpgp.org. Callers hand in the merge of both copies.
    const source = { type: "keyserver", user: "carol@d.test", fetchedAt: 1 };
    await saveContact(
      legacyContact({ source, alias: "Caz" } as Partial<PublicContactKey>),
    );
    await saveContact(
      legacyContact({
        armoredPublicKey: "-----BEGIN PGP PUBLIC KEY BLOCK----- carol MERGED",
        usableForEncryption: false,
        revoked: true,
      }),
    );

    const [stored] = await loadContacts();
    expect(stored.armoredPublicKey).toContain("MERGED");
    expect(stored.revoked).toBe(true);
    expect(stored.usableForEncryption).toBe(false);
    expect(contactSource(stored)?.user).toBe("carol@d.test");
    expect(stored.alias).toBe("Caz");
  });

  it("is pure: a pasted duplicate leaves the list as it was", () => {
    const existing = [multiContact(3)];
    const pasted = legacyContact({ keyId: "SHA256:key0" });
    expect(upsertContacts(existing, pasted)).toEqual(existing);
    expect(upsertContacts([], pasted)).toEqual([pasted]);
  });
});

/** Every write takes the store's lock, and single-field writes re-read
 *  rather than republish a snapshot. */
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

  it("applies an awaited change to the record on disk, not a snapshot", async () => {
    await saveContact(legacyContact());
    // A slow change (a keyserver merge) starts...
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const slow = updateContact("CCCC", async (current) => {
      await gate;
      return { ...current, expiresAt: 42 };
    });
    // ...and must not undo the rename queued behind the lock.
    const rename = updateContact("CCCC", (c) => ({ ...c, alias: "Caz" }));
    release();
    await Promise.all([slow, rename]);
    const [stored] = await loadContacts();
    expect(stored).toMatchObject({ expiresAt: 42, alias: "Caz" });
  });

  it("writes nothing for a contact deleted before an awaited change", async () => {
    await saveContact(legacyContact());
    await removeContact("CCCC");
    const result = await updateContact("CCCC", (c) =>
      Promise.resolve({ ...c, expiresAt: 42 }),
    );
    expect(result).toBeUndefined();
    expect(await loadContacts()).toEqual([]);
  });

  it("toggles a key without republishing a stale snapshot", async () => {
    await saveContact(multiContact(3));
    const snapshot = (await loadContacts())[0];

    // Something else edits the record after the page captured it.
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

/** Spreading `recipientsField` can't clear a list shrinking to one key;
 *  `withRecipients` must. */
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
    expect(JSON.stringify(Object.keys(two))).toBe(
      JSON.stringify(Object.keys(c)),
    );
  });
});

/** A contact's local display name: absent means fall back, `""` is never
 *  written, and an unnamed contact stays byte-identical. */
describe("alias - absent means the derived name", () => {
  it("falls back to the first User ID when there is no alias", () => {
    expect(displayUserId(legacyContact())).toBe("Carol <c@d.test>");
    expect("alias" in legacyContact()).toBe(false);
  });

  it("wins over the User IDs when set", () => {
    const named = withAlias(legacyContact(), "Carol's laptop");
    expect(displayUserId(named)).toBe("Carol's laptop");
    // The identity is untouched: an alias is a local label only.
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
    // `alias: ""` or `alias: undefined` here would rewrite every user's blob.
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

/** "Verified" belongs to the key, not the person: kept across a refresh
 *  of the same key, never inherited by a different one, absent when
 *  unset. */
describe("verified - the user's decision about one key", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("marks verified with the time, and clears both fields on unmark", async () => {
    vi.useFakeTimers({ now: 4242, toFake: ["Date"] });
    await saveContact(legacyContact());

    await setContactVerified("CCCC", true);
    const [marked] = await loadContacts();
    expect(marked.verified).toBe(true);
    expect(marked.verifiedAt).toBe(4242);

    await setContactVerified("CCCC", false);
    const [cleared] = await loadContacts();
    expect("verified" in cleared).toBe(false);
    expect("verifiedAt" in cleared).toBe(false);
    // Never `verified: false`: the record is back to its stored shape.
    expect(JSON.stringify(cleared)).toBe(JSON.stringify(legacyContact()));
  });

  it("touches nothing else on the record", async () => {
    await saveContact(multiContact(3));
    const before = (await loadContacts())[0];
    await setContactVerified(before.keyId, true);
    await setContactVerified(before.keyId, false);
    const after = (await loadContacts())[0];
    expect(JSON.stringify(after)).toBe(JSON.stringify(before));
  });

  it("writes nothing for a contact that is gone", async () => {
    await saveContact(legacyContact());
    await setContactVerified("NOPE", true);
    const [stored] = await loadContacts();
    expect("verified" in stored).toBe(false);
  });

  it("keeps verified and the alias across a re-import of the same key", async () => {
    await saveContact(legacyContact({ alias: "Caz" }));
    await setContactVerified("CCCC", true);
    const { verifiedAt } = (await loadContacts())[0];

    // The same key pasted again: a fresh record, no alias, no flag.
    await saveContact(
      legacyContact({ armoredPublicKey: "NEWER COPY", lastUsedAt: 9 }),
    );

    const [stored] = await loadContacts();
    expect(stored.armoredPublicKey).toBe("NEWER COPY");
    expect(stored.verified).toBe(true);
    expect(stored.verifiedAt).toBe(verifiedAt);
    expect(stored.alias).toBe("Caz");
  });

  it("lets an incoming alias win over the stored one", async () => {
    await saveContact(legacyContact({ alias: "Caz" }));
    await saveContact(legacyContact({ alias: "Carol L" }));
    const [stored] = await loadContacts();
    expect(stored.alias).toBe("Carol L");
  });

  it("never carries verified to a different key for the same person", async () => {
    // A re-fetch by source with a new head key: the alias survives, the
    // verification (of the old key) does not.
    await saveContact({ ...multiContact(3), alias: "Octo" });
    await setContactVerified("SHA256:key0", true);

    const list = [sshRecipient(5), sshRecipient(6)];
    await saveContact({
      ...multiContact(3),
      keyId: list[0].keyId,
      armoredPublicKey: list[0].armored,
      source: { type: "github", user: "octocat", fetchedAt: 5000 },
      ...recipientsField(list),
    });

    const all = await loadContacts();
    expect(all).toHaveLength(1);
    expect(all[0].keyId).toBe("SHA256:key5");
    expect(all[0].alias).toBe("Octo");
    expect("verified" in all[0]).toBe(false);
    expect("verifiedAt" in all[0]).toBe(false);
  });

  it("drops verified when a group gains a key under the same head", async () => {
    // What the user compared was the old set of keys.
    await saveContact(multiContact(2));
    await setContactVerified("SHA256:key0", true);
    await saveContact({
      ...multiContact(3),
      source: { type: "github", user: "octocat", fetchedAt: 5000 },
    });

    const [stored] = await loadContacts();
    expect(stored.keyId).toBe("SHA256:key0");
    expect("verified" in stored).toBe(false);
  });

  it("never carries the name or verified onto a key set that grew by id", () => {
    // Attack: Alice's key plus Mallory's, pasted under her comment, lands on
    // Alice's record by id. Her alias must not name a contact encrypting to
    // Mallory too.
    const [aliceKey, malloryKey] = [sshRecipient(0), sshRecipient(9)];
    const alice: PublicContactKey = {
      kind: "ssh",
      keyId: aliceKey.keyId,
      userIds: ["alice@laptop"],
      algorithm: aliceKey.algorithm,
      armoredPublicKey: aliceKey.armored,
      addedAt: 1,
      lastUsedAt: 1,
      alias: "Alice",
      verified: true,
      verifiedAt: 5,
    };
    const grown: PublicContactKey = {
      ...alice,
      alias: undefined,
      verified: undefined,
      verifiedAt: undefined,
      addedAt: 7,
      ...recipientsField([aliceKey, malloryKey]),
    };
    const [stored, ...rest] = upsertContacts([alice], grown);
    expect(rest).toEqual([]);
    expect(stored.alias).toBeUndefined();
    expect(stored.verified).toBeUndefined();
    expect(contactRecipients(stored).map((r) => r.keyId)).toEqual([
      aliceKey.keyId,
      malloryKey.keyId,
    ]);
  });

  it("keeps the name when the same key set is pasted again by id", () => {
    const list = [sshRecipient(0), sshRecipient(1)];
    const record: PublicContactKey = {
      ...multiContact(2),
      source: undefined,
      alias: "Otto",
    };
    const again: PublicContactKey = {
      ...multiContact(2),
      source: undefined,
      ...recipientsField([...list].reverse()),
    };
    const [stored] = upsertContacts([record], again);
    expect(stored.alias).toBe("Otto");
  });

  it("still carries a disabled key across a reviewed update by id", () => {
    // A disabled key stays off when the same record gains a key.
    const two: PublicContactKey = {
      ...multiContact(2),
      source: undefined,
      ...recipientsField(
        withRecipientDisabled(
          [sshRecipient(0), sshRecipient(1)],
          "SHA256:key1",
          true,
        ),
      ),
    };
    const three: PublicContactKey = {
      ...multiContact(3),
      source: undefined,
    };
    const [stored] = upsertContacts([two], three);
    expect(
      contactRecipients(stored)
        .filter(isRecipientDisabled)
        .map((r) => r.keyId),
    ).toEqual(["SHA256:key1"]);
  });

  it("never carries verified to another person's record", async () => {
    await saveContact(multiContact(3, "octocat"));
    await setContactVerified("SHA256:key0", true);
    // Another account publishing the same key collides by keyId alone.
    await saveContact(multiContact(3, "hubot"));
    const [stored] = await loadContacts();
    expect(contactSource(stored)?.user).toBe("hubot");
    expect("verified" in stored).toBe(false);
  });
});
