/**
 * Saving what the user chose on the import Review.
 *
 * What is pinned here is the rule the identity-binding fix rests on: a
 * key in conflict (one claiming a contact's address or look-alike name)
 * is NEVER saved unless the user picked something for it -- a missing
 * decision means "skip" -- and "replace" writes the new key before it
 * removes the old contact, so a failure in between leaves both rather
 * than neither.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import type { PublicContactKey } from "../storage/contacts";
import type { ReviewDecision, ReviewedContact } from "./review";
import type { IncomingKey } from "./types";
import { IDENTITY_VERSION } from "../storage/contacts";
import {
  applyReview,
  contactFromIncoming,
  defaultDecision,
  needsDecision,
} from "./review";

// The WASM engine is not available under vitest. Only the SSH case
// parses anything (the recipient line), and says what the engine returns.
const wasm = vi.hoisted(() => ({ parseSshRecipient: vi.fn() }));
vi.mock("../pgp/wasm", () => wasm);

const CAROL = "CA70CA70CA70CA70CA70CA70CA70CA70CA70CA70";
const IMPOSTOR = "BAD0BAD0BAD0BAD0BAD0BAD0BAD0BAD0BAD0BAD0";
const DAVE = "DA7EDA7EDA7EDA7EDA7EDA7EDA7EDA7EDA7EDA7E";

/** Carol as stored: a local name, a key she rotated from before. */
function carolContact(): PublicContactKey {
  return {
    keyId: CAROL,
    userIds: ["Carol Lane <carol@example.com>"],
    algorithm: "ed25519",
    armoredPublicKey: "ARMOR-CAROL",
    addedAt: 1,
    lastUsedAt: 1,
    expiresAt: null,
    alias: "Carol (work)",
    previousKeyIds: ["OLDCAROL"],
    verified: true,
    verifiedAt: 1,
  };
}

function incoming(over: Partial<IncomingKey> = {}): IncomingKey {
  return {
    keyId: DAVE,
    kind: "pgp-public",
    status: "new",
    info: null,
    details: null,
    userIds: ["Dave Hill <dave@example.com>"],
    changes: [],
    publicArmored: "ARMOR-DAVE",
    ...over,
  };
}

/** The advisory's key: a new fingerprint under Carol's exact User ID. */
function impostor(over: Partial<IncomingKey> = {}): IncomingKey {
  const carol = carolContact();
  return incoming({
    keyId: IMPOSTOR,
    userIds: carol.userIds,
    publicArmored: "ARMOR-IMPOSTOR",
    conflict: {
      kind: "address",
      holders: [{ keyId: carol.keyId, userIds: carol.userIds }],
    },
    ...over,
  });
}

/** A store that records every write, in order. */
function fakeStore(contacts: PublicContactKey[] = [carolContact()]) {
  const calls: string[] = [];
  const added: ReviewedContact[] = [];
  return {
    calls,
    added,
    contacts,
    add: vi.fn((c: ReviewedContact) => {
      calls.push(`add ${c.keyId}`);
      added.push(c);
      return Promise.resolve();
    }),
    remove: vi.fn((keyId: string) => {
      calls.push(`remove ${keyId}`);
      return Promise.resolve();
    }),
  };
}

const decide = (...entries: [string, ReviewDecision][]) => new Map(entries);

describe("needsDecision / defaultDecision", () => {
  it("asks about new keys and updates only", () => {
    expect(needsDecision(incoming())).toBe(true);
    expect(needsDecision(incoming({ status: "update" }))).toBe(true);
    expect(needsDecision(incoming({ status: "duplicate" }))).toBe(false);
    expect(needsDecision(incoming({ status: "rejected" }))).toBe(false);
  });

  it("starts a key in conflict unticked, every other key ticked", () => {
    expect(defaultDecision(impostor())).toBe("skip");
    expect(
      defaultDecision(impostor({ conflict: { kind: "name", holders: [] } })),
    ).toBe("skip");
    expect(defaultDecision(incoming())).toBe("import");
  });

  it("starts an update that leaves only turned-off keys unticked", () => {
    expect(
      defaultDecision(incoming({ status: "update", allKeysOff: true })),
    ).toBe("skip");
  });
});

describe("contactFromIncoming", () => {
  it("builds a PGP contact without inventing a source or a verification", async () => {
    const contact = await contactFromIncoming(
      incoming({
        info: {
          keyId: DAVE,
          userIds: ["Dave Hill <dave@example.com>"],
          algorithm: "rsa4096",
          createdAt: 1,
          expiresAt: 99,
          isPrivate: false,
          usableForEncryption: false,
          usableForSigning: true,
        },
      }),
    );
    expect(contact).toMatchObject({
      keyId: DAVE,
      algorithm: "rsa4096",
      armoredPublicKey: "ARMOR-DAVE",
      expiresAt: 99,
      usableForEncryption: false,
      identityVersion: IDENTITY_VERSION,
    });
    expect("source" in contact).toBe(false);
    expect("verified" in contact).toBe(false);
    expect("revoked" in contact).toBe(false);
  });
});

describe("applyReview", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("saves nothing for a key the user skipped", async () => {
    const store = fakeStore();
    const outcome = await applyReview(
      [impostor(), incoming()],
      decide([IMPOSTOR, "skip"], [DAVE, "skip"]),
      store,
    );
    expect(store.calls).toEqual([]);
    expect(outcome).toEqual({ added: 0, updated: 0, replaced: 0, keyIds: [] });
  });

  it("never saves a key in conflict that has no decision", async () => {
    // The advisory's bundle with nothing chosen: the impostor stays out,
    // the unrelated key beside it goes in as before.
    const store = fakeStore();
    const outcome = await applyReview(
      [impostor(), incoming()],
      new Map(),
      store,
    );
    expect(store.calls).toEqual([`add ${DAVE}`]);
    expect(outcome.keyIds).toEqual([DAVE]);
    expect(store.remove).not.toHaveBeenCalled();
  });

  it("never saves a name clash without a decision either", async () => {
    const store = fakeStore();
    await applyReview(
      [
        impostor({
          userIds: ["Carol Lane <carol.lane@mail.example>"],
          conflict: {
            kind: "name",
            holders: [{ keyId: CAROL, userIds: carolContact().userIds }],
          },
        }),
      ],
      new Map(),
      store,
    );
    expect(store.add).not.toHaveBeenCalled();
  });

  it('"import" keeps a key in conflict as a separate contact', async () => {
    const store = fakeStore();
    const outcome = await applyReview(
      [impostor()],
      decide([IMPOSTOR, "import"]),
      store,
    );
    expect(store.calls).toEqual([`add ${IMPOSTOR}`]);
    expect(outcome).toEqual({
      added: 1,
      updated: 0,
      replaced: 0,
      keyIds: [IMPOSTOR],
    });
    // A separate contact: nothing of Carol's carries over.
    const [saved] = store.added;
    expect("alias" in saved).toBe(false);
    expect("previousKeyIds" in saved).toBe(false);
  });

  it('"replace" saves the new key as the contact, then removes the old one', async () => {
    const store = fakeStore();
    const outcome = await applyReview(
      [impostor()],
      decide([IMPOSTOR, "replace"]),
      store,
    );

    // Add BEFORE remove: a failure between the two leaves both contacts,
    // never neither.
    expect(store.calls).toEqual([`add ${IMPOSTOR}`, `remove ${CAROL}`]);
    expect(outcome).toEqual({
      added: 0,
      updated: 0,
      replaced: 1,
      keyIds: [IMPOSTOR],
    });

    const [saved] = store.added;
    expect(saved.keyId).toBe(IMPOSTOR);
    expect(saved.armoredPublicKey).toBe("ARMOR-IMPOSTOR");
    // The contact's local name stays; the old key is remembered, newest
    // first.
    expect(saved.alias).toBe("Carol (work)");
    expect(saved.previousKeyIds).toEqual([CAROL, "OLDCAROL"]);
    // A different key is never "verified" because the old one was.
    expect("verified" in saved).toBe(false);
    expect("verifiedAt" in saved).toBe(false);
  });

  it("keeps the old contact when saving the replacement fails", async () => {
    const store = fakeStore();
    store.add.mockRejectedValueOnce(new Error("disk full"));
    await expect(
      applyReview([impostor()], decide([IMPOSTOR, "replace"]), store),
    ).rejects.toThrow("disk full");
    expect(store.remove).not.toHaveBeenCalled();
  });

  it('"replace" on a name clash only adds -- it never removes someone', async () => {
    // Replace is defined against the contact holding the ADDRESS; a
    // look-alike name under another address names no one to replace.
    const store = fakeStore();
    const outcome = await applyReview(
      [
        impostor({
          conflict: {
            kind: "name",
            holders: [{ keyId: CAROL, userIds: carolContact().userIds }],
          },
        }),
      ],
      decide([IMPOSTOR, "replace"]),
      store,
    );
    expect(store.calls).toEqual([`add ${IMPOSTOR}`]);
    expect(outcome.added).toBe(1);
    expect(outcome.replaced).toBe(0);
  });

  it('"replace" with several contacts holding the address removes none', async () => {
    // Which of them the key takes over is not something to guess, and
    // replacing them all deletes people the Review never named. The
    // Review does not offer Replace then; a stale decision only adds.
    const other = { ...carolContact(), keyId: DAVE, alias: "Carol (home)" };
    const store = fakeStore([carolContact(), other]);
    const outcome = await applyReview(
      [
        impostor({
          conflict: {
            kind: "address",
            holders: [
              { keyId: CAROL, userIds: carolContact().userIds },
              { keyId: DAVE, userIds: other.userIds },
            ],
          },
        }),
      ],
      decide([IMPOSTOR, "replace"]),
      store,
    );
    expect(store.calls).toEqual([`add ${IMPOSTOR}`]);
    expect(store.remove).not.toHaveBeenCalled();
    expect(outcome.replaced).toBe(0);
    expect("alias" in store.added[0]).toBe(false);
  });

  it('"replace" never removes the user\'s own key or another incoming one', async () => {
    const store = fakeStore();
    const outcome = await applyReview(
      [
        impostor({
          conflict: {
            kind: "address",
            holders: [
              { keyId: CAROL, userIds: carolContact().userIds, own: true },
            ],
          },
        }),
      ],
      decide([IMPOSTOR, "replace"]),
      store,
    );
    expect(store.calls).toEqual([`add ${IMPOSTOR}`]);
    expect(outcome.replaced).toBe(0);
  });

  it('"replace" on a lookalike address only adds, too', async () => {
    // "al\u0131ce@" only READS as the holder's address. A new key for a
    // lookalike of someone's address is never their rotation.
    const store = fakeStore();
    const outcome = await applyReview(
      [
        impostor({
          conflict: {
            kind: "address",
            lookalike: true,
            holders: [{ keyId: CAROL, userIds: carolContact().userIds }],
          },
        }),
      ],
      decide([IMPOSTOR, "replace"]),
      store,
    );
    expect(store.calls).toEqual([`add ${IMPOSTOR}`]);
    expect(outcome.replaced).toBe(0);
  });

  it("never saves a duplicate or a rejected key, whatever the decision", async () => {
    const store = fakeStore();
    const outcome = await applyReview(
      [
        incoming({ keyId: "DUP", status: "duplicate" }),
        incoming({ keyId: "REJ", status: "rejected" }),
      ],
      decide(["DUP", "import"], ["REJ", "import"]),
      store,
    );
    expect(store.calls).toEqual([]);
    expect(outcome.keyIds).toEqual([]);
  });

  it("counts an update as updated and a new key as added", async () => {
    const store = fakeStore();
    const outcome = await applyReview(
      [
        incoming({ keyId: CAROL, status: "update", userIds: ["Carol"] }),
        incoming(),
      ],
      new Map(),
      store,
    );
    expect(outcome).toEqual({
      added: 1,
      updated: 1,
      replaced: 0,
      keyIds: [CAROL, DAVE],
    });
  });
});

describe("contactFromIncoming: a single pasted SSH key", () => {
  const FP = "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
  const LINE = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample";

  beforeEach(() => {
    // The stored recipient is the canonical line, which has no comment:
    // the engine's parse of it reports none.
    wasm.parseSshRecipient.mockResolvedValue({
      fingerprint: FP,
      recipient: LINE,
      comment: "",
      algorithm: "ssh-ed25519",
    });
  });

  const ssh = (userIds: string[]) =>
    incoming({ keyId: FP, kind: "ssh-public", userIds, publicArmored: LINE });

  it("keeps the comment the Review showed as the contact's name", async () => {
    const contact = await contactFromIncoming(ssh(["alice@laptop"]));
    expect(contact.userIds).toEqual(["alice@laptop"]);
    expect(contact.keyId).toBe(FP);
    expect(contact.armoredPublicKey).toBe(LINE);
    expect(contact.expiresAt).toBeNull();
  });

  it("stores no name, not the placeholder, for a key with no comment", async () => {
    const contact = await contactFromIncoming(ssh(["SSH key"]));
    expect(contact.userIds).toEqual([]);
  });
});
