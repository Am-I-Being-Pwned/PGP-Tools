import { beforeEach, describe, expect, it, vi } from "vitest";

import type { PublicContactKey } from "../lib/storage/contacts";
import { IDENTITY_VERSION } from "../lib/storage/contacts";
import { backfillIdentity, withUpdatedContact } from "./useContacts";

const wasm = vi.hoisted(() => ({ parseKey: vi.fn() }));
vi.mock("../lib/pgp/wasm", () => wasm);

const store = vi.hoisted(() => ({
  updateContact: vi.fn(),
}));
vi.mock("../lib/storage/contacts", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../lib/storage/contacts")>()),
  updateContact: store.updateContact,
}));

function contact(over: Partial<PublicContactKey> = {}): PublicContactKey {
  return {
    keyId: "FPR1",
    userIds: ["Aaron CEO <ceo@corp.test>", "Bob <bob@example.com>"],
    algorithm: "ed25519",
    armoredPublicKey: "ARMOR",
    addedAt: 1,
    lastUsedAt: 1,
    expiresAt: null,
    ...over,
  };
}

/**
 * Contacts stored before the engine stopped listing unbound User IDs
 * still carry them -- and the first one names the contact on every
 * signer card. The backfill re-derives the identity fields once.
 */
describe("backfillIdentity", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    store.updateContact.mockImplementation(
      (_id: string, patch: (c: PublicContactKey) => PublicContactKey) =>
        Promise.resolve(patch(contact())),
    );
  });

  it("replaces stored User IDs with the bound ones and records revocation", async () => {
    wasm.parseKey.mockResolvedValue({
      userIds: ["Bob <bob@example.com>"],
      usableForEncryption: false,
      revoked: true,
    });

    const [patched] = await backfillIdentity([contact()]);

    expect(patched.userIds).toEqual(["Bob <bob@example.com>"]);
    expect(patched.revoked).toBe(true);
    expect(patched.usableForEncryption).toBe(false);
    expect(patched.identityVersion).toBe(IDENTITY_VERSION);
  });

  it("records a lookalike name with its warning", async () => {
    wasm.parseKey.mockResolvedValue({
      userIds: ["Аlice <alice@example.com>"],
      usableForEncryption: true,
      lookalike: true,
      securityWarning: "mixes letters from different alphabets",
    });

    const [patched] = await backfillIdentity([contact()]);

    expect(patched.lookalike).toBe(true);
    expect(patched.securityWarning).toMatch(/alphabets/);
  });

  it("runs once: a contact already at the current version is left alone", async () => {
    await backfillIdentity([contact({ identityVersion: IDENTITY_VERSION })]);
    expect(wasm.parseKey).not.toHaveBeenCalled();
    expect(store.updateContact).not.toHaveBeenCalled();
  });

  it("marks an SSH contact checked without parsing it as PGP", async () => {
    const [patched] = await backfillIdentity([
      contact({ kind: "ssh", armoredPublicKey: "ssh-ed25519 AAAA" }),
    ]);
    expect(wasm.parseKey).not.toHaveBeenCalled();
    expect(patched.identityVersion).toBe(IDENTITY_VERSION);
  });
});

/**
 * A record changed in place outside the hook (the recipient toggle)
 * replaces its copy in the list on screen -- see `onContactUpdated`.
 */
describe("withUpdatedContact", () => {
  it("swaps in the record as written, by id, keeping the order", () => {
    const a = contact({ keyId: "A" });
    const b = contact({ keyId: "B" });
    const written = contact({
      keyId: "A",
      recipients: [
        { keyId: "A", armored: "ARMOR", algorithm: "ed25519", disabled: true },
      ],
    });
    expect(withUpdatedContact([a, b], written)).toEqual([written, b]);
  });

  it("leaves a list without that record untouched", () => {
    const list = [contact({ keyId: "A" })];
    expect(withUpdatedContact(list, contact({ keyId: "Z" }))).toBe(list);
  });
});
