import { beforeEach, describe, expect, it, vi } from "vitest";

import { backfillIdentity } from "~/lib/storage/contact-backfill";
import type * as ContactsModule from "~/lib/storage/contacts";
import {
  IDENTITY_VERSION,
  type PublicContactKey,
} from "~/lib/storage/contacts";

const wasm = vi.hoisted(() => ({ parseKey: vi.fn() }));
vi.mock("~/lib/pgp/wasm", () => wasm);

const store = vi.hoisted(() => ({
  updateContact: vi.fn(),
}));
vi.mock("~/lib/storage/contacts", async (importOriginal) => ({
  ...(await importOriginal<typeof ContactsModule>()),
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

/** Old records still list unbound User IDs; the backfill re-derives the
 *  identity fields once. */
let written: PublicContactKey | undefined;
function lastWritten(): PublicContactKey {
  if (!written) throw new Error("nothing was written");
  return written;
}

describe("backfillIdentity", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    written = undefined;
    store.updateContact.mockImplementation(
      (_id: string, patch: (c: PublicContactKey) => PublicContactKey) => {
        written = patch(contact());
        return Promise.resolve(written);
      },
    );
  });

  it("replaces stored User IDs with the bound ones and records revocation", async () => {
    wasm.parseKey.mockResolvedValue({
      userIds: ["Bob <bob@example.com>"],
      usableForEncryption: false,
      revoked: true,
    });

    await backfillIdentity(contact());
    const patched = lastWritten();

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

    await backfillIdentity(contact());
    const patched = lastWritten();

    expect(patched.lookalike).toBe(true);
    expect(patched.securityWarning).toMatch(/alphabets/);
  });

  it("runs once: a contact already at the current version is left alone", async () => {
    await backfillIdentity(contact({ identityVersion: IDENTITY_VERSION }));
    expect(wasm.parseKey).not.toHaveBeenCalled();
    expect(store.updateContact).not.toHaveBeenCalled();
  });

  it("marks an SSH contact checked without parsing it as PGP", async () => {
    await backfillIdentity(
      contact({ kind: "ssh", armoredPublicKey: "ssh-ed25519 AAAA" }),
    );
    const patched = lastWritten();
    expect(wasm.parseKey).not.toHaveBeenCalled();
    expect(patched.identityVersion).toBe(IDENTITY_VERSION);
  });
});
