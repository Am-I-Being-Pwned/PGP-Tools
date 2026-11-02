/** Merging imported public keys into contacts. `parseKeys` is mocked;
 *  cert parsing is covered by the Rust tests. */

import { afterEach, describe, expect, it, vi } from "vitest";

import {
  importRejectionMessage,
  isUsableContact,
  mergeIntoContact,
} from "~/lib/import-public-keys";
import type { KeyInfo } from "~/lib/pgp/types";
import { mergePublicKey, parseKeys } from "~/lib/pgp/wasm";
import type * as ContactsModule from "~/lib/storage/contacts";
import type { PublicContactKey } from "~/lib/storage/contacts";

vi.mock("~/lib/pgp/wasm", () => ({
  parseKeys: vi.fn(),
  mergePublicKey: vi.fn(),
  revocationIssuers: vi.fn(),
}));

const store = vi.hoisted(() => ({ updateContact: vi.fn() }));
vi.mock("~/lib/storage/contacts", async (importOriginal) => ({
  ...(await importOriginal<typeof ContactsModule>()),
  updateContact: store.updateContact,
}));

const parse = vi.mocked(parseKeys);
const merge = vi.mocked(mergePublicKey);

function keyInfo(over: Partial<KeyInfo> = {}): KeyInfo {
  return {
    keyId: "FPR1",
    userIds: ["Alice <a@b.test>"],
    algorithm: "ed25519",
    expiresAt: null,
    usableForEncryption: true,
    usableForSigning: true,
    ...over,
  } as KeyInfo;
}

function cert(over: Partial<KeyInfo> = {}, armored = "ARMOR-1") {
  return { keyInfo: keyInfo(over), armored };
}

afterEach(() => {
  vi.resetAllMocks();
});

describe("isUsableContact", () => {
  it.each([
    [
      "encryption only",
      { usableForEncryption: true, usableForSigning: false },
      true,
    ],
    [
      "signing only",
      { usableForEncryption: false, usableForSigning: true },
      true,
    ],
    ["both", { usableForEncryption: true, usableForSigning: true }, true],
    ["neither", { usableForEncryption: false, usableForSigning: false }, false],
  ])("accepts a cert usable for %s", (_label, flags, expected) => {
    expect(isUsableContact(keyInfo(flags))).toBe(expected);
  });
});

describe("importRejectionMessage", () => {
  it("explains an absent cert", () => {
    expect(importRejectionMessage(undefined)).toMatch(/no usable public key/);
  });

  it("names the expiry date, because expiry is the common case", () => {
    const expiresAt = new Date("2020-03-04T00:00:00Z").getTime();
    const message = importRejectionMessage(keyInfo({ expiresAt }));
    expect(message).toMatch(/expired on/);
    expect(message).toMatch(/2020/);
    expect(message).toMatch(/current key/);
  });

  it("prefers the expiry message over a policy error", () => {
    const expiresAt = Date.now() - 1000;
    expect(
      importRejectionMessage(keyInfo({ expiresAt, policyError: "weak hash" })),
    ).toMatch(/expired on/);
  });

  it("passes through a policy error for a live key", () => {
    expect(
      importRejectionMessage(keyInfo({ policyError: "SHA-1 is rejected" })),
    ).toBe("SHA-1 is rejected");
  });

  it("does not treat a future expiry as expired", () => {
    const expiresAt = Date.now() + 86_400_000;
    expect(importRejectionMessage(keyInfo({ expiresAt }))).not.toMatch(
      /expired/,
    );
  });

  it("falls back to the generic reason", () => {
    expect(importRejectionMessage(keyInfo())).toMatch(
      /no usable encryption or signing key/,
    );
  });
});

describe("mergeIntoContact", () => {
  it("merges into the record as the store hands it over, not a caller's copy", async () => {
    // Store already holds a revocation and a rename made meanwhile.
    const onDisk: PublicContactKey = {
      keyId: "FPR1",
      userIds: ["Alice <a@b.test>"],
      algorithm: "ed25519",
      armoredPublicKey: "ON-DISK-REVOKED",
      addedAt: 1,
      lastUsedAt: 1,
      alias: "Ali",
      revoked: true,
    };
    store.updateContact.mockImplementation(
      async (
        _id: string,
        apply: (c: PublicContactKey) => Promise<PublicContactKey>,
      ) => apply(onDisk),
    );
    merge.mockResolvedValue("MERGED");
    parse.mockResolvedValue([cert({ revoked: true }, "MERGED")]);

    const result = await mergeIntoContact("FPR1", "FETCHED");

    expect(merge).toHaveBeenCalledWith("ON-DISK-REVOKED", "FETCHED");
    expect(result?.contact).toMatchObject({
      armoredPublicKey: "MERGED",
      alias: "Ali",
      revoked: true,
    });
  });

  it("writes nothing and says so when the contact is gone", async () => {
    store.updateContact.mockResolvedValue(undefined);
    expect(await mergeIntoContact("FPR1", "FETCHED")).toBeUndefined();
    expect(merge).not.toHaveBeenCalled();
  });

  describe("never changes who the contact is", () => {
    // No Review behind this write: a new User ID must not bind silently.
    const verifiedAlice = (): PublicContactKey => ({
      keyId: "FPR1",
      userIds: ["Alice <a@b.test>"],
      algorithm: "ed25519",
      armoredPublicKey: "ON-DISK",
      addedAt: 1,
      lastUsedAt: 1,
      expiresAt: null,
      verified: true,
      verifiedAt: 5,
    });
    const written: PublicContactKey[] = [];
    const onDisk = (contact: PublicContactKey) =>
      store.updateContact.mockImplementation(
        async (
          _id: string,
          apply: (c: PublicContactKey) => Promise<PublicContactKey>,
        ) => {
          const next = await apply(contact);
          written.push(next);
          return next;
        },
      );
    afterEach(() => {
      written.length = 0;
    });

    it("keeps a new expiry, and 'verified', when the User IDs are unchanged", async () => {
      onDisk(verifiedAlice());
      merge.mockResolvedValue("MERGED");
      parse.mockResolvedValue([cert({ expiresAt: 99 }, "MERGED")]);
      const result = await mergeIntoContact("FPR1", "FETCHED");
      expect(result?.needsReview).toBeUndefined();
      expect(written[0]).toMatchObject({
        armoredPublicKey: "MERGED",
        expiresAt: 99,
        userIds: ["Alice <a@b.test>"],
        verified: true,
        verifiedAt: 5,
      });
    });

    it("writes nothing and asks for the Review when the copy adds a User ID", async () => {
      const alice = verifiedAlice();
      onDisk(alice);
      merge.mockResolvedValue("MERGED");
      parse.mockResolvedValue([
        cert(
          { userIds: ["Alice <a@b.test>", "Carol <carol@corp.test>"] },
          "MERGED",
        ),
      ]);
      const result = await mergeIntoContact("FPR1", "FETCHED");
      expect(result?.needsReview).toBe(true);
      expect(written).toEqual([alice]);
    });

    it("saves a revocation that adds a User ID under the old ones, unverified", async () => {
      onDisk({ ...verifiedAlice(), lookalike: undefined });
      merge.mockResolvedValue("MERGED");
      parse.mockResolvedValue([
        cert(
          {
            revoked: true,
            lookalike: true,
            userIds: ["Alice <a@b.test>", "Аlice <a@evil.test>"],
          },
          "MERGED",
        ),
      ]);
      const result = await mergeIntoContact("FPR1", "FETCHED");
      expect(result?.needsReview).toBeUndefined();
      expect(result?.keyInfo.revoked).toBe(true);
      expect(written[0]).toMatchObject({
        armoredPublicKey: "MERGED",
        revoked: true,
        userIds: ["Alice <a@b.test>"],
      });
      expect("verified" in written[0]).toBe(false);
      expect("verifiedAt" in written[0]).toBe(false);
      expect("lookalike" in written[0]).toBe(false);
    });
  });
});
