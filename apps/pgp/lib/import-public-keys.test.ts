/**
 * Merging imported public keys into contacts, and the rules that decide
 * whether a cert is worth keeping.
 *
 * (The bundle routing -- each cert against its own armor, stale
 * rotations dropped -- is `prepareImport`'s now; see prepare.test.ts.)
 *
 * `parseKeys` is mocked -- parsing certificates is the WASM engine's job
 * and is covered by the Rust tests. What is tested here is the routing
 * decision made on top of whatever it returns.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import type { KeyInfo } from "./pgp/types";
import type { PublicContactKey } from "./storage/contacts";
import {
  importRejectionMessage,
  isUsableContact,
  mergeIntoContact,
} from "./import-public-keys";
import { mergePublicKey, parseKeys } from "./pgp/wasm";

vi.mock("./pgp/wasm", () => ({
  parseKeys: vi.fn(),
  mergePublicKey: vi.fn(),
  revocationIssuers: vi.fn(),
}));

const store = vi.hoisted(() => ({ updateContactAsync: vi.fn() }));
vi.mock("./storage/contacts", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./storage/contacts")>()),
  updateContactAsync: store.updateContactAsync,
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

/** One parsed cert as `parseKeys` returns it. */
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
    // Sign-only keys are perfectly good contacts -- you just can't
    // encrypt to them.
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
    // The store's version already holds a revocation imported while a
    // keyserver check was in flight, and a rename.
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
    store.updateContactAsync.mockImplementation(
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
    store.updateContactAsync.mockResolvedValue(undefined);
    expect(await mergeIntoContact("FPR1", "FETCHED")).toBeUndefined();
    expect(merge).not.toHaveBeenCalled();
  });
});
