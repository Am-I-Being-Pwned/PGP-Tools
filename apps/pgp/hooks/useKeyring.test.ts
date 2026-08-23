import { beforeEach, describe, expect, it, vi } from "vitest";

const storage = vi.hoisted(() => ({
  getKeyring: vi.fn(),
  addKey: vi.fn(),
  removeKey: vi.fn(),
  updateAlias: vi.fn(),
  updateRevocationCertificate: vi.fn(),
}));
vi.mock("../lib/storage/keyring", () => storage);

import { readKeyring } from "./useKeyring";

/**
 * The distinction under test is the one a user reads as catastrophe: an
 * empty keyring and an unreadable keyring render identically, and only
 * one of them means "your keys are gone". `getKeyring` throws when the
 * session key can't open the blob, and an unhandled throw used to leave
 * the hook showing "no keys" for a vault that was intact on disk.
 */
describe("readKeyring", () => {
  beforeEach(() => vi.clearAllMocks());

  it("reports an unreadable keyring as an error, not as an empty one", async () => {
    storage.getKeyring.mockRejectedValue(new Error("bad AEAD tag"));
    const { keys, error } = await readKeyring();
    expect(error).toBeInstanceOf(Error);
    expect(keys).toEqual([]);
  });

  it("leaves error null for a genuinely empty keyring", async () => {
    storage.getKeyring.mockResolvedValue([]);
    const { keys, error } = await readKeyring();
    expect(error).toBeNull();
    expect(keys).toEqual([]);
  });

  it("passes a populated keyring through untouched", async () => {
    const blobs = [{ keyId: "AAAA" }, { keyId: "BBBB" }];
    storage.getKeyring.mockResolvedValue(blobs);
    const { keys, error } = await readKeyring();
    expect(error).toBeNull();
    expect(keys).toBe(blobs);
  });

  it("wraps a non-Error rejection so the UI always has a message", async () => {
    storage.getKeyring.mockRejectedValue("just a string");
    const { error } = await readKeyring();
    expect(error).toBeInstanceOf(Error);
    expect(error?.message).toBe("just a string");
  });
});
