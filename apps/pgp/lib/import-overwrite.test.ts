import { describe, expect, it } from "vitest";

import { detectImportOverwrite } from "./import-overwrite";

const DAY = 24 * 60 * 60 * 1000;

const contact = {
  keyId: "ABCDEF0123456789",
  userIds: ["Alice <alice@example.com>"],
  addedAt: 1_700_000_000_000,
  expiresAt: 1_800_000_000_000,
};

const keyringEntry = {
  keyId: "1122334455667788",
  userIds: ["Bob <bob@example.com>"],
  createdAt: 1_650_000_000_000,
};

describe("detectImportOverwrite", () => {
  it("returns null for an unknown fingerprint", () => {
    expect(detectImportOverwrite("DEADBEEF", [contact, keyringEntry])).toBe(
      null,
    );
  });

  it("returns null against an empty store", () => {
    expect(detectImportOverwrite(contact.keyId, [])).toBe(null);
  });

  it("detects a contact collision with its user ID and added date", () => {
    const result = detectImportOverwrite(contact.keyId, [contact]);
    expect(result).toEqual({
      userId: "Alice <alice@example.com>",
      addedAt: contact.addedAt,
      changes: [],
    });
  });

  it("matches fingerprints case-insensitively", () => {
    const result = detectImportOverwrite(
      contact.keyId.toLowerCase(),
      [contact],
    );
    expect(result?.userId).toBe("Alice <alice@example.com>");
  });

  it("falls back to createdAt for keyring entries", () => {
    const result = detectImportOverwrite(keyringEntry.keyId, [keyringEntry]);
    expect(result?.addedAt).toBe(keyringEntry.createdAt);
  });

  it("reports a changed expiry", () => {
    const result = detectImportOverwrite(contact.keyId, [contact], {
      expiresAt: contact.expiresAt + 365 * DAY,
      userIds: contact.userIds,
    });
    expect(result?.changes).toHaveLength(1);
    expect(result?.changes[0]).toMatch(/^new expiry: /);
  });

  it("reports an expiry removed entirely", () => {
    const result = detectImportOverwrite(contact.keyId, [contact], {
      expiresAt: null,
      userIds: contact.userIds,
    });
    expect(result?.changes).toEqual(["no longer expires"]);
  });

  it("skips the expiry diff when the stored entry records none", () => {
    const result = detectImportOverwrite(keyringEntry.keyId, [keyringEntry], {
      expiresAt: 1_900_000_000_000,
      userIds: keyringEntry.userIds,
    });
    expect(result?.changes).toEqual([]);
  });

  it("reports new user IDs", () => {
    const result = detectImportOverwrite(contact.keyId, [contact], {
      expiresAt: contact.expiresAt,
      userIds: [...contact.userIds, "Alice <alice@work.example>"],
    });
    expect(result?.changes).toEqual(["1 new user ID"]);
  });

  it("reports no changes for an identical re-import", () => {
    const result = detectImportOverwrite(contact.keyId, [contact], {
      expiresAt: contact.expiresAt,
      userIds: contact.userIds,
    });
    expect(result?.changes).toEqual([]);
  });
});
