import { beforeEach, describe, expect, it, vi } from "vitest";

import type { KeyDetails, KeyInfo } from "../pgp/types";
import type { StoredKey, StoredKeys } from "./prepare";
import { extractPublicKey, parseKeyDetails, parseKeys } from "../pgp/wasm";
import { classifyCert, importable, isNoOp, prepareImport } from "./prepare";

// The WASM engine is not available under vitest (see vitest.config.ts);
// parsing itself is covered by the Rust tests. These tests are about the
// classification built on top of it, so the parser is stubbed.
vi.mock("../pgp/wasm", () => ({
  parseKeys: vi.fn(),
  parseKeyDetails: vi.fn(),
  extractPublicKey: vi.fn(),
}));

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.UTC(2026, 7, 23);
const FP = "3A9E1F5C7B2D48E6A0C1938574FD62B0E4A75C11";

function info(over: Partial<KeyInfo> = {}): KeyInfo {
  return {
    keyId: FP,
    userIds: ["Alice <alice@example.com>"],
    algorithm: "ed25519",
    createdAt: NOW - 400 * DAY,
    expiresAt: NOW + 400 * DAY,
    isPrivate: false,
    usableForEncryption: true,
    usableForSigning: true,
    ...over,
  };
}

function details(fingerprints: string[]): KeyDetails {
  return {
    truncated: false,
    keys: fingerprints.map((fingerprint, i) => ({
      fingerprint,
      keyId: fingerprint.slice(-16),
      algorithm: "ed25519",
      createdAt: NOW - 400 * DAY,
      expiresAt: null,
      isPrimary: i === 0,
      canSign: true,
      canEncrypt: false,
      canCertify: true,
      canAuthenticate: false,
      status: "active" as const,
    })),
  };
}

function storedKey(over: Partial<StoredKey> = {}): StoredKey {
  return {
    keyId: FP,
    userIds: ["Alice <alice@example.com>"],
    armored: "ARMOR-A",
    addedAt: NOW - 30 * DAY,
    expiresAt: NOW + 400 * DAY,
    ...over,
  };
}

const noStores: StoredKeys = { own: [], contacts: [] };

beforeEach(() => {
  vi.mocked(parseKeys).mockReset();
  vi.mocked(extractPublicKey).mockReset();
  vi.mocked(parseKeyDetails).mockReset();
  vi.mocked(parseKeyDetails).mockResolvedValue(details([FP]));
});

describe("classifyCert", () => {
  it("marks an unknown fingerprint as new", async () => {
    const result = await classifyCert(info(), "ARMOR-A", []);
    expect(result.status).toBe("new");
    expect(result.kind).toBe("public");
    expect(result.changes).toEqual([]);
  });

  it("marks byte-identical armor as a duplicate, with the stored date", async () => {
    const result = await classifyCert(info(), "ARMOR-A", [storedKey()]);
    expect(result.status).toBe("duplicate");
    expect(result.existingAddedAt).toBe(NOW - 30 * DAY);
  });

  it("ignores line-ending and whitespace differences when deduping", async () => {
    const result = await classifyCert(info(), "ARMOR-A\r\n  ", [
      storedKey({ armored: "ARMOR-A\n" }),
    ]);
    expect(result.status).toBe("duplicate");
  });

  it("reports an extended expiry as an update", async () => {
    const result = await classifyCert(
      info({ expiresAt: NOW + 900 * DAY }),
      "ARMOR-B",
      [storedKey()],
    );
    expect(result.status).toBe("update");
    expect(result.changes.join(" ")).toMatch(/new expiry/i);
  });

  it("reports added user IDs as an update", async () => {
    const result = await classifyCert(
      info({ userIds: ["Alice <alice@example.com>", "Alice <a@work.example>"] }),
      "ARMOR-B",
      [storedKey()],
    );
    expect(result.status).toBe("update");
    expect(result.changes.join(" ")).toMatch(/1 new user ID/);
  });

  it("reports added subkeys as an update", async () => {
    vi.mocked(parseKeyDetails)
      .mockResolvedValueOnce(details([FP, "SUB-1", "SUB-2"])) // incoming
      .mockResolvedValueOnce(details([FP, "SUB-1"])); // stored
    const result = await classifyCert(info(), "ARMOR-B", [storedKey()]);
    expect(result.status).toBe("update");
    expect(result.changes).toContain("1 new subkey");
  });

  it("still explains an update whose visible fields all match", async () => {
    const result = await classifyCert(info(), "ARMOR-B", [storedKey()]);
    expect(result.status).toBe("update");
    expect(result.changes).toEqual(["The key has been re-issued"]);
  });

  it("rejects a key that is neither encryption- nor signing-capable", async () => {
    const result = await classifyCert(
      info({ usableForEncryption: false, usableForSigning: false }),
      "ARMOR-A",
      [],
    );
    expect(result.status).toBe("rejected");
    expect(result.rejection).toBeTruthy();
  });

  it("explains an expired key with its date", async () => {
    const result = await classifyCert(
      info({
        expiresAt: NOW - 10 * DAY,
        usableForEncryption: false,
        usableForSigning: false,
      }),
      "ARMOR-A",
      [],
    );
    expect(result.status).toBe("rejected");
    expect(result.rejection).toMatch(/expired/i);
  });

  it("previews from KeyInfo alone when the breakdown fails to parse", async () => {
    vi.mocked(parseKeyDetails).mockRejectedValue(new Error("bad cert"));
    const result = await classifyCert(info(), "ARMOR-A", []);
    expect(result.status).toBe("new");
    expect(result.details).toBeNull();
    expect(result.info).not.toBeNull();
  });
});

describe("prepareImport", () => {
  it("flags text that carries no certificate", async () => {
    vi.mocked(parseKeys).mockRejectedValue(new Error("no cert"));
    const prepared = await prepareImport("hello", noStores);
    expect(prepared.unparseable).toBe(true);
    expect(prepared.keys).toEqual([]);
  });

  it("classifies every cert in a bundle", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info(), armored: "ARMOR-A" },
      { keyInfo: info({ keyId: "OTHER" }), armored: "ARMOR-C" },
    ]);
    const prepared = await prepareImport("blob", {
      own: [],
      contacts: [storedKey()],
    });
    expect(prepared.keys.map((k) => k.status)).toEqual(["duplicate", "new"]);
  });

  it("drops stale rotations when a live cert is present", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      {
        keyInfo: info({
          keyId: "OLD",
          usableForEncryption: false,
          usableForSigning: false,
        }),
        armored: "ARMOR-OLD",
      },
      { keyInfo: info({ keyId: "LIVE" }), armored: "ARMOR-LIVE" },
    ]);
    const prepared = await prepareImport("blob", noStores);
    expect(prepared.keys).toHaveLength(1);
    expect(prepared.keys[0].keyId).toBe("LIVE");
  });

  it("keeps the rejects when nothing in the blob is usable", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      {
        keyInfo: info({
          usableForEncryption: false,
          usableForSigning: false,
        }),
        armored: "ARMOR-OLD",
      },
    ]);
    const prepared = await prepareImport("blob", noStores);
    expect(prepared.keys.map((k) => k.status)).toEqual(["rejected"]);
  });

  it("keeps private armor out of the preview and parks it in secrets", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info({ isPrivate: true }), armored: "PRIVATE-ARMOR" },
    ]);
    vi.mocked(extractPublicKey).mockResolvedValue("PUBLIC-ARMOR");

    const prepared = await prepareImport("blob", noStores);
    const key = prepared.keys[0];
    expect(key.kind).toBe("private");
    expect(key.publicArmored).toBe("PUBLIC-ARMOR");
    expect(JSON.stringify(key)).not.toContain("PRIVATE-ARMOR");
    expect(prepared.secrets.get(FP)).toBe("PRIVATE-ARMOR");
  });

  it("drops a private cert whose secret half cannot be stripped", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info({ isPrivate: true }), armored: "PRIVATE-ARMOR" },
    ]);
    vi.mocked(extractPublicKey).mockRejectedValue(new Error("nope"));

    const prepared = await prepareImport("blob", noStores);
    expect(prepared.keys).toEqual([]);
    expect(prepared.unparseable).toBe(true);
  });

  it("matches a private import against the keyring, not contacts", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info({ isPrivate: true }), armored: "PRIVATE-ARMOR" },
    ]);
    vi.mocked(extractPublicKey).mockResolvedValue("ARMOR-A");

    const prepared = await prepareImport("blob", {
      own: [storedKey({ createdAt: NOW - 90 * DAY, addedAt: undefined })],
      contacts: [],
    });
    expect(prepared.keys[0].status).toBe("duplicate");
    expect(prepared.keys[0].existingAddedAt).toBe(NOW - 90 * DAY);
  });
});

describe("isNoOp / importable", () => {
  it("is a no-op only when every key is already stored", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info(), armored: "ARMOR-A" },
    ]);
    const prepared = await prepareImport("blob", {
      own: [],
      contacts: [storedKey()],
    });
    expect(isNoOp(prepared)).toBe(true);
    expect(importable(prepared.keys)).toEqual([]);
  });

  it("is not a no-op when one key of a bundle is new", async () => {
    vi.mocked(parseKeys).mockResolvedValue([
      { keyInfo: info(), armored: "ARMOR-A" },
      { keyInfo: info({ keyId: "OTHER" }), armored: "ARMOR-C" },
    ]);
    const prepared = await prepareImport("blob", {
      own: [],
      contacts: [storedKey()],
    });
    expect(isNoOp(prepared)).toBe(false);
    expect(importable(prepared.keys)).toHaveLength(1);
  });

  it("an empty result is not a no-op", () => {
    expect(
      isNoOp({ keys: [], secrets: new Map(), unparseable: true }),
    ).toBe(false);
  });
});
