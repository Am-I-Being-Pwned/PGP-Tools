import { describe, expect, it } from "vitest";

import { parseCrxKeyBlocks, serializeCrxKeyBlocks } from "./backup";
import type { CrxSigningKeyBlob } from "./types";

function passwordBlob(id: string): CrxSigningKeyBlob {
  return {
    version: 1,
    extensionId: id,
    label: "My Extension ✎",
    publicKeyDerB64: "TUlJQ...",
    algorithm: "rsa2048",
    protection: { method: "password", kdfSalt: "c2FsdA==" },
    encryptedPrivateKey: "Y2lwaGVy",
    iv: "aXY=",
    createdAt: 111,
    lastUsedAt: 222,
  };
}

function passkeyBlob(id: string): CrxSigningKeyBlob {
  return {
    version: 1,
    extensionId: id,
    publicKeyDerB64: "TUlJQ...",
    algorithm: "rsa2048",
    protection: {
      method: "passkey",
      credentialId: "Y3JlZA",
      prfSalt: "cHJm",
      storedSecret: "c2VjcmV0",
    },
    encryptedPrivateKey: "Y2lwaGVy",
    iv: "aXY=",
    createdAt: 1,
    lastUsedAt: 2,
  };
}

describe("crx backup blocks", () => {
  it("round-trips a mix of password- and passkey-protected keys", () => {
    const keys = [
      passwordBlob("abcdefghijklmnopabcdefghijklmnop"),
      passkeyBlob("ponmlkjihgfedcbaponmlkjihgfedcba"),
    ];
    const parsed = parseCrxKeyBlocks(serializeCrxKeyBlocks(keys));
    expect(parsed).toEqual(keys);
  });

  it("preserves unicode labels through base64", () => {
    const [key] = parseCrxKeyBlocks(
      serializeCrxKeyBlocks([passwordBlob("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]),
    );
    expect(key.label).toBe("My Extension ✎");
  });

  it("serializes nothing for an empty list", () => {
    expect(serializeCrxKeyBlocks([])).toBe("");
  });

  it("finds CRX blocks embedded alongside other text (e.g. PGP armor)", () => {
    const bundle = `-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----\n\n${serializeCrxKeyBlocks(
      [passwordBlob("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")],
    )}`;
    expect(parseCrxKeyBlocks(bundle)).toHaveLength(1);
  });

  it("skips corrupt or non-CRX blocks without throwing", () => {
    expect(parseCrxKeyBlocks("just some random text")).toEqual([]);
    const corrupt =
      "-----BEGIN PGP TOOLS CRX SIGNING KEY-----\n!!!not base64!!!\n-----END PGP TOOLS CRX SIGNING KEY-----";
    expect(parseCrxKeyBlocks(corrupt)).toEqual([]);
  });
});
