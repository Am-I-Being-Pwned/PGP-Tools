import { describe, expect, it } from "vitest";

import type { CrxSigningKeyBlob } from "./types";
import {
  MAX_CRX_BLOCKS,
  parseCrxKeyBlocks,
  serializeCrxKeyBlocks,
} from "./backup";

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

describe("parseCrxKeyBlocks: hostile shapes stay linear", () => {
  const BEGIN = "-----BEGIN PGP TOOLS CRX SIGNING KEY-----";
  const END = "-----END PGP TOOLS CRX SIGNING KEY-----";
  // The regex this replaced took ~28 s on the first shape: every BEGIN
  // with no END after it retried the lazy body against the whole rest.
  const shapes: Record<string, string> = {
    "many BEGINs with whitespace, no END":
      `${BEGIN}\n${" ".repeat(200)}\n`.repeat(2000),
    "many BEGINs, one END at the very end":
      `${BEGIN} ${"QUJD".repeat(20)}\n`.repeat(3000) + END,
    "many ENDs, no BEGIN": `${END}\n`.repeat(5000),
    "one BEGIN, a huge whitespace body": `${BEGIN}${" ".repeat(500_000)}`,
  };

  it.each(Object.entries(shapes))("%s", (_name, input) => {
    expect(input.length).toBeGreaterThan(100_000);
    const started = performance.now();
    expect(parseCrxKeyBlocks(input)).toEqual([]);
    expect(performance.now() - started).toBeLessThan(500);
  });

  it("reads a whole block after a torn one, not the torn one's text", () => {
    const good = serializeCrxKeyBlocks([
      passwordBlob("cccccccccccccccccccccccccccccccc"),
    ]);
    expect(
      parseCrxKeyBlocks(`${BEGIN}\ntorn, never closed\n${good}`),
    ).toHaveLength(1);
  });

  it("reads at most MAX_CRX_BLOCKS blocks", () => {
    const one = serializeCrxKeyBlocks([
      passwordBlob("dddddddddddddddddddddddddddddddd"),
    ]);
    const many = Array.from({ length: MAX_CRX_BLOCKS + 5 }, () => one).join(
      "\n",
    );
    expect(parseCrxKeyBlocks(many)).toHaveLength(MAX_CRX_BLOCKS);
  });
});
