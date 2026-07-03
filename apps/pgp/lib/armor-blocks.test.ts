import { describe, expect, it } from "vitest";

import { splitArmoredKeyBlocks, splitPublicKeyBlocks } from "./armor-blocks";

function publicBlock(body: string): string {
  return `-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n${body}\n-----END PGP PUBLIC KEY BLOCK-----`;
}

function privateBlock(body: string): string {
  return `-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n${body}\n-----END PGP PRIVATE KEY BLOCK-----`;
}

describe("splitArmoredKeyBlocks", () => {
  it("splits a mixed dump into public and private blocks", () => {
    const text = [
      privateBlock("aaa"),
      publicBlock("bbb"),
      privateBlock("ccc"),
      publicBlock("ddd"),
    ].join("\n\n");
    const { publicKeys, privateKeys } = splitArmoredKeyBlocks(text);
    expect(publicKeys).toEqual([publicBlock("bbb"), publicBlock("ddd")]);
    expect(privateKeys).toEqual([privateBlock("aaa"), privateBlock("ccc")]);
  });

  it("ignores surrounding prose", () => {
    const text = `Here is my key:\n${publicBlock("xyz")}\nCheers!`;
    const { publicKeys, privateKeys } = splitArmoredKeyBlocks(text);
    expect(publicKeys).toEqual([publicBlock("xyz")]);
    expect(privateKeys).toEqual([]);
  });

  it("returns empty lists for non-armor text", () => {
    expect(splitArmoredKeyBlocks("nothing here")).toEqual({
      publicKeys: [],
      privateKeys: [],
    });
  });

  it("does not confuse private blocks for public ones", () => {
    expect(splitPublicKeyBlocks(privateBlock("aaa"))).toEqual([]);
  });

  it("is safe to call repeatedly (global regex state)", () => {
    const text = publicBlock("abc");
    expect(splitPublicKeyBlocks(text)).toHaveLength(1);
    expect(splitPublicKeyBlocks(text)).toHaveLength(1);
  });
});
