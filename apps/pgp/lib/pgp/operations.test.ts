/**
 * The marshalling around the PGP engine's decrypt results. The engine is
 * stubbed (it is not available under vitest; the Rust tests cover it);
 * what is pinned here is what becomes of the plaintext bytes on the way
 * out -- in particular that a leading byte-order mark survives, since
 * Copy and Download hand back exactly this string.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  asTextIfUtf8,
  decryptWithHandle,
  decryptWithPassword,
  openUnencrypted,
} from "./operations";

const wasm = vi.hoisted(() => ({
  decryptWithHandle: vi.fn(),
  openUnencrypted: vi.fn(),
}));
const secrets = vi.hoisted(() => ({
  decryptWithPassword: vi.fn(),
  encryptWithPassword: vi.fn(),
}));

vi.mock("./wasm", () => wasm);
vi.mock("./wasm-secrets", () => secrets);

const BOM = "\u{feff}";
const withBom = new Uint8Array([0xef, 0xbb, 0xbf, 0x68, 0x69]); // BOM + "hi"
const result = (plaintext: Uint8Array) => ({
  plaintext,
  signatureInfo: { signatureStatus: "unsigned" },
});
const input = { kind: "armored" as const, armoredMessage: "x" };

describe("decrypt results", () => {
  beforeEach(() => {
    wasm.decryptWithHandle.mockResolvedValue(result(withBom.slice()));
    wasm.openUnencrypted.mockResolvedValue(result(withBom.slice()));
    secrets.decryptWithPassword.mockResolvedValue(result(withBom.slice()));
  });

  it("keeps a leading byte-order mark on every path", async () => {
    const outputs = await Promise.all([
      decryptWithHandle({ input, keyHandle: 1 }),
      decryptWithPassword({ input, password: "pw" }),
      openUnencrypted({ input }),
    ]);
    for (const { data } of outputs) expect(data).toBe(`${BOM}hi`);
  });

  it("falls back to the bytes when the plaintext is not UTF-8", () => {
    const bytes = new Uint8Array([0xff, 0xfe, 0x00]);
    expect(asTextIfUtf8(bytes)).toBe(bytes);
    expect(asTextIfUtf8(new Uint8Array([0x6f, 0x6b]))).toBe("ok");
  });
});
