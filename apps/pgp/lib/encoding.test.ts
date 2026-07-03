import { describe, expect, it } from "vitest";

import {
  fromBase64,
  fromBase64url,
  toBase64,
  toBase64url,
  unpackIvCiphertext,
} from "./encoding";

describe("base64", () => {
  it("round-trips arbitrary bytes", () => {
    const bytes = new Uint8Array([0, 1, 2, 127, 128, 254, 255]);
    expect(fromBase64(toBase64(bytes))).toEqual(bytes);
  });

  it("round-trips empty input", () => {
    expect(fromBase64(toBase64(new Uint8Array(0)))).toEqual(new Uint8Array(0));
  });

  it("accepts an ArrayBuffer input", () => {
    const bytes = new Uint8Array([10, 20, 30]);
    expect(toBase64(bytes.buffer)).toBe(toBase64(bytes));
  });

  it("matches btoa for known input", () => {
    expect(toBase64(new TextEncoder().encode("hello"))).toBe("aGVsbG8=");
  });
});

describe("base64url", () => {
  it("round-trips arbitrary bytes", () => {
    const bytes = new Uint8Array([251, 255, 190, 0, 62, 63]);
    expect(fromBase64url(toBase64url(bytes))).toEqual(bytes);
  });

  it("uses url-safe characters and no padding", () => {
    // 0xfb 0xff produces '+' and '/' and '=' in plain base64.
    const encoded = toBase64url(new Uint8Array([251, 255, 190, 255]));
    expect(encoded).not.toMatch(/[+/=]/);
  });

  it("re-pads correctly for all input lengths", () => {
    for (let len = 0; len < 8; len++) {
      const bytes = new Uint8Array(len).fill(0xab);
      expect(fromBase64url(toBase64url(bytes))).toEqual(bytes);
    }
  });
});

describe("unpackIvCiphertext", () => {
  it("splits a packed blob into 12-byte IV and ciphertext", () => {
    const packed = new Uint8Array(20).map((_, i) => i);
    const { iv, ciphertext } = unpackIvCiphertext(packed);
    expect(iv).toEqual(packed.slice(0, 12));
    expect(ciphertext).toEqual(packed.slice(12));
  });

  it("returns copies, not views into the packed buffer", () => {
    const packed = new Uint8Array(16);
    const { iv } = unpackIvCiphertext(packed);
    iv[0] = 42;
    expect(packed[0]).toBe(0);
  });
});
