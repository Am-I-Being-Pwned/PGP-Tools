/**
 * Known-answer tests for the at-rest wire formats.
 *
 * These layouts are not an implementation detail: they describe bytes
 * that are already sitting on users' disks, written by builds we can no
 * longer change. If an offset moves, nothing throws -- the reader simply
 * hands the wrong 16 bytes to Argon2id as a salt, the AEAD tag check
 * fails, and every stored key becomes permanently unopenable. There is
 * no version marker to catch it and no migration that could fix it after
 * the fact.
 *
 * So the layouts are pinned here as literal byte fixtures rather than
 * recomputed from the constants under test: a fixture that disagrees
 * with the code is exactly the signal we want, and one derived from the
 * code would agree with any change.
 *
 * The three formats (see `gpg-wasm/src/protected.rs`, which states the
 * same table on the Rust side):
 *
 *   password seal:  [16 salt][12 iv][ct||tag]
 *   passkey  seal:  [12 iv][ct||tag]
 *   packed return:  [u32_le json_len][json][blob]
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  unpackMetaBlob,
  unpackPasswordBlob,
  unpackPrfBlob,
} from "./protected-blob";

// The packed-return half is unpacked inside `wasm-secrets.ts` by
// functions that are deliberately not exported, so it is exercised
// through the real protect exports with only the wasm module itself
// swapped out -- the boundary the packed bytes actually cross.
const wasmStub: { module: Record<string, () => Uint8Array> } = vi.hoisted(
  () => ({ module: {} }),
);

vi.mock("../pgp/wasm-loader", () => ({
  loadWasm: () => Promise.resolve(wasmStub.module),
}));

beforeEach(() => {
  wasmStub.module = {};
});

/** `[16 salt][12 iv][5 ct]`, every byte distinct enough that a
 *  one-position slip in any boundary changes the assertion. */
// prettier-ignore
const PASSWORD_PACKED = new Uint8Array([
  // salt (16)
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  // iv (12)
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b,
  // ciphertext || tag (rest)
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
]);

/** `[12 iv][4 ct]` -- no salt: the HKDF salt is `storedSecret`, which
 *  lives beside the blob and never inside it. */
// prettier-ignore
const PRF_PACKED = new Uint8Array([
  // iv (12)
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
  0x28, 0x29, 0x2a, 0x2b,
  // ciphertext || tag (rest)
  0xe0, 0xe1, 0xe2, 0xe3,
]);

describe("password blob layout", () => {
  it("splits [16 salt][12 iv][ct] at exactly those offsets", () => {
    const { salt, iv, ct } = unpackPasswordBlob(PASSWORD_PACKED);

    expect([...salt]).toEqual([
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
      0x0c, 0x0d, 0x0e, 0x0f,
    ]);
    expect([...iv]).toEqual([
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    ]);
    expect([...ct]).toEqual([0xf0, 0xf1, 0xf2, 0xf3, 0xf4]);

    // AES-GCM's own sizes, restated so a change to either constant is
    // caught even if the fixture were regenerated.
    expect(salt).toHaveLength(16);
    expect(iv).toHaveLength(12);
  });

  it("hands back copies, not views onto the packed buffer", () => {
    // The parts outlive the packed blob (they are base64'd into the
    // stored record, and `cachePassword` reads them again after the
    // fact). A view would alias a buffer the caller is free to reuse.
    const packed = PASSWORD_PACKED.slice();
    const { salt, iv, ct } = unpackPasswordBlob(packed);
    packed.fill(0xaa);

    expect(salt[0]).toBe(0x00);
    expect(iv[0]).toBe(0x10);
    expect(ct[0]).toBe(0xf0);
  });
});

describe("prf blob layout", () => {
  it("splits [12 iv][ct] at exactly those offsets", () => {
    const { iv, ct } = unpackPrfBlob(PRF_PACKED);

    expect([...iv]).toEqual([
      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
    ]);
    expect([...ct]).toEqual([0xe0, 0xe1, 0xe2, 0xe3]);
    expect(iv).toHaveLength(12);
  });

  it("does not carry a salt -- the PRF seal has none to carry", () => {
    // Reading the PRF blob with the password layout (or vice versa) is
    // the exact confusion this asserts against: the first 16 bytes are
    // IV+ciphertext, not a KDF salt.
    expect(Object.keys(unpackPrfBlob(PRF_PACKED)).sort()).toEqual(["ct", "iv"]);
  });
});

/** `[u32_le json_len][json][blob]` -- built by hand so the length
 *  prefix's width, endianness and position are all pinned. */
function packed(meta: unknown, blob: Uint8Array): Uint8Array {
  const json = new TextEncoder().encode(JSON.stringify(meta));
  const out = new Uint8Array(4 + json.length + blob.length);
  out[0] = json.length & 0xff;
  out[1] = (json.length >> 8) & 0xff;
  out[2] = (json.length >> 16) & 0xff;
  out[3] = (json.length >> 24) & 0xff;
  out.set(json, 4);
  out.set(blob, 4 + json.length);
  return out;
}

const CRX_META = {
  extensionId: "a".repeat(32),
  publicKeyDerB64: "ZGVy",
  algorithm: "rsa2048",
};

describe("packed wasm return layout", () => {
  it("reads a little-endian u32 length, then the json, then the blob", async () => {
    const { generateCrxKeyWithPassword } = await import("../pgp/wasm");
    // Short metadata: the length fits in the low byte. The multi-byte
    // case is pinned by the next test.
    wasmStub.module.generateCrxKeyWithPassword = () =>
      packed(CRX_META, PASSWORD_PACKED);

    const result = await generateCrxKeyWithPassword(
      new Uint8Array(4),
      1024,
      1,
      1,
    );
    expect(result.meta).toEqual(CRX_META);
    expect([...result.blob]).toEqual([...PASSWORD_PACKED]);
  });

  it("reads the length as u32_le, not u16 or big-endian", async () => {
    const { generateCrxKeyWithPassword } = await import("../pgp/wasm");
    // Padding pushes the JSON past 255 bytes, so the length spills into
    // the second byte: `[0x2c, 0x01, 0x00, 0x00]` = 300. A big-endian
    // read would see 738197504; a u16 read would still work here, so
    // the trailing two zero bytes are asserted separately below.
    const meta = { ...CRX_META, label: "x".repeat(300) };
    const bytes = packed(meta, PRF_PACKED);
    const jsonLen = new TextEncoder().encode(JSON.stringify(meta)).length;
    expect(jsonLen).toBeGreaterThan(255);
    expect([...bytes.slice(0, 4)]).toEqual([
      jsonLen & 0xff,
      (jsonLen >> 8) & 0xff,
      0,
      0,
    ]);

    wasmStub.module.generateCrxKeyWithPassword = () => bytes;
    const result = await generateCrxKeyWithPassword(
      new Uint8Array(4),
      1024,
      1,
      1,
    );
    expect(result.meta).toEqual(meta);
    expect([...result.blob]).toEqual([...PRF_PACKED]);
  });

  it("unpacks a packed return that does not start at byte 0 of its buffer", async () => {
    const { generateProtectedWithPrf } = await import("../pgp/wasm");
    // wasm-bindgen hands back a view into linear memory, so `byteOffset`
    // is routinely non-zero. A `new DataView(packed.buffer)` that
    // forgets to pass the offset reads someone else's bytes as the
    // length -- silently, and only in the real extension.
    const meta = {
      publicKeyArmored: "PUB",
      keyInfo: {
        keyId: "FP",
        userIds: ["a@b.test"],
        algorithm: "ed25519",
        createdAt: 1,
        expiresAt: null,
        isPrivate: true,
        usableForEncryption: true,
        usableForSigning: true,
      },
    };
    const body = packed(meta, PRF_PACKED);
    const backing = new Uint8Array(7 + body.length);
    backing.set(body, 7);
    const view = backing.subarray(7);
    expect(view.byteOffset).toBe(7);

    wasmStub.module.generateProtectedWithPrf = () => view;
    const result = await generateProtectedWithPrf(
      { name: "a", email: "a@b.test" },
      new Uint8Array(32),
      new Uint8Array(32),
    );
    expect(result.meta).toEqual(meta);
    expect([...result.blob]).toEqual([...PRF_PACKED]);
  });

  it("round-trips packed -> unpacked -> the seal parts the store persists", async () => {
    const { generateCrxKeyWithPassword } = await import("../pgp/wasm");
    // The two layouts compose: the packed return's tail IS the seal, so
    // a change to either offset table shows up here as wrong salt/iv.
    wasmStub.module.generateCrxKeyWithPassword = () =>
      packed(CRX_META, PASSWORD_PACKED);
    const { blob } = await generateCrxKeyWithPassword(
      new Uint8Array(4),
      1024,
      1,
      1,
    );
    const { salt, iv, ct } = unpackPasswordBlob(blob);
    expect([...salt.slice(0, 2)]).toEqual([0x00, 0x01]);
    expect([...iv.slice(0, 2)]).toEqual([0x10, 0x11]);
    expect([...ct]).toEqual([0xf0, 0xf1, 0xf2, 0xf3, 0xf4]);
  });
});

/**
 * Truncation must fail AS truncation.
 *
 * `Uint8Array.slice` past the end returns a short array rather than
 * throwing, so a clipped blob used to sail through the unpackers with a
 * 3-byte "salt" and an empty IV and only fail several layers down, at the
 * AEAD tag check -- which the UI reports as a wrong password. The user
 * then goes looking for a credential problem they do not have while the
 * real fault (a half-written record, a clipped backup) goes unnamed.
 */
describe("length validation", () => {
  it("rejects a password blob too short to hold [16 salt][12 iv]", () => {
    expect(() => unpackPasswordBlob(PASSWORD_PACKED.slice(0, 27))).toThrow(
      /Malformed protected blob/,
    );
    // Exactly the header, with no ciphertext, is still malformed: there
    // is nothing to decrypt and no room for the GCM tag.
    expect(() => unpackPasswordBlob(PASSWORD_PACKED.slice(0, 28))).toThrow(
      /Malformed protected blob/,
    );
    expect(() => unpackPasswordBlob(new Uint8Array(0))).toThrow(
      /Malformed protected blob/,
    );
  });

  it("rejects a PRF blob too short to hold [12 iv]", () => {
    expect(() => unpackPrfBlob(PRF_PACKED.slice(0, 11))).toThrow(
      /Malformed protected blob/,
    );
    expect(() => unpackPrfBlob(PRF_PACKED.slice(0, 12))).toThrow(
      /Malformed protected blob/,
    );
  });

  it("still accepts the shortest well-formed blobs", () => {
    // The boundary is off-by-one sensitive in the direction that matters:
    // a real blob must not start throwing.
    expect(unpackPasswordBlob(PASSWORD_PACKED.slice(0, 29)).ct).toHaveLength(1);
    expect(unpackPrfBlob(PRF_PACKED.slice(0, 13)).ct).toHaveLength(1);
  });

  it("rejects a packed return whose length prefix runs past the buffer", () => {
    // The other truncation: the metadata header survived but its body
    // did not. Without this the TextDecoder yields a short string and
    // the failure surfaces as a JSON parse error about the metadata.
    const bytes = packed(CRX_META, PASSWORD_PACKED).slice(0, 10);
    expect(() => unpackMetaBlob(bytes)).toThrow(/exceeds/);
  });

  it("rejects a packed return with no room for the length prefix", () => {
    expect(() => unpackMetaBlob(new Uint8Array(3))).toThrow(
      /Malformed protected blob/,
    );
  });
});

