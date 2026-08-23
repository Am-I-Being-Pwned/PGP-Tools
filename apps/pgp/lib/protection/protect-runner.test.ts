/**
 * The two contracts `runProtect` owes every key type: secrets are
 * `.fill(0)`'d on EVERY exit path, and the blob it assembles has exactly
 * the field names the store persists.
 *
 * Zeroization is the reason this module exists at all -- the comment at
 * the top of `protect-runner.ts` says a per-key-type copy of the
 * `.fill(0)` is a per-key-type chance to forget it. The failure it guards
 * against is not a crash: it is a plaintext passphrase left sitting in a
 * heap buffer that outlives the flow, invisible to every other test in
 * the suite. This one was a real bug -- `importAndProtect` encoded the
 * source passphrase BEFORE the weak-password gate and the WebAuthn
 * ceremony, both of which throw, so those two paths leaked it. Each
 * throwing path therefore gets its own test here rather than being
 * assumed to follow from the happy one.
 *
 * The blob shape is asserted by exact field set (not `toMatchObject`)
 * because these objects are on users' disks: a rename that only the
 * writer learns about turns every stored key into an unreadable record
 * the validator silently drops.
 *
 * Everything below the wasm boundary is stubbed -- the point is what JS
 * does with the buffers it hands over, and the real crypto is covered by
 * the Rust tests.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { GenerateKeyOptions } from "../pgp/types";
import type { CrxProtectFlowResult, ProtectFlowResult } from "../pgp/wasm";
import { fromBase64 } from "../encoding";

const wasm = vi.hoisted(() => ({
  generateProtectedWithPassword: vi.fn(),
  generateProtectedWithPrf: vi.fn(),
  protectImportedWithPassword: vi.fn(),
  protectImportedWithPrf: vi.fn(),
  unlockWithPassword: vi.fn(),
  unlockWithPrf: vi.fn(),
  generateCrxKeyWithPassword: vi.fn(),
  generateCrxKeyWithPrf: vi.fn(),
  importCrxKeyWithPassword: vi.fn(),
  importCrxKeyWithPrf: vi.fn(),
  reprotectCrxKeyWithPassword: vi.fn(),
  unlockCrxWithPassword: vi.fn(),
  unlockCrxWithPrf: vi.fn(),
  signCrxWithHandle: vi.fn(),
  dropCrxKey: vi.fn(),
  verifyCrx: vi.fn(),
  exportCrxPrivateKeyPem: vi.fn(),
  hasContactsSession: vi.fn(() => Promise.resolve(true)),
}));

vi.mock("../pgp/wasm", () => wasm);

const webauthn = vi.hoisted(() => ({
  registerPasskey: vi.fn(),
  authenticateAndGetPrf: vi.fn(),
  generatePrfSalt: vi.fn(),
  generateStoredSecret: vi.fn(),
  isWebAuthnCancel: vi.fn(() => false),
  checkPrfSupport: vi.fn(() => true),
}));

vi.mock("./webauthn-prf", () => webauthn);
vi.mock("../protection/webauthn-prf", () => webauthn);

import { generateCrxKey } from "../crx/operations";
import { generateAndProtect, importAndProtect } from "./protect-flow";

// ── fixtures ─────────────────────────────────────────────────────────

const PASSWORD = "correct horse battery";
const SOURCE_PASSPHRASE = "the imported key's own passphrase";
const CREDENTIAL_ID = "cred-id-b64url";

/** `[16 salt][12 iv][ct]` and `[12 iv][ct]`, filled with per-section
 *  markers so a mis-sliced blob shows up as the wrong bytes, not just a
 *  wrong length. */
function passwordPacked(): Uint8Array {
  const packed = new Uint8Array(16 + 12 + 8);
  packed.fill(0x11, 0, 16);
  packed.fill(0x22, 16, 28);
  packed.fill(0x33, 28);
  return packed;
}

function prfPacked(): Uint8Array {
  const packed = new Uint8Array(12 + 8);
  packed.fill(0x44, 0, 12);
  packed.fill(0x55, 12);
  return packed;
}

function pgpResult(blob: Uint8Array): ProtectFlowResult {
  return {
    blob,
    meta: {
      publicKeyArmored: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
      keyInfo: {
        keyId: "3A9E1F5C7B2D48E6",
        userIds: ["Alice <alice@example.com>"],
        algorithm: "ed25519",
        createdAt: 1,
        expiresAt: null,
        isPrivate: true,
        usableForEncryption: true,
        usableForSigning: true,
      },
    },
  };
}

function crxResult(blob: Uint8Array): CrxProtectFlowResult {
  return {
    blob,
    meta: {
      extensionId: "a".repeat(32),
      publicKeyDerB64: "ZGVyLWJ5dGVz",
      algorithm: "rsa2048",
    },
  };
}

const KEY_OPTS: GenerateKeyOptions = {
  name: "Alice",
  email: "alice@example.com",
  type: "ecc",
};

/**
 * Every `Uint8Array` any code under test produced from a given string.
 *
 * The leaking buffers live entirely inside the flow -- a throwing path
 * never hands them to a stub we could capture them from -- so the
 * encoder itself is the observation point.
 */
const encoded: { text: string; bytes: Uint8Array }[] = [];

const RealTextEncoder = globalThis.TextEncoder;

/** Records every buffer produced, then behaves exactly as the real one.
 *  Installed as the global for the duration of each test, so the code
 *  under test keeps writing `new TextEncoder()` as it always has. */
class RecordingTextEncoder extends RealTextEncoder {
  override encode(input?: string): Uint8Array<ArrayBuffer> {
    const bytes = super.encode(input);
    encoded.push({ text: input ?? "", bytes });
    return bytes;
  }
}

function buffersFor(text: string): Uint8Array[] {
  return encoded.filter((e) => e.text === text).map((e) => e.bytes);
}

/** Asserts the buffer both existed and was scrubbed -- an assertion over
 *  an empty list would pass for a secret that was never encoded. */
function expectZeroized(text: string): void {
  const buffers = buffersFor(text);
  expect(buffers.length).toBeGreaterThan(0);
  for (const bytes of buffers) {
    expect([...bytes]).toEqual(new Array(bytes.length).fill(0));
  }
}

/** Asserts a buffer the wasm stub captured is now all zeros. Throws
 *  rather than asserting on `undefined`, so "wasm was never called" can
 *  never read as a pass. */
function expectScrubbed(bytes: Uint8Array | undefined): void {
  if (!bytes) throw new Error("the wasm stub captured no buffer");
  expect(bytes.length).toBeGreaterThan(0);
  expect([...bytes]).toEqual(new Array(bytes.length).fill(0));
}

/** A live PRF output the caller owns, distinguishable from zeros. */
function prfOutput(): Uint8Array {
  return new Uint8Array(32).fill(0x77);
}

beforeEach(() => {
  vi.clearAllMocks();
  encoded.length = 0;

  vi.stubGlobal("TextEncoder", RecordingTextEncoder);

  webauthn.generatePrfSalt.mockReturnValue(new Uint8Array(32).fill(9).buffer);
  webauthn.generateStoredSecret.mockReturnValue(
    new Uint8Array(32).fill(8).buffer,
  );
  webauthn.registerPasskey.mockResolvedValue({
    credentialId: CREDENTIAL_ID,
    prfEnabled: true,
  });
  webauthn.authenticateAndGetPrf.mockResolvedValue({
    prfOutput: prfOutput(),
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

// ── zeroization on every exit path ───────────────────────────────────

describe("runProtect zeroization", () => {
  it("scrubs the password after a successful protect", async () => {
    let captured: Uint8Array | undefined;
    wasm.generateProtectedWithPassword.mockImplementation(
      (_opts: string, password: Uint8Array) => {
        // Snapshot proves the bytes were LIVE at the wasm call and only
        // scrubbed afterwards -- a `.fill(0)` before the call would
        // "pass" a plain zero check while breaking every unlock.
        expect([...password]).toEqual([
          ...new TextEncoder().encode(PASSWORD),
        ]);
        captured = password;
        return Promise.resolve(pgpResult(passwordPacked()));
      },
    );

    await generateAndProtect(KEY_OPTS, { method: "password", password: PASSWORD });

    expectScrubbed(captured);
  });

  it("scrubs the password when the wasm call throws", async () => {
    let captured: Uint8Array | undefined;
    wasm.generateProtectedWithPassword.mockImplementation(
      (_opts: string, password: Uint8Array) => {
        captured = password;
        return Promise.reject(new Error("wasm exploded"));
      },
    );

    await expect(
      generateAndProtect(KEY_OPTS, { method: "password", password: PASSWORD }),
    ).rejects.toThrow("wasm exploded");
    expectScrubbed(captured);
  });

  it("scrubs the imported key's source passphrase when the weak-password gate rejects", async () => {
    // The regression: `importAndProtect` encodes the source passphrase
    // first, and `assertStrongPassword` throws before wasm is reached.
    await expect(
      importAndProtect("ARMOR", SOURCE_PASSPHRASE, {
        method: "password",
        password: "short",
      }),
    ).rejects.toThrow(/at least 8 characters/);

    expect(wasm.protectImportedWithPassword).not.toHaveBeenCalled();
    expectZeroized(SOURCE_PASSPHRASE);
  });

  it("scrubs the source passphrase when the WebAuthn ceremony throws", async () => {
    // The passkey branch reaches the authenticator before wasm, and a
    // user pressing Escape is the common case, not the rare one.
    webauthn.authenticateAndGetPrf.mockRejectedValue(
      new Error("NotAllowedError"),
    );

    await expect(
      importAndProtect("ARMOR", SOURCE_PASSPHRASE, {
        method: "passkey",
        reusePasskeyCredentialId: CREDENTIAL_ID,
      }),
    ).rejects.toThrow("NotAllowedError");

    expect(wasm.protectImportedWithPrf).not.toHaveBeenCalled();
    expectZeroized(SOURCE_PASSPHRASE);
  });

  it("scrubs the source passphrase and the password together on the happy path", async () => {
    wasm.protectImportedWithPassword.mockResolvedValue(
      pgpResult(passwordPacked()),
    );

    await importAndProtect("ARMOR", SOURCE_PASSPHRASE, {
      method: "password",
      password: PASSWORD,
    });

    expectZeroized(SOURCE_PASSPHRASE);
    expectZeroized(PASSWORD);
  });

  it("scrubs a PRF output it obtained itself, even when wasm throws", async () => {
    const output = prfOutput();
    webauthn.authenticateAndGetPrf.mockResolvedValue({ prfOutput: output });
    wasm.generateProtectedWithPrf.mockRejectedValue(new Error("wasm exploded"));

    await expect(
      generateAndProtect(KEY_OPTS, {
        method: "passkey",
        reusePasskeyCredentialId: CREDENTIAL_ID,
      }),
    ).rejects.toThrow("wasm exploded");

    expect([...output]).toEqual(new Array(32).fill(0));
  });

  it("leaves a caller-owned (reused) PRF output alone", async () => {
    // One ceremony protects several keys during a bulk import; zeroizing
    // here would break every blob after the first. Ownership is the
    // documented contract, so it is pinned in both directions.
    const output = prfOutput();
    wasm.generateProtectedWithPrf.mockResolvedValue(pgpResult(prfPacked()));

    await generateAndProtect(KEY_OPTS, {
      method: "passkey",
      reusePasskeyCredentialId: CREDENTIAL_ID,
      prfReuse: { prfOutput: output, prfSalt: new Uint8Array(32).fill(9).buffer },
    });

    expect([...output]).toEqual(new Array(32).fill(0x77));
    expect(webauthn.authenticateAndGetPrf).not.toHaveBeenCalled();
  });

  it("leaves a caller-owned PRF output alone when wasm throws", async () => {
    const output = prfOutput();
    wasm.generateProtectedWithPrf.mockRejectedValue(new Error("wasm exploded"));

    await expect(
      generateAndProtect(KEY_OPTS, {
        method: "passkey",
        reusePasskeyCredentialId: CREDENTIAL_ID,
        prfReuse: {
          prfOutput: output,
          prfSalt: new Uint8Array(32).fill(9).buffer,
        },
      }),
    ).rejects.toThrow("wasm exploded");

    expect([...output]).toEqual(new Array(32).fill(0x77));
  });

  it("scrubs the password even when the cached unlock throws", async () => {
    // `cache: true` chains an unlock while the bytes are still live --
    // the one place the `finally` has to outlast a second async call.
    let captured: Uint8Array | undefined;
    wasm.generateProtectedWithPassword.mockImplementation(
      (_opts: string, password: Uint8Array) => {
        captured = password;
        return Promise.resolve(pgpResult(passwordPacked()));
      },
    );
    wasm.unlockWithPassword.mockRejectedValue(new Error("unlock failed"));

    await expect(
      generateAndProtect(KEY_OPTS, {
        method: "password",
        password: PASSWORD,
        cache: true,
      }),
    ).rejects.toThrow("unlock failed");
    expectScrubbed(captured);
  });
});

// ── stored blob shape ────────────────────────────────────────────────

/** Decodes without throwing, and re-encodes to the same string -- a
 *  field that quietly became hex or base64url fails both halves. */
function isBase64(value: unknown, expectedLength?: number): boolean {
  if (typeof value !== "string") return false;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return false;
  try {
    const bytes = fromBase64(value);
    return expectedLength === undefined || bytes.length === expectedLength;
  } catch {
    return false;
  }
}

describe("ProtectedKeyBlob shape", () => {
  it("persists exactly these fields under a password", async () => {
    wasm.generateProtectedWithPassword.mockResolvedValue(
      pgpResult(passwordPacked()),
    );

    const { blob } = await generateAndProtect(KEY_OPTS, {
      method: "password",
      password: PASSWORD,
    });

    expect(Object.keys(blob).sort()).toEqual([
      "algorithm",
      "createdAt",
      "encryptedPrivateKey",
      "iv",
      "keyId",
      "lastUsedAt",
      "protection",
      "publicKeyArmored",
      "userIds",
      "version",
    ]);
    expect(blob.version).toBe(1);
    if (blob.protection.method !== "password") throw new Error("wrong method");
    expect(Object.keys(blob.protection).sort()).toEqual(["kdfSalt", "method"]);
    // 16-byte salt, 12-byte IV: the seal's own sizes, surviving the
    // unpack and the base64 round-trip.
    expect(isBase64(blob.protection.kdfSalt, 16)).toBe(true);
    expect(isBase64(blob.iv, 12)).toBe(true);
    expect(isBase64(blob.encryptedPrivateKey, 8)).toBe(true);
    // Salt, IV and ciphertext must not be confused for one another.
    expect([...fromBase64(blob.protection.kdfSalt)]).toEqual(
      new Array(16).fill(0x11),
    );
    expect([...fromBase64(blob.iv)]).toEqual(new Array(12).fill(0x22));
    expect([...fromBase64(blob.encryptedPrivateKey)]).toEqual(
      new Array(8).fill(0x33),
    );
  });

  it("persists exactly these fields under a passkey", async () => {
    wasm.generateProtectedWithPrf.mockResolvedValue(pgpResult(prfPacked()));

    const { blob } = await generateAndProtect(KEY_OPTS, {
      method: "passkey",
      reusePasskeyCredentialId: CREDENTIAL_ID,
    });

    expect(Object.keys(blob).sort()).toEqual([
      "algorithm",
      "createdAt",
      "encryptedPrivateKey",
      "iv",
      "keyId",
      "lastUsedAt",
      "protection",
      "publicKeyArmored",
      "userIds",
      "version",
    ]);
    expect(Object.keys(blob.protection).sort()).toEqual([
      "credentialId",
      "method",
      "prfSalt",
      "storedSecret",
    ]);
    if (blob.protection.method !== "passkey") throw new Error("wrong method");
    expect(blob.protection.credentialId).toBe(CREDENTIAL_ID);
    expect(isBase64(blob.protection.prfSalt, 32)).toBe(true);
    expect(isBase64(blob.protection.storedSecret, 32)).toBe(true);
    expect(isBase64(blob.iv, 12)).toBe(true);
    // No `kdfSalt` on this branch: there is no password to derive from,
    // and a reader that found one would derive the wrong key.
    expect(blob.protection).not.toHaveProperty("kdfSalt");
    // The stored secret is a fresh per-blob HKDF salt, never the PRF
    // output itself -- which would put the secret on disk.
    expect([...fromBase64(blob.protection.storedSecret)]).toEqual(
      new Array(32).fill(8),
    );
  });

  it("carries a generated key's revocation certificate onto the blob", async () => {
    // Optional and only sometimes present, so it is easy to drop in a
    // refactor -- and its absence is only noticed the day a user needs
    // to revoke a key they can no longer unlock.
    const result = pgpResult(passwordPacked());
    result.meta.revocationCertificate = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
    result.meta.keyInfo.securityWarning = "SHA-1 binding signature";
    wasm.generateProtectedWithPassword.mockResolvedValue(result);

    const { blob } = await generateAndProtect(KEY_OPTS, {
      method: "password",
      password: PASSWORD,
    });
    expect(blob.revocationCertificate).toBe(result.meta.revocationCertificate);
    expect(blob.securityWarning).toBe("SHA-1 binding signature");
  });
});

describe("CrxSigningKeyBlob shape", () => {
  it("persists exactly these fields, sharing the seal layout with PGP", async () => {
    wasm.generateCrxKeyWithPassword.mockResolvedValue(
      crxResult(passwordPacked()),
    );

    const blob = await generateCrxKey(
      { method: "password", password: PASSWORD },
      "My Extension",
    );

    expect(Object.keys(blob).sort()).toEqual([
      "algorithm",
      "createdAt",
      "encryptedPrivateKey",
      "extensionId",
      "iv",
      "label",
      "lastUsedAt",
      "protection",
      "publicKeyDerB64",
      "version",
    ]);
    expect(blob.version).toBe(1);
    expect(blob.label).toBe("My Extension");
    if (blob.protection.method !== "password") throw new Error("wrong method");
    expect(Object.keys(blob.protection).sort()).toEqual(["kdfSalt", "method"]);
    // Same [16 salt][12 iv][ct] split as the keyring: one layout, two
    // key types. If these diverge, the shared unpacker is wrong for one.
    expect([...fromBase64(blob.protection.kdfSalt)]).toEqual(
      new Array(16).fill(0x11),
    );
    expect([...fromBase64(blob.iv)]).toEqual(new Array(12).fill(0x22));
    expect([...fromBase64(blob.encryptedPrivateKey)]).toEqual(
      new Array(8).fill(0x33),
    );
  });

  it("never caches a CRX key open -- there is no handle to leak", async () => {
    // `crxSpec` deliberately omits the `cache*` hooks; a CRX key is
    // unlocked for one signing act and dropped.
    wasm.generateCrxKeyWithPrf.mockResolvedValue(crxResult(prfPacked()));

    const blob = await generateCrxKey({
      method: "passkey",
      reusePasskeyCredentialId: CREDENTIAL_ID,
    });

    expect(wasm.unlockCrxWithPrf).not.toHaveBeenCalled();
    expect(blob.protection.method).toBe("passkey");
    expect(blob.label).toBeUndefined();
  });
});
