/**
 * Pins `runProtect`'s two contracts: secrets are `.fill(0)`'d on EVERY
 * exit path (each throwing path tested separately), and the stored blob
 * has exactly the persisted field set (exact match: these are on users'
 * disks). Wasm is stubbed; real crypto is covered by the Rust tests.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { generateCrxKey } from "~/lib/crx/operations";
import { fromBase64 } from "~/lib/encoding";
import type { GenerateKeyOptions } from "~/lib/pgp/types";
import type { CrxProtectFlowResult, ProtectFlowResult } from "~/lib/pgp/wasm";
import { generateAndProtect, importAndProtect } from "./protect-flow";

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

const webauthn = await vi.hoisted(async () =>
  (await import("./fake-webauthn")).fakeWebauthnPrf(),
);

vi.mock("./webauthn-prf", () => webauthn);
vi.mock("../protection/webauthn-prf", () => webauthn);

// ── fixtures ─────────────────────────────────────────────────────────

const PASSWORD = "correct horse battery";
const SOURCE_PASSPHRASE = "the imported key's own passphrase";
const CREDENTIAL_ID = "cred-id-b64url";

/** `[16 salt][12 iv][ct]` / `[12 iv][ct]` with per-section markers. */
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

/** Every buffer encoded during a test; the encoder is the only place a
 *  throwing path's buffers can be observed. */
const encoded: { text: string; bytes: Uint8Array }[] = [];

const RealTextEncoder = globalThis.TextEncoder;

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

/** Non-empty check: a secret that was never encoded must not pass. */
function expectZeroized(text: string): void {
  const buffers = buffersFor(text);
  expect(buffers.length).toBeGreaterThan(0);
  for (const bytes of buffers) {
    expect([...bytes]).toEqual(new Array(bytes.length).fill(0));
  }
}

/** Throws if wasm was never called, so that can't read as a pass. */
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
        // Live at the wasm call, scrubbed only afterwards.
        expect([...password]).toEqual([...new TextEncoder().encode(PASSWORD)]);
        captured = password;
        return Promise.resolve(pgpResult(passwordPacked()));
      },
    );

    await generateAndProtect(KEY_OPTS, {
      method: "password",
      password: PASSWORD,
    });

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
    // Caller-owned (shared across a bulk import): pinned both directions.
    const output = prfOutput();
    wasm.generateProtectedWithPrf.mockResolvedValue(pgpResult(prfPacked()));

    await generateAndProtect(KEY_OPTS, {
      method: "passkey",
      reusePasskeyCredentialId: CREDENTIAL_ID,
      prfReuse: {
        prfOutput: output,
        prfSalt: new Uint8Array(32).fill(9).buffer,
      },
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
    // The `finally` must outlast the chained cache unlock.
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

// ── sealing under the master salt ────────────────────────────────────

/** `prfSalt` changes only the ceremony's salt: the output is still ours
 *  to zero, and `prfReuse` still wins. */
describe("runProtect with a caller-supplied prfSalt", () => {
  const MASTER_SALT = new Uint8Array(32).fill(0x0c).buffer;

  it("runs the ceremony under that exact salt and persists it", async () => {
    wasm.generateProtectedWithPrf.mockResolvedValue(pgpResult(prfPacked()));

    const { blob } = await generateAndProtect(KEY_OPTS, {
      method: "passkey",
      reusePasskeyCredentialId: CREDENTIAL_ID,
      prfSalt: MASTER_SALT,
    });

    expect(webauthn.authenticateAndGetPrf).toHaveBeenCalledExactlyOnceWith(
      CREDENTIAL_ID,
      MASTER_SALT,
    );
    expect(webauthn.generatePrfSalt).not.toHaveBeenCalled();
    if (blob.protection.method !== "passkey") throw new Error("wrong method");
    expect([...fromBase64(blob.protection.prfSalt)]).toEqual(
      new Array(32).fill(0x0c),
    );
    expect(blob.protection.credentialId).toBe(CREDENTIAL_ID);
  });

  it("is ignored when prfReuse is also given -- that carries its own salt", async () => {
    wasm.generateProtectedWithPrf.mockResolvedValue(pgpResult(prfPacked()));
    const reuseSalt = new Uint8Array(32).fill(0x0d).buffer;

    const { blob } = await generateAndProtect(KEY_OPTS, {
      method: "passkey",
      reusePasskeyCredentialId: CREDENTIAL_ID,
      prfReuse: { prfOutput: prfOutput(), prfSalt: reuseSalt },
      prfSalt: MASTER_SALT,
    });

    expect(webauthn.authenticateAndGetPrf).not.toHaveBeenCalled();
    expect(webauthn.generatePrfSalt).not.toHaveBeenCalled();
    if (blob.protection.method !== "passkey") throw new Error("wrong method");
    expect([...fromBase64(blob.protection.prfSalt)]).toEqual(
      new Array(32).fill(0x0d),
    );
  });

  it("still scrubs the PRF output it obtained under the supplied salt", async () => {
    const output = prfOutput();
    webauthn.authenticateAndGetPrf.mockResolvedValue({ prfOutput: output });
    wasm.generateProtectedWithPrf.mockResolvedValue(pgpResult(prfPacked()));

    await generateAndProtect(KEY_OPTS, {
      method: "passkey",
      reusePasskeyCredentialId: CREDENTIAL_ID,
      prfSalt: MASTER_SALT,
    });

    expect([...output]).toEqual(new Array(32).fill(0));
  });
});

// ── stored blob shape ────────────────────────────────────────────────

/** Strict base64: decodes and re-encodes to the same string. */
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
    expect(isBase64(blob.protection.kdfSalt, 16)).toBe(true);
    expect(isBase64(blob.iv, 12)).toBe(true);
    expect(isBase64(blob.encryptedPrivateKey, 8)).toBe(true);
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
    expect(blob.protection).not.toHaveProperty("kdfSalt");
    // Never the PRF output itself: that would put the secret on disk.
    expect([...fromBase64(blob.protection.storedSecret)]).toEqual(
      new Array(32).fill(8),
    );
  });

  it("carries a generated key's revocation certificate onto the blob", async () => {
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
    expect([...fromBase64(blob.protection.kdfSalt)]).toEqual(
      new Array(16).fill(0x11),
    );
    expect([...fromBase64(blob.iv)]).toEqual(new Array(12).fill(0x22));
    expect([...fromBase64(blob.encryptedPrivateKey)]).toEqual(
      new Array(8).fill(0x33),
    );
  });

  it("never caches a CRX key open -- there is no handle to leak", async () => {
    // CRX keys never cache: unlocked for one signing act and dropped.
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
