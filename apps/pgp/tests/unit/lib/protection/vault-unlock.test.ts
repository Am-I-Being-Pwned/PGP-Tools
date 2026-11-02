/**
 * "Unlock keys when the vault unlocks" bookkeeping (SECURITY.md §14).
 * Pins: eligibility is exactly same credential AND salt; SSH/PGP dispatch
 * (separate AAD prefix and store); the re-sealed parts' shape; the
 * identity check (a mismatched fingerprint would destroy the entry); and
 * that the shared PRF output is never zeroed here. Wasm is stubbed.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import { fromBase64, toBase64 } from "~/lib/encoding";
import {
  isSealedUnderMaster,
  masterPasskeyOf,
  needsMasterReseal,
  openWithMasterPrf,
  partitionByMasterSeal,
  resealUnderMaster,
} from "~/lib/protection/vault-unlock";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import type { MasterProtection } from "~/lib/storage/master-protection";

const wasm = vi.hoisted(() => ({
  unlockWithPrf: vi.fn(),
  unlockSshIdentityWithPrf: vi.fn(),
  reprotectKeyWithPrf: vi.fn(),
  reprotectSshIdentityWithPrf: vi.fn(),
}));

vi.mock("~/lib/pgp/wasm", () => wasm);

const webauthn = vi.hoisted(() => ({
  generateStoredSecret: vi.fn(),
}));

vi.mock("~/lib/protection/webauthn-prf", () => webauthn);

// ── fixtures ─────────────────────────────────────────────────────────

const MASTER_CREDENTIAL = "master-cred-b64url";
const OTHER_CREDENTIAL = "other-cred-b64url";
const MASTER_SALT = toBase64(new Uint8Array(32).fill(0x01));
const OTHER_SALT = toBase64(new Uint8Array(32).fill(0x02));

const MASTER = { credentialId: MASTER_CREDENTIAL, prfSalt: MASTER_SALT };

const CIPHERTEXT = new Uint8Array(8).fill(0x33);
const IV = new Uint8Array(12).fill(0x22);
const STORED_SECRET = new Uint8Array(32).fill(0x08);

function passkeyBlob(
  overrides: Partial<ProtectedKeyBlob> = {},
  protection: Partial<
    Extract<ProtectedKeyBlob["protection"], { method: "passkey" }>
  > = {},
): ProtectedKeyBlob {
  return {
    version: 1,
    keyId: "3A9E1F5C7B2D48E6",
    userIds: ["Alice <alice@example.com>"],
    algorithm: "ed25519",
    publicKeyArmored: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
    protection: {
      method: "passkey",
      credentialId: MASTER_CREDENTIAL,
      prfSalt: MASTER_SALT,
      storedSecret: toBase64(STORED_SECRET),
      ...protection,
    },
    encryptedPrivateKey: toBase64(CIPHERTEXT),
    iv: toBase64(IV),
    createdAt: 1,
    lastUsedAt: 2,
    ...overrides,
  };
}

function passwordBlob(
  overrides: Partial<ProtectedKeyBlob> = {},
): ProtectedKeyBlob {
  return passkeyBlob({
    keyId: "PASSWORD-KEY",
    protection: {
      method: "password",
      kdfSalt: toBase64(new Uint8Array(16).fill(0x11)),
    },
    ...overrides,
  });
}

/** `[12 iv][ct]` as the reprotect exports hand it back. */
function prfPacked(): Uint8Array {
  const packed = new Uint8Array(12 + 8);
  packed.fill(0x44, 0, 12);
  packed.fill(0x55, 12);
  return packed;
}

function resealed(keyId = "3A9E1F5C7B2D48E6") {
  return { meta: { keyId }, blob: prfPacked() };
}

/** A live PRF output, distinguishable from zeros. */
function prfOutput(): Uint8Array {
  return new Uint8Array(32).fill(0x77);
}

beforeEach(() => {
  vi.clearAllMocks();
  webauthn.generateStoredSecret.mockReturnValue(
    new Uint8Array(32).fill(0x09).buffer,
  );
});

// ── eligibility ──────────────────────────────────────────────────────

describe("masterPasskeyOf", () => {
  it("is null when there is no master protection", () => {
    expect(masterPasskeyOf(null)).toBeNull();
  });

  it("is null for a password master -- there is no PRF output to reuse", () => {
    const mp: MasterProtection = {
      method: "password",
      kdfSalt: "c2FsdA==",
      encryptedCanary: "Y2FuYXJ5",
      canaryIv: "aXY=",
    };
    expect(masterPasskeyOf(mp)).toBeNull();
  });

  it("carries exactly the two public halves of a passkey master", () => {
    const mp: MasterProtection = {
      method: "passkey",
      credentialId: MASTER_CREDENTIAL,
      prfSalt: MASTER_SALT,
      storedSecret: "bm90LXRoaXM=",
    };
    // The master's storedSecret is the VAULT's HKDF salt; never copied.
    expect(masterPasskeyOf(mp)).toEqual(MASTER);
  });
});

describe("isSealedUnderMaster", () => {
  it("is true only when credential AND salt both match", () => {
    expect(isSealedUnderMaster(passkeyBlob(), MASTER)).toBe(true);
  });

  it("is false for a password blob", () => {
    expect(isSealedUnderMaster(passwordBlob(), MASTER)).toBe(false);
  });

  it("is false for a blob on a different passkey", () => {
    const blob = passkeyBlob({}, { credentialId: OTHER_CREDENTIAL });
    expect(isSealedUnderMaster(blob, MASTER)).toBe(false);
  });

  it("is false for the master passkey under its own per-key salt", () => {
    // Same credential, own salt: a different PRF output.
    const blob = passkeyBlob({}, { prfSalt: OTHER_SALT });
    expect(isSealedUnderMaster(blob, MASTER)).toBe(false);
  });
});

describe("partitionByMasterSeal", () => {
  it("splits into eligible and ineligible, preserving order within each", () => {
    const e1 = passkeyBlob({ keyId: "E1" });
    const i1 = passwordBlob({ keyId: "I1" });
    const e2 = passkeyBlob({ keyId: "E2", kind: "ssh" });
    const i2 = passkeyBlob({ keyId: "I2" }, { prfSalt: OTHER_SALT });
    const e3 = passkeyBlob({ keyId: "E3" });

    const { eligible, ineligible } = partitionByMasterSeal(
      [e1, i1, e2, i2, e3],
      MASTER,
    );

    expect(eligible).toEqual([e1, e2, e3]);
    expect(ineligible).toEqual([i1, i2]);
  });

  it("returns two empty buckets for an empty keyring", () => {
    expect(partitionByMasterSeal([], MASTER)).toEqual({
      eligible: [],
      ineligible: [],
    });
  });
});

// ── unlock ───────────────────────────────────────────────────────────

describe("openWithMasterPrf", () => {
  it("opens a PGP blob through unlockWithPrf with the decoded seal", async () => {
    wasm.unlockWithPrf.mockResolvedValue(7);
    const output = prfOutput();

    await expect(openWithMasterPrf(passkeyBlob(), output)).resolves.toBe(7);

    expect(wasm.unlockWithPrf).toHaveBeenCalledExactlyOnceWith(
      CIPHERTEXT,
      IV,
      output,
      STORED_SECRET,
      "3A9E1F5C7B2D48E6",
    );
    expect(wasm.unlockSshIdentityWithPrf).not.toHaveBeenCalled();
  });

  it("opens an SSH blob through unlockSshIdentityWithPrf", async () => {
    wasm.unlockSshIdentityWithPrf.mockResolvedValue(3);
    const output = prfOutput();
    const blob = passkeyBlob({ keyId: "SHA256:abc", kind: "ssh" });

    await expect(openWithMasterPrf(blob, output)).resolves.toBe(3);

    expect(wasm.unlockSshIdentityWithPrf).toHaveBeenCalledExactlyOnceWith(
      CIPHERTEXT,
      IV,
      output,
      STORED_SECRET,
      "SHA256:abc",
    );
    expect(wasm.unlockWithPrf).not.toHaveBeenCalled();
  });

  it("rejects a password blob before reaching wasm", async () => {
    await expect(
      openWithMasterPrf(passwordBlob(), prfOutput()),
    ).rejects.toThrow("not passkey-protected");

    expect(wasm.unlockWithPrf).not.toHaveBeenCalled();
    expect(wasm.unlockSshIdentityWithPrf).not.toHaveBeenCalled();
  });

  it("leaves the caller-owned PRF output alone", async () => {
    // One ceremony, many keys: the same output opens the next blob.
    wasm.unlockWithPrf.mockResolvedValue(7);
    const output = prfOutput();

    await openWithMasterPrf(passkeyBlob(), output);

    expect([...output]).toEqual(new Array(32).fill(0x77));
  });
});

// ── who moves over by itself ─────────────────────────────────────────

describe("needsMasterReseal", () => {
  it("is true for the master credential with a different salt", () => {
    expect(
      needsMasterReseal(passkeyBlob({}, { prfSalt: OTHER_SALT }), MASTER),
    ).toBe(true);
  });

  it("is false for a key already sealed under the master", () => {
    expect(needsMasterReseal(passkeyBlob(), MASTER)).toBe(false);
  });

  it("is false for another passkey, even with the master salt", () => {
    expect(
      needsMasterReseal(
        passkeyBlob({}, { credentialId: OTHER_CREDENTIAL }),
        MASTER,
      ),
    ).toBe(false);
  });

  it("is false for a password key", () => {
    expect(needsMasterReseal(passwordBlob(), MASTER)).toBe(false);
  });
});

// ── re-seal ──────────────────────────────────────────────────────────

describe("resealUnderMaster", () => {
  it("re-seals a PGP handle through reprotectKeyWithPrf", async () => {
    wasm.reprotectKeyWithPrf.mockResolvedValue(resealed());
    const output = prfOutput();

    await resealUnderMaster(passkeyBlob(), 7, MASTER, output);

    expect(wasm.reprotectKeyWithPrf).toHaveBeenCalledExactlyOnceWith(
      7,
      output,
      new Uint8Array(32).fill(0x09),
    );
    expect(wasm.reprotectSshIdentityWithPrf).not.toHaveBeenCalled();
  });

  it("re-seals an SSH handle through reprotectSshIdentityWithPrf", async () => {
    wasm.reprotectSshIdentityWithPrf.mockResolvedValue(resealed("SHA256:abc"));
    const output = prfOutput();

    await resealUnderMaster(
      passkeyBlob({ keyId: "SHA256:abc", kind: "ssh" }),
      3,
      MASTER,
      output,
    );

    expect(wasm.reprotectSshIdentityWithPrf).toHaveBeenCalledExactlyOnceWith(
      3,
      output,
      new Uint8Array(32).fill(0x09),
    );
    expect(wasm.reprotectKeyWithPrf).not.toHaveBeenCalled();
  });

  it("returns exactly the three sealing fields, under the master credential + salt", async () => {
    // Only these three: the store applies them under its own lock.
    wasm.reprotectSshIdentityWithPrf.mockResolvedValue(resealed("SHA256:abc"));
    const input = passkeyBlob(
      { keyId: "SHA256:abc", kind: "ssh", alias: "work laptop" },
      { credentialId: OTHER_CREDENTIAL, prfSalt: OTHER_SALT },
    );

    const parts = await resealUnderMaster(input, 3, MASTER, prfOutput());

    expect(Object.keys(parts).sort()).toEqual([
      "encryptedPrivateKey",
      "iv",
      "protection",
    ]);
    expect(parts.protection).toEqual({
      method: "passkey",
      credentialId: MASTER_CREDENTIAL,
      prfSalt: MASTER_SALT,
      storedSecret: toBase64(new Uint8Array(32).fill(0x09)),
    });
    expect([...fromBase64(parts.iv)]).toEqual(new Array(12).fill(0x44));
    expect([...fromBase64(parts.encryptedPrivateKey)]).toEqual(
      new Array(8).fill(0x55),
    );
    // Input not mutated: the caller holds it until the write lands.
    expect(
      input.protection.method === "passkey" && input.protection.prfSalt,
    ).toBe(OTHER_SALT);
  });

  it("refuses a handle whose key is not the keyring entry's", async () => {
    // Writing key Y's ciphertext under key X would destroy X.
    wasm.reprotectKeyWithPrf.mockResolvedValue(resealed("SOMEOTHERKEY"));

    await expect(
      resealUnderMaster(passkeyBlob(), 7, MASTER, prfOutput()),
    ).rejects.toThrow(/does not match/);
  });

  it("re-seals a password-protected key too", async () => {
    wasm.reprotectKeyWithPrf.mockResolvedValue(resealed("PASSWORD-KEY"));

    const parts = await resealUnderMaster(
      passwordBlob(),
      7,
      MASTER,
      prfOutput(),
    );

    expect(parts.protection.method).toBe("passkey");
    expect(parts.protection).not.toHaveProperty("kdfSalt");
  });

  it("generates a fresh stored secret per re-seal", async () => {
    // Two blobs off one PRF output must still get distinct AES keys.
    wasm.reprotectKeyWithPrf
      .mockResolvedValueOnce(resealed("A"))
      .mockResolvedValueOnce(resealed("B"));
    webauthn.generateStoredSecret
      .mockReturnValueOnce(new Uint8Array(32).fill(0x0a).buffer)
      .mockReturnValueOnce(new Uint8Array(32).fill(0x0b).buffer);
    const output = prfOutput();

    const a = await resealUnderMaster(
      passkeyBlob({ keyId: "A" }),
      1,
      MASTER,
      output,
    );
    const b = await resealUnderMaster(
      passkeyBlob({ keyId: "B" }),
      2,
      MASTER,
      output,
    );

    expect(webauthn.generateStoredSecret).toHaveBeenCalledTimes(2);
    if (a.protection.method !== "passkey") throw new Error("wrong method");
    if (b.protection.method !== "passkey") throw new Error("wrong method");
    expect([...fromBase64(a.protection.storedSecret)]).toEqual(
      new Array(32).fill(0x0a),
    );
    expect([...fromBase64(b.protection.storedSecret)]).toEqual(
      new Array(32).fill(0x0b),
    );
  });

  it("leaves the caller-owned PRF output alone", async () => {
    wasm.reprotectKeyWithPrf.mockResolvedValue(resealed());
    const output = prfOutput();

    await resealUnderMaster(passkeyBlob(), 7, MASTER, output);

    expect([...output]).toEqual(new Array(32).fill(0x77));
  });
});
