/**
 * The bookkeeping half of "unlock keys when the vault unlocks"
 * (SECURITY.md §14). The crypto is the existing PRF seal, so the things
 * that can go wrong here are all JS-side:
 *
 *  - eligibility that is LOOSER than "same credential AND same salt".
 *    A blob on the master passkey but its own salt cannot be opened by
 *    the vault's PRF output; handing it to the batch would fail the
 *    AEAD check, which the UI reports as a wrong credential. A blob on
 *    a different passkey must never even reach wasm off this output;
 *  - the SSH / PGP dispatch. An SSH identity is sealed under its own AAD
 *    prefix and lives in SSH_KEY_STORE; opening it through the PGP
 *    export fails, and re-sealing it through the PGP export would read
 *    a PGP handle at that index;
 *  - the re-sealed parts' shape. Only the three sealing fields come
 *    back (the store applies them under its lock, `replaceKeyProtection`),
 *    so the IV / ciphertext split and the master credential + salt must
 *    be exactly right -- there is no other copy to fall back on;
 *  - the identity check. Wasm reports the fingerprint the new AAD was
 *    derived from; writing a result whose fingerprint is not the
 *    keyring entry's would destroy that entry;
 *  - zeroing the PRF output. It is deliberately shared across every
 *    blob in the batch, so a `.fill(0)` here would break the second one.
 *
 * Everything below the wasm boundary is stubbed; the seal round trip is
 * covered by the Rust tests.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ProtectedKeyBlob } from "../storage/keyring";
import type { MasterProtection } from "../storage/master-protection";
import { fromBase64, toBase64 } from "../encoding";
import {
  isSealedUnderMaster,
  masterPasskeyOf,
  needsMasterReseal,
  openWithMasterPrf,
  partitionByMasterSeal,
  resealUnderMaster,
} from "./vault-unlock";

const wasm = vi.hoisted(() => ({
  unlockWithPrf: vi.fn(),
  unlockSshIdentityWithPrf: vi.fn(),
  reprotectKeyWithPrf: vi.fn(),
  reprotectSshIdentityWithPrf: vi.fn(),
}));

vi.mock("../pgp/wasm", () => wasm);

const webauthn = vi.hoisted(() => ({
  generateStoredSecret: vi.fn(),
}));

vi.mock("./webauthn-prf", () => webauthn);

// ── fixtures ─────────────────────────────────────────────────────────

const MASTER_CREDENTIAL = "master-cred-b64url";
const OTHER_CREDENTIAL = "other-cred-b64url";
const MASTER_SALT = toBase64(new Uint8Array(32).fill(0x01));
const OTHER_SALT = toBase64(new Uint8Array(32).fill(0x02));

const MASTER = { credentialId: MASTER_CREDENTIAL, prfSalt: MASTER_SALT };

/** Ciphertext, IV and stored secret with per-section markers, so an
 *  argument handed to wasm in the wrong position shows up as the wrong
 *  bytes, not just the wrong length. */
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

/** The unpacked reseal result: the identity wasm derived the AAD from,
 *  plus the bare blob. Defaults to the PGP fixture's keyId. */
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
    // The master's own storedSecret is the VAULT's HKDF salt; it has no
    // business in a key blob and must not ride along.
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
    // Every single-key import before this feature: same authenticator,
    // but a random salt, so a different PRF output. Sharing a credential
    // is not enough.
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
  // The key's OWN prompt can carry the master salt as the second PRF
  // evaluation only when it is the same authenticator secret, i.e. the
  // same credential. Anything else is left alone.
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
    // Nothing else comes back on purpose: the store swaps these three in
    // under its own lock (`replaceKeyProtection`) so a stale snapshot of
    // alias / lastUsedAt / revocation cert is never written back.
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
    // `[12 iv][ct]` split the same way the protect path splits it; IV
    // and ciphertext must not be confused for one another.
    expect([...fromBase64(parts.iv)]).toEqual(new Array(12).fill(0x44));
    expect([...fromBase64(parts.encryptedPrivateKey)]).toEqual(
      new Array(8).fill(0x55),
    );
    // The input is not mutated: the caller still holds the old blob
    // until the store write lands.
    expect(
      input.protection.method === "passkey" && input.protection.prfSalt,
    ).toBe(OTHER_SALT);
  });

  it("refuses a handle whose key is not the keyring entry's", async () => {
    // Wasm derives the AAD from the key the HANDLE holds and reports
    // that identity. Writing this result under `blob.keyId` would store
    // key Y's ciphertext (AAD fpr(Y)) under key X: X destroyed, Y's copy
    // unopenable. Handles are never reused, so this is not reachable
    // today -- the refusal is what keeps that a property.
    wasm.reprotectKeyWithPrf.mockResolvedValue(resealed("SOMEOTHERKEY"));

    await expect(
      resealUnderMaster(passkeyBlob(), 7, MASTER, prfOutput()),
    ).rejects.toThrow(/does not match/);
  });

  it("re-seals a password-protected key too", async () => {
    // Migration is the one place a key's sealing changes, and a
    // password key is the common thing to migrate. The handle is
    // already open; the old protection is irrelevant.
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
