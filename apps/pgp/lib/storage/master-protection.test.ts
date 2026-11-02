/**
 * The vault's protection record is deliberately plaintext, so its
 * validator is all that stands between a corrupted entry and the unlock
 * flow: a record missing any field its method needs reads back as `null`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  STORAGE_INTEGRITY,
  STORAGE_MASTER_PROTECTION,
  STORAGE_PREFERENCES,
} from "~/lib/constants";
import { invalidateLocationCache } from "./engine";
import { stubChromeStorage, type FakeArea } from "./fake-area";
import {
  getMasterProtection,
  saveMasterProtection,
  VaultExistsError,
  type MasterProtection,
} from "./master-protection";

let local: FakeArea;
let sync: FakeArea;

beforeEach(() => {
  ({ local, sync } = stubChromeStorage());
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const passkey: MasterProtection = {
  method: "passkey",
  credentialId: "Y3JlZA",
  prfSalt: "c2FsdA==",
  storedSecret: "c2VjcmV0",
};

const password: MasterProtection = {
  method: "password",
  kdfSalt: "c2FsdA==",
  encryptedCanary: "Y2FuYXJ5",
  canaryIv: "aXY=",
};

describe("round trip", () => {
  it("stores and returns a passkey record", async () => {
    await saveMasterProtection(passkey);
    expect(await getMasterProtection()).toEqual(passkey);
  });

  it("stores and returns a password record", async () => {
    await saveMasterProtection(password);
    expect(await getMasterProtection()).toEqual(password);
  });
});

/** The writer refuses to replace a vault in EITHER area: the bootstrap's
 *  flag and `storageLocation` are both forgeable. */
describe("never replaces an existing vault", () => {
  it("refuses a second save in the same area", async () => {
    await saveMasterProtection(password);
    await expect(saveMasterProtection(passkey)).rejects.toBeInstanceOf(
      VaultExistsError,
    );
    expect(await getMasterProtection()).toEqual(password);
  });

  it("refuses when the vault is in the OTHER area", async () => {
    // Local vault, bootstrap flipped to sync: the engine sees nothing.
    local.store.set(STORAGE_MASTER_PROTECTION, password);
    sync.store.set(STORAGE_PREFERENCES, { storageLocation: "sync" });
    invalidateLocationCache();

    await expect(saveMasterProtection(passkey)).rejects.toBeInstanceOf(
      VaultExistsError,
    );
    expect(local.store.get(STORAGE_MASTER_PROTECTION)).toEqual(password);
    expect(sync.store.has(STORAGE_MASTER_PROTECTION)).toBe(false);
  });

  it("refuses over a record this build cannot even parse", async () => {
    // Only a VALID record counts as a vault.
    local.store.set(STORAGE_MASTER_PROTECTION, { method: "yubikey" });
    await expect(saveMasterProtection(password)).resolves.toBeUndefined();
  });

  it("drops an integrity ledger left by an earlier vault", async () => {
    // It would read as tampering under the new vault's key.
    local.store.set(STORAGE_INTEGRITY, { iv: "x", ciphertext: "y" });
    await saveMasterProtection(password);
    expect(local.store.has(STORAGE_INTEGRITY)).toBe(false);
  });
});

describe("validation", () => {
  /** Bypasses `saveMasterProtection` to seed corrupted/older shapes. */
  function seed(raw: unknown) {
    local.store.set(STORAGE_MASTER_PROTECTION, raw);
  }

  it("returns null when nothing is stored", async () => {
    expect(await getMasterProtection()).toBeNull();
  });

  it.each([
    ["null", null],
    ["a string", "passkey"],
    ["a number", 7],
    ["an array", []],
    ["an unknown method", { method: "yubikey" }],
    [
      "no method at all",
      { credentialId: "a", prfSalt: "b", storedSecret: "c" },
    ],
  ])("rejects %s", async (_label, raw) => {
    seed(raw);
    expect(await getMasterProtection()).toBeNull();
  });

  it.each([["credentialId"], ["prfSalt"], ["storedSecret"]])(
    "rejects a passkey record missing %s",
    async (field) => {
      const { [field as keyof typeof passkey]: _dropped, ...rest } = passkey;
      seed(rest);
      expect(await getMasterProtection()).toBeNull();
    },
  );

  it.each([["kdfSalt"], ["encryptedCanary"], ["canaryIv"]])(
    "rejects a password record missing %s",
    async (field) => {
      const { [field as keyof typeof password]: _dropped, ...rest } = password;
      seed(rest);
      expect(await getMasterProtection()).toBeNull();
    },
  );

  it("rejects a passkey record whose fields are the wrong type", async () => {
    // Realistic corruption: an older build that stored byte arrays.
    seed({ ...passkey, prfSalt: [1, 2, 3] });
    expect(await getMasterProtection()).toBeNull();
  });

  it("ignores extra fields a newer build might add", async () => {
    // Forward compatibility: unknown fields still unlock.
    seed({ ...passkey, transports: ["internal"] });
    expect(await getMasterProtection()).toEqual({
      ...passkey,
      transports: ["internal"],
    });
  });
});
