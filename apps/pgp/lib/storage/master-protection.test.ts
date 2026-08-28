/**
 * The vault's own protection record.
 *
 * This is the one storage record that is deliberately PLAINTEXT (see the
 * security note in the module): it is what the unlock flow reads before
 * any key exists to decrypt it with. That makes its validator the only
 * thing standing between a corrupted or hand-edited storage entry and an
 * unlock path that thinks it knows how the vault is protected.
 *
 * So what is pinned here is the validator's shape discipline: a record
 * missing any field its method depends on reads back as `null` -- "no
 * protection configured" -- rather than as a half-populated object the
 * unlock flow would then dereference.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { MasterProtection } from "./master-protection";
import { STORAGE_MASTER_PROTECTION } from "../constants";
import { invalidateLocationCache } from "./engine";
import { fakeArea } from "./fake-area";
import { getMasterProtection, saveMasterProtection } from "./master-protection";

let local: ReturnType<typeof fakeArea>;

beforeEach(() => {
  local = fakeArea();
  vi.stubGlobal("chrome", { storage: { local, sync: fakeArea() } });
  invalidateLocationCache();
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

  it("overwrites on re-save, so switching method leaves no trace of the old one", async () => {
    await saveMasterProtection(password);
    await saveMasterProtection(passkey);
    expect(await getMasterProtection()).toEqual(passkey);
  });
});

describe("validation", () => {
  /** Write straight past `saveMasterProtection` -- these are the shapes a
   *  corrupted profile or an older build leaves behind, not ones our own
   *  writer can produce. */
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
    // base64 strings arriving as raw byte arrays is the realistic
    // corruption here -- an older build that stored Uint8Arrays.
    seed({ ...passkey, prfSalt: [1, 2, 3] });
    expect(await getMasterProtection()).toBeNull();
  });

  it("ignores extra fields a newer build might add", async () => {
    // Forward compatibility: a record written by a build that learned a
    // new field must still unlock on this one.
    seed({ ...passkey, transports: ["internal"] });
    expect(await getMasterProtection()).toEqual({
      ...passkey,
      transports: ["internal"],
    });
  });
});
