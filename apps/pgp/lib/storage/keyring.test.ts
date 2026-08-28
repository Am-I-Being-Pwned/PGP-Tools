/**
 * The keyring store.
 *
 * `key-kind.test.ts` and `protected-store.test.ts` already pin the
 * `kind` field's on-disk discipline and the generic store mechanics. Two
 * things specific to the keyring are pinned here instead:
 *
 *  1. THE DELETE GUARD. A locked vault reads as an empty keyring, which
 *     is indistinguishable from "the user deleted their last key". An
 *     unguarded delete would therefore compute "nothing left", take the
 *     empty-store shortcut, and remove the sealed blob -- destroying
 *     every key without the vault ever being opened. `removeKey` must
 *     refuse rather than proceed. This is the behaviour the guard exists
 *     for, so it gets a test that fails loudly if the guard is dropped.
 *
 *  2. THE SEAL ROUND TRIP. `blobFromEncrypted` and
 *     `encryptedBlobFromProtected` are inverses across both protection
 *     methods. They are the only path between the stored record and the
 *     decrypt call, and a field dropped in either direction produces an
 *     un-openable key that nothing catches until a user tries to unlock.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { EncryptedBlob } from "../protection/encrypt-private-key";
import type { ProtectedKeyBlob } from "./keyring";
import { STORAGE_KEYRING } from "../constants";
import { invalidateLocationCache } from "./engine";
import { fakeArea } from "./fake-area";
import {
  domainEnvelope,
  fakeDecryptContacts,
  fakeDecryptStore,
  fakeEncryptContacts,
  fakeEncryptStore,
  isDomainSealed,
  legacyEnvelope,
} from "./fake-store-crypto";
import {
  addKey,
  blobFromEncrypted,
  encryptedBlobFromProtected,
  getKeyring,
  normalizeKeyringPadding,
  removeKey,
  updateAlias,
} from "./keyring";

const wasmMock = vi.hoisted(() => ({ session: true }));

vi.mock("../pgp/wasm", () => ({
  hasContactsSession: () => Promise.resolve(wasmMock.session),
  encryptStore: (domain: string, plaintext: Uint8Array) =>
    Promise.resolve(fakeEncryptStore(domain, plaintext)),
  decryptStore: (domain: string, ciphertext: Uint8Array) =>
    Promise.resolve(fakeDecryptStore(domain, ciphertext)),
  encryptContacts: (plaintext: Uint8Array) =>
    Promise.resolve(fakeEncryptContacts(plaintext)),
  decryptContacts: (ciphertext: Uint8Array) =>
    Promise.resolve(fakeDecryptContacts(ciphertext)),
}));

let local: ReturnType<typeof fakeArea>;

beforeEach(() => {
  local = fakeArea();
  vi.stubGlobal("chrome", { storage: { local, sync: fakeArea() } });
  wasmMock.session = true;
  invalidateLocationCache();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const passwordSeal: EncryptedBlob = {
  method: "password",
  ciphertext: "Y3Q=",
  iv: "aXY=",
  salt: "c2FsdA==",
};

const passkeySeal: EncryptedBlob = {
  method: "passkey",
  ciphertext: "Y3Q=",
  iv: "aXY=",
  credentialId: "Y3JlZA",
  prfSalt: "cHJm",
  storedSecret: "c2VjcmV0",
};

function blob(over: Partial<ProtectedKeyBlob> = {}): ProtectedKeyBlob {
  return {
    ...blobFromEncrypted(
      "FPR1",
      ["Alice <a@b.test>"],
      "ed25519",
      "-----BEGIN PGP PUBLIC KEY BLOCK----- alice",
      passwordSeal,
    ),
    ...over,
  };
}

describe("seal round trip", () => {
  it("restores a password blob to the exact seal it was built from", () => {
    const built = blobFromEncrypted("F", [], "rsa4096", "pub", passwordSeal);
    expect(encryptedBlobFromProtected(built)).toEqual(passwordSeal);
  });

  it("restores a passkey blob to the exact seal it was built from", () => {
    // credentialId / prfSalt / storedSecret all have to survive: without
    // any one of them the PRF can't be re-derived and the key is lost.
    const built = blobFromEncrypted("F", [], "ed25519", "pub", passkeySeal);
    expect(encryptedBlobFromProtected(built)).toEqual(passkeySeal);
  });

  it("carries the ciphertext and iv from the blob, not the protection record", () => {
    const built = blobFromEncrypted("F", [], "ed25519", "pub", passkeySeal);
    const moved = {
      ...built,
      encryptedPrivateKey: "b3RoZXI=",
      iv: "b3RoZXJpdg==",
    };
    expect(encryptedBlobFromProtected(moved)).toMatchObject({
      ciphertext: "b3RoZXI=",
      iv: "b3RoZXJpdg==",
    });
  });
});

describe("removeKey", () => {
  it("deletes a key when the vault is unlocked", async () => {
    await addKey(blob());
    await addKey(blob({ keyId: "FPR2" }));

    await removeKey("FPR1");

    expect((await getKeyring()).map((b) => b.keyId)).toEqual(["FPR2"]);
  });

  it("refuses to delete while the vault is locked", async () => {
    await addKey(blob());
    wasmMock.session = false;

    await expect(removeKey("FPR1")).rejects.toThrow(/vault is locked/);
  });

  it("leaves the sealed blob intact after a locked delete", async () => {
    // The regression this guards: a locked read returns [], the delete
    // computes "nothing left", and removeItem wipes the whole keyring.
    await addKey(blob());
    const sealed = local.store.get(STORAGE_KEYRING);

    wasmMock.session = false;
    // The rejection is the assertion above; here we only need the store
    // left untouched afterwards.
    await removeKey("FPR1").catch(() => undefined);
    wasmMock.session = true;

    expect(local.store.get(STORAGE_KEYRING)).toEqual(sealed);
    expect((await getKeyring()).map((b) => b.keyId)).toEqual(["FPR1"]);
  });

  it("removing the last key still leaves the keyring readable", async () => {
    await addKey(blob());
    await removeKey("FPR1");
    expect(await getKeyring()).toEqual([]);
  });
});

describe("getKeyring validation", () => {
  it("drops records missing the fields an unlock depends on", async () => {
    const good = blob();
    local.store.set(
      STORAGE_KEYRING,
      domainEnvelope(
        STORAGE_KEYRING,
        new TextEncoder().encode(
          JSON.stringify([
            good,
            { keyId: "NOPUB" },
            { ...good, keyId: 42 },
            { ...good, protection: null },
            { ...good, protection: { noMethod: true } },
            null,
          ]),
        ),
      ),
    );

    expect((await getKeyring()).map((b) => b.keyId)).toEqual(["FPR1"]);
  });

  it("reads as empty while locked", async () => {
    await addKey(blob());
    wasmMock.session = false;
    expect(await getKeyring()).toEqual([]);
  });
});

describe("normalizeKeyringPadding", () => {
  it("upgrades a legacy blob without changing the keys in it", async () => {
    const stored = [blob()];
    local.store.set(
      STORAGE_KEYRING,
      legacyEnvelope(new TextEncoder().encode(JSON.stringify(stored))),
    );

    await normalizeKeyringPadding();

    expect(isDomainSealed(local.store.get(STORAGE_KEYRING))).toBe(true);
    expect(await getKeyring()).toEqual(stored);
  });
});

describe("updateAlias", () => {
  it("sets and clears the local display name", async () => {
    await addKey(blob());

    await updateAlias("FPR1", "Work key");
    expect((await getKeyring())[0].alias).toBe("Work key");

    // Clearing reverts the UI to the first User ID, so the field must go
    // away rather than persist as an empty string.
    await updateAlias("FPR1", "   ");
    expect((await getKeyring())[0].alias).toBeUndefined();
  });

  it("never touches the certificate", async () => {
    await addKey(blob());
    await updateAlias("FPR1", "Work key");
    const stored = (await getKeyring())[0];
    expect(stored.userIds).toEqual(["Alice <a@b.test>"]);
    expect(stored.publicKeyArmored).toContain("alice");
  });
});
