/**
 * Keyring-specific: the delete guard (a locked vault reads as empty, so an
 * unguarded delete would destroy every key) and the seal round trip
 * (`blobFromEncrypted` / `encryptedBlobFromProtected` are inverses; a
 * dropped field makes an un-openable key).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { STORAGE_KEYRING } from "~/lib/constants";
import type { EncryptedBlob } from "~/lib/protection/encrypt-private-key";
import {
  addKey,
  blobFromEncrypted,
  encryptedBlobFromProtected,
  getKeyring,
  normalizeKeyringPadding,
  removeKey,
  replaceKeyProtection,
  updateAlias,
  type ProtectedKeyBlob,
} from "~/lib/storage/keyring";
import { stubChromeStorage, type FakeArea } from "./fake-area";
import {
  domainEnvelope,
  isDomainSealed,
  legacyEnvelope,
} from "./fake-store-crypto";

const wasmMock = vi.hoisted(() => ({ session: true }));

vi.mock("~/lib/pgp/wasm", async () =>
  (await import("./fake-store-crypto")).fakeStoreWasm(() => wasmMock.session),
);

let local: FakeArea;

beforeEach(() => {
  ({ local } = stubChromeStorage());
  wasmMock.session = true;
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
    // Without any of these the PRF can't be re-derived and the key is lost.
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
    await addKey(blob());
    const sealed = local.store.get(STORAGE_KEYRING);

    wasmMock.session = false;
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

describe("replaceKeyProtection", () => {
  it("swaps only the three sealing fields and keeps the rest", async () => {
    await addKey(blob({ alias: "work", lastUsedAt: 42 }));

    await replaceKeyProtection("FPR1", {
      protection: {
        method: "passkey",
        credentialId: "master-cred",
        prfSalt: "bWFzdGVyLXNhbHQ=",
        storedSecret: "ZnJlc2gtc2VjcmV0",
      },
      encryptedPrivateKey: "bmV3LWN0",
      iv: "bmV3LWl2",
    });

    const [stored] = await getKeyring();
    expect(stored.protection).toEqual({
      method: "passkey",
      credentialId: "master-cred",
      prfSalt: "bWFzdGVyLXNhbHQ=",
      storedSecret: "ZnJlc2gtc2VjcmV0",
    });
    expect(stored.encryptedPrivateKey).toBe("bmV3LWN0");
    expect(stored.iv).toBe("bmV3LWl2");
    // Read under the lock, not from the caller's snapshot.
    expect(stored.alias).toBe("work");
    expect(stored.lastUsedAt).toBe(42);
    expect(stored.userIds).toEqual(["Alice <a@b.test>"]);
  });

  it("throws for a key that is not in the keyring", async () => {
    // A silent no-op would report a migration that never happened.
    await addKey(blob());
    await expect(
      replaceKeyProtection("NOPE", {
        protection: { method: "password", kdfSalt: "c2FsdA==" },
        encryptedPrivateKey: "Y3Q=",
        iv: "aXY=",
      }),
    ).rejects.toThrow(/not in the keyring/);
  });
});

describe("updateAlias", () => {
  it("sets and clears the local display name", async () => {
    await addKey(blob());

    await updateAlias("FPR1", "Work key");
    expect((await getKeyring())[0].alias).toBe("Work key");

    // Cleared means absent, not an empty string.
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
