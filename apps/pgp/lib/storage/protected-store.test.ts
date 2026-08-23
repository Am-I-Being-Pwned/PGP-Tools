/**
 * The generic protected-key store, exercised through the two stores that
 * instantiate it (`storage/keyring.ts`, `crx/storage.ts`) rather than
 * directly — those public APIs are the contract users' on-disk blobs and
 * the UI both depend on.
 *
 * What is pinned here is the behaviour that is easy to lose when the
 * machinery is shared: mutations serialize under the store's lock, a
 * store emptied by a delete removes its storage entry rather than
 * leaving a sealed empty array, a missing key is a no-op for the
 * metadata setters but must THROW for `updateRevocationCertificate`
 * (whose caller reports "certificate created"), and a CRX mutation
 * without a vault session must never be allowed to persist the empty
 * array that a locked read returns.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { CrxSigningKeyBlob } from "../crx/types";
import type { PublicContactKey } from "./contacts";
import type { ProtectedKeyBlob } from "./keyring";
import { STORAGE_CRX_KEYS, STORAGE_KEYRING } from "../constants";
import {
  addCrxKey,
  getCrxKeys,
  removeCrxKey,
  updateCrxLabel,
  updateCrxLastUsed,
} from "../crx/storage";
import { contactsOfKind, loadContacts, saveContact } from "./contacts";
import { invalidateLocationCache } from "./engine";
import { isPgpRecord, isSshRecord, storedKeyKind } from "./key-kind";
import {
  fakeDecryptStore,
  fakeEncryptStore,
  fakeEncryptContacts,
  fakeDecryptContacts,
} from "./fake-store-crypto";
import {
  addKey,
  getKeyring,
  removeKey,
  updateAlias,
  updateLastUsed,
  updateRevocationCertificate,
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

function fakeArea() {
  const store = new Map<string, unknown>();
  return {
    store,
    get: (keys?: string | string[] | null) => {
      if (keys == null) return Promise.resolve(Object.fromEntries(store));
      const list = Array.isArray(keys) ? keys : [keys];
      const out: Record<string, unknown> = {};
      for (const k of list) if (store.has(k)) out[k] = store.get(k);
      return Promise.resolve(out);
    },
    set: (items: Record<string, unknown>) => {
      for (const [k, v] of Object.entries(items)) store.set(k, v);
      return Promise.resolve();
    },
    remove: (keys: string | string[]) => {
      const list = Array.isArray(keys) ? keys : [keys];
      for (const k of list) store.delete(k);
      return Promise.resolve();
    },
  };
}

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

function pgpKey(keyId: string): ProtectedKeyBlob {
  return {
    version: 1,
    keyId,
    userIds: [`${keyId} <a@b.test>`],
    algorithm: "ed25519",
    publicKeyArmored: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
    protection: { method: "password", kdfSalt: "c2FsdA==" },
    encryptedPrivateKey: "Y3Q=",
    iv: "aXY=",
    createdAt: 1,
    lastUsedAt: 1,
  };
}

/** A CRX blob whose public key really does hash to `extensionId` -- the
 *  identity check in `addCrxKey` is not bypassable, by design. */
async function crxKey(): Promise<CrxSigningKeyBlob> {
  const { extensionIdFromPublicKeyDer } = await import("../crx/types");
  const publicKeyDerB64 = "ZGVyLWJ5dGVz";
  return {
    version: 1,
    extensionId: await extensionIdFromPublicKeyDer(publicKeyDerB64),
    publicKeyDerB64,
    algorithm: "rsa2048",
    protection: { method: "password", kdfSalt: "c2FsdA==" },
    encryptedPrivateKey: "Y3Q=",
    iv: "aXY=",
    createdAt: 1,
    lastUsedAt: 1,
  };
}

describe("keyring CRUD", () => {
  it("adds, replaces by keyId, and reads back", async () => {
    await addKey(pgpKey("AAAA"));
    await addKey(pgpKey("BBBB"));
    await addKey({ ...pgpKey("AAAA"), algorithm: "rsa4096" });

    const keyring = await getKeyring();
    expect(keyring.map((k) => k.keyId).sort()).toEqual(["AAAA", "BBBB"]);
    expect(keyring.find((k) => k.keyId === "AAAA")?.algorithm).toBe("rsa4096");
  });

  it("serializes concurrent adds -- no lost update", async () => {
    await Promise.all([
      addKey(pgpKey("AAAA")),
      addKey(pgpKey("BBBB")),
      addKey(pgpKey("CCCC")),
    ]);
    expect((await getKeyring()).map((k) => k.keyId).sort()).toEqual([
      "AAAA",
      "BBBB",
      "CCCC",
    ]);
  });

  it("removes the storage entry once the last key is deleted", async () => {
    await addKey(pgpKey("AAAA"));
    await addKey(pgpKey("BBBB"));

    await removeKey("AAAA");
    expect(local.store.has(STORAGE_KEYRING)).toBe(true);

    await removeKey("BBBB");
    expect(local.store.has(STORAGE_KEYRING)).toBe(false);
    expect(await getKeyring()).toEqual([]);
  });

  it("updates alias and lastUsed in place, and no-ops on a miss", async () => {
    await addKey(pgpKey("AAAA"));

    await updateAlias("AAAA", "  Work key  ");
    expect((await getKeyring())[0].alias).toBe("Work key");

    await updateAlias("AAAA", "   ");
    expect((await getKeyring())[0].alias).toBeUndefined();

    await updateLastUsed("AAAA");
    expect((await getKeyring())[0].lastUsedAt).toBeGreaterThan(1);

    await expect(updateAlias("NOPE", "x")).resolves.toBeUndefined();
    await expect(updateLastUsed("NOPE")).resolves.toBeUndefined();
  });

  it("throws rather than no-oping when a revocation cert has no key", async () => {
    await addKey(pgpKey("AAAA"));
    await updateRevocationCertificate("AAAA", "REVOKE");
    expect((await getKeyring())[0].revocationCertificate).toBe("REVOKE");

    // A false "certificate created" is the failure mode being prevented.
    await expect(updateRevocationCertificate("NOPE", "REVOKE")).rejects.toThrow(
      /Key not found/,
    );
  });
});

describe("CRX key store", () => {
  it("rejects a blob whose public key doesn't match its extension id", async () => {
    const blob = await crxKey();
    await expect(
      addCrxKey({ ...blob, extensionId: "a".repeat(32) }),
    ).rejects.toThrow(/does not match its extension id/);
    expect(local.store.has(STORAGE_CRX_KEYS)).toBe(false);
  });

  it("round-trips a valid blob and renames it", async () => {
    const blob = await crxKey();
    await addCrxKey(blob);
    expect((await getCrxKeys()).map((k) => k.extensionId)).toEqual([
      blob.extensionId,
    ]);

    await updateCrxLabel(blob.extensionId, " My Extension ");
    expect((await getCrxKeys())[0].label).toBe("My Extension");

    await removeCrxKey(blob.extensionId);
    expect(local.store.has(STORAGE_CRX_KEYS)).toBe(false);
  });

  it("refuses to mutate while the vault is locked", async () => {
    const blob = await crxKey();
    await addCrxKey(blob);
    const sealed = local.store.get(STORAGE_CRX_KEYS);

    wasmMock.session = false;
    await expect(addCrxKey(blob)).rejects.toThrow(/vault is locked/);
    await expect(removeCrxKey(blob.extensionId)).rejects.toThrow(
      /vault is locked/,
    );
    await expect(updateCrxLabel(blob.extensionId, "x")).rejects.toThrow(
      /vault is locked/,
    );
    // The locked read returns [] -- the stored keys must survive it.
    expect(local.store.get(STORAGE_CRX_KEYS)).toBe(sealed);

    wasmMock.session = true;
    expect(await getCrxKeys()).toHaveLength(1);
  });

  it("skips the lastUsed timestamp when locked instead of failing", async () => {
    const blob = await crxKey();
    await addCrxKey(blob);
    const sealed = local.store.get(STORAGE_CRX_KEYS);

    wasmMock.session = false;
    // Signing legitimately outlives the master session; a metadata-only
    // write must not turn that into an error.
    await expect(updateCrxLastUsed(blob.extensionId)).resolves.toBeUndefined();
    expect(local.store.get(STORAGE_CRX_KEYS)).toBe(sealed);

    wasmMock.session = true;
    await updateCrxLastUsed(blob.extensionId);
    expect((await getCrxKeys())[0].lastUsedAt).toBeGreaterThan(1);
  });
});

describe("keyring - the kind discriminant", () => {
  /** An SSH identity: same store, same seal, same CRUD. Only `kind`,
   *  the fingerprint form and the "armor" (a recipient line) differ. */
  function sshKey(fingerprint: string): ProtectedKeyBlob {
    return {
      ...pgpKey(fingerprint),
      kind: "ssh",
      userIds: ["alice@host"],
      algorithm: "ssh-ed25519",
      publicKeyArmored: "ssh-ed25519 AAAAC3Nza alice@host",
    };
  }

  it("round-trips a legacy blob with the field ABSENT, still absent", async () => {
    // The migration property: a blob written before SSH existed goes
    // through the store's read-modify-write untouched. If a normalize
    // pass or a constructor started stamping `kind: "pgp"` on the way
    // back out, an older build would read it as a foreign engine.
    await addKey(pgpKey("AAAA"));
    await updateAlias("AAAA", "Legacy key");

    const [stored] = await getKeyring();
    expect("kind" in stored).toBe(false);
    expect(storedKeyKind(stored)).toBe("pgp");
    expect(stored.alias).toBe("Legacy key");
  });

  it("holds both engines in one store, addressed by the same id", async () => {
    await addKey(pgpKey("AAAA"));
    await addKey(sshKey("SHA256:bbb"));

    const keyring = await getKeyring();
    expect(keyring).toHaveLength(2);
    expect(keyring.filter(isPgpRecord).map((k) => k.keyId)).toEqual(["AAAA"]);
    expect(keyring.filter(isSshRecord).map((k) => k.keyId)).toEqual([
      "SHA256:bbb",
    ]);
  });

  it("survives the seal, so `kind` is inside the encrypted envelope", async () => {
    // Not a plaintext sidecar: the discriminant rides in the same sealed
    // array as everything else the store holds.
    await addKey(sshKey("SHA256:bbb"));
    const [stored] = await getKeyring();
    expect(stored.kind).toBe("ssh");
    expect(stored.publicKeyArmored).toMatch(/^ssh-ed25519 /);
  });

  it("deletes an SSH identity by its fingerprint like any other key", async () => {
    await addKey(pgpKey("AAAA"));
    await addKey(sshKey("SHA256:bbb"));
    await removeKey("SHA256:bbb");
    expect((await getKeyring()).map((k) => k.keyId)).toEqual(["AAAA"]);
  });
});

describe("contacts - the kind discriminant", () => {
  function contact(over: Partial<PublicContactKey> = {}): PublicContactKey {
    return {
      keyId: "CCCC",
      userIds: ["Carol <c@d.test>"],
      algorithm: "ed25519",
      armoredPublicKey: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
      addedAt: 1,
      lastUsedAt: 1,
      ...over,
    };
  }

  it("reads a legacy contact (no kind) as a PGP recipient", async () => {
    await saveContact(contact());
    const contacts = await loadContacts();
    expect("kind" in contacts[0]).toBe(false);
    expect(contactsOfKind(contacts, "pgp").map((c) => c.keyId)).toEqual([
      "CCCC",
    ]);
    expect(contactsOfKind(contacts, "ssh")).toEqual([]);
  });

  it("separates the two engines' recipients", async () => {
    // The narrowing a composer MUST do: the two sets cannot be combined
    // in one message (see `lib/encrypt-recipients.ts`).
    await saveContact(contact());
    await saveContact(
      contact({
        kind: "ssh",
        keyId: "SHA256:eee",
        userIds: ["erin@host"],
        algorithm: "ssh-ed25519",
        armoredPublicKey: "ssh-ed25519 AAAAC3Nza erin@host",
      }),
    );

    const contacts = await loadContacts();
    expect(contactsOfKind(contacts, "pgp").map((c) => c.keyId)).toEqual([
      "CCCC",
    ]);
    expect(contactsOfKind(contacts, "ssh").map((c) => c.keyId)).toEqual([
      "SHA256:eee",
    ]);
  });
});

