/**
 * The generic protected-key store, via its public instantiations
 * (`storage/keyring.ts`, `crx/storage.ts`): mutations serialize, an
 * emptied store stays a sealed empty array, a missing key no-ops for
 * metadata setters but THROWS for `updateRevocationCertificate`, and a CRX
 * mutation without a session never persists a locked read's `[]`.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { STORAGE_CRX_KEYS, STORAGE_KEYRING } from "~/lib/constants";
import {
  addCrxKey,
  getCrxKeys,
  removeCrxKey,
  updateCrxLabel,
  updateCrxLastUsed,
} from "~/lib/crx/storage";
import type { CrxSigningKeyBlob } from "~/lib/crx/types";
import {
  contactsOfKind,
  loadContacts,
  saveContact,
  type PublicContactKey,
} from "~/lib/storage/contacts";
import {
  isPgpRecord,
  isSshRecord,
  storedKeyKind,
} from "~/lib/storage/key-kind";
import {
  addKey,
  getKeyring,
  removeKey,
  updateAlias,
  updateLastUsed,
  updateRevocationCertificate,
  type ProtectedKeyBlob,
} from "~/lib/storage/keyring";
import { stubChromeStorage, type FakeArea } from "./fake-area";
import { isDomainSealed } from "./fake-store-crypto";

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

/** A CRX blob whose public key really hashes to `extensionId`. */
async function crxKey(): Promise<CrxSigningKeyBlob> {
  const { extensionIdFromPublicKeyDer } = await import("~/lib/crx/types");
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

  it("keeps a sealed empty store once the last key is deleted", async () => {
    // Never removed: a missing store reads as a deletion attack.
    await addKey(pgpKey("AAAA"));
    await addKey(pgpKey("BBBB"));

    await removeKey("AAAA");
    await removeKey("BBBB");
    expect(isDomainSealed(local.store.get(STORAGE_KEYRING))).toBe(true);
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
    expect(await getCrxKeys()).toEqual([]);
    expect(isDomainSealed(local.store.get(STORAGE_CRX_KEYS))).toBe(true);
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
    // Signing outlives the session; a metadata-only write must not error.
    await expect(updateCrxLastUsed(blob.extensionId)).resolves.toBeUndefined();
    expect(local.store.get(STORAGE_CRX_KEYS)).toBe(sealed);

    wasmMock.session = true;
    await updateCrxLastUsed(blob.extensionId);
    expect((await getCrxKeys())[0].lastUsedAt).toBeGreaterThan(1);
  });
});

describe("keyring - the kind discriminant", () => {
  /** An SSH identity: same store and seal; differs in `kind`, fingerprint
   *  and recipient-line "armor". */
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
    // A pre-SSH blob must round-trip without gaining `kind: "pgp"`.
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
    // The discriminant is inside the sealed array, not a plaintext sidecar.
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
    // The two sets can't be combined in one message (`lib/encrypt-recipients.ts`).
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
