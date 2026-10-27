/**
 * The storage-write attacker: someone who can WRITE chrome.storage (for a
 * "sync across devices" user, anyone signed in to their Google account)
 * but does not know the vault password. Every attack below was
 * demonstrated against the previous build; each test is its regression.
 *
 *  A. a plaintext legacy index sealed into the vault as genuine
 *  B. legacy plaintext preferences laundered into the sealed settings
 *  C. a forged bootstrap putting onboarding up over a real vault
 *  D. an older, validly sealed blob written back (un-revoking a contact,
 *     resurrecting deleted data), or a blob deleted outright
 *  E. the follow-up review's gaps: a junk settings blob, a sync-planted
 *     master protection hiding a local vault, odd location values, a
 *     deleted or junk ledger, and the onboarding write order
 *
 * Plus the property the D defence has to keep: ordinary multi-device
 * sync, a location move, and a first upgrade must NOT warn.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { PublicContactKey } from "./contacts";
import {
  STORAGE_CONTACTS,
  STORAGE_CRX_KEYS,
  STORAGE_DEVICE_LOCATION,
  STORAGE_INTEGRITY,
  STORAGE_KEYRING,
  STORAGE_MASTER_PROTECTION,
  STORAGE_PREFERENCES,
  STORAGE_SETTINGS,
} from "../constants";
import { getCrxKeys } from "../crx/storage";
import { PRESETS } from "../presets";
import {
  loadContacts,
  removeContact,
  saveContact,
  updateContact,
} from "./contacts";
import {
  copyEncryptedBlobRepacked,
  saveEncryptedArray,
} from "./encrypted-store";
import { asStorageLocation, invalidateLocationCache } from "./engine";
import { fakeArea } from "./fake-area";
import {
  domainEnvelope,
  fakeDecryptContacts,
  fakeDecryptStore,
  fakeEncryptContacts,
  fakeEncryptStore,
  isDomainSealed,
} from "./fake-store-crypto";
import {
  acknowledgeIntegrityIssues,
  clearIntegrityIssues,
  integrityIssues,
  masterProtectionDigest,
  splitGeneration,
} from "./integrity";
import { getKeyring } from "./keyring";
import {
  masterProtectionIn,
  saveMasterProtection,
  VaultExistsError,
} from "./master-protection";
import {
  getPreferences,
  sanitizeSettings,
  savePreferences,
} from "./preferences";
import {
  adoptVaultLocation,
  moveVault,
  ORPHAN_RECHECK_MS,
  resolveVaultState,
} from "./vault-state";

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
let sync: ReturnType<typeof fakeArea>;

function stub(l: ReturnType<typeof fakeArea>, s: ReturnType<typeof fakeArea>) {
  vi.stubGlobal("chrome", { storage: { local: l, sync: s } });
  invalidateLocationCache();
}

beforeEach(() => {
  local = fakeArea();
  sync = fakeArea();
  stub(local, sync);
  wasmMock.session = true;
  clearIntegrityIssues();
  ORPHAN_RECHECK_MS.value = 0;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

function useSync() {
  sync.store.set(STORAGE_PREFERENCES, {
    storageLocation: "sync",
    onboardingComplete: true,
  });
  invalidateLocationCache();
}

function contact(keyId: string, extra: Partial<PublicContactKey> = {}) {
  return {
    keyId,
    armoredPublicKey: `-----BEGIN PGP PUBLIC KEY BLOCK-----${keyId}`,
    userIds: [`${keyId} <${keyId.toLowerCase()}@example.com>`],
    algorithm: "ed25519",
    addedAt: 1,
    lastUsedAt: 1,
    identityVersion: 1,
    ...extra,
  } satisfies PublicContactKey;
}

const kinds = () => integrityIssues().map((i) => `${i.store}:${i.kind}`);

const PASSWORD_MP = {
  method: "password",
  kdfSalt: "c2FsdA==",
  encryptedCanary: "Y2FuYXJ5",
  canaryIv: "aXY=",
} as const;

// ── A ────────────────────────────────────────────────────────────────

describe("A: the retired plaintext index is never sealed into the vault", () => {
  it("does not adopt a planted VERIFIED contact over a real sealed store", async () => {
    useSync();
    await saveContact(contact("REAL"));
    // The attacker overwrites the sealed blob with an old-format index.
    sync.store.set(STORAGE_CONTACTS, ["evil"]);
    sync.store.set(`${STORAGE_CONTACTS}:evil`, {
      ...contact("DEADBEEF"),
      userIds: ["Alice <alice@example.com>"],
      verified: true,
      verifiedAt: 1,
      identityVersion: 999,
    });

    expect(await loadContacts()).toEqual([]);
    // Nothing sealed, and the substitution is reported as tampering.
    expect(isDomainSealed(sync.store.get(STORAGE_CONTACTS))).toBe(false);
    expect(kinds()).toContain(`${STORAGE_CONTACTS}:missing`);
  });

  it("does not adopt a planted own key into the keyring", async () => {
    local.store.set(STORAGE_KEYRING, ["k"]);
    local.store.set(`${STORAGE_KEYRING}:k`, {
      keyId: "AAAA",
      publicKeyArmored: "x",
      encryptedPrivateKey: "x",
      iv: "x",
      protection: { method: "password", kdfSalt: "x" },
      userIds: ["Victim <v@example.com>"],
    });
    expect(await getKeyring()).toEqual([]);
    expect(isDomainSealed(local.store.get(STORAGE_KEYRING))).toBe(false);
  });

  it("does not adopt a planted CRX signing key", async () => {
    local.store.set(STORAGE_CRX_KEYS, ["c"]);
    local.store.set(`${STORAGE_CRX_KEYS}:c`, { extensionId: "a".repeat(32) });
    expect(await getCrxKeys()).toEqual([]);
    expect(isDomainSealed(local.store.get(STORAGE_CRX_KEYS))).toBe(false);
  });
});

// ── B ────────────────────────────────────────────────────────────────

describe("B: legacy plaintext preferences", () => {
  const evil = {
    advancedMode: true,
    autoLockEnabled: false,
    autoLockMinutes: 99999,
    unlockKeysOnOpen: true,
    defaultKeyId: "EVIL",
    storageLocation: "local",
    onboardingComplete: true,
  };

  it("is not migrated once this device has settled the migration", async () => {
    // A device that has run this build: the settled marker is sealed in
    // the local ledger, which a sync attacker cannot reach.
    await savePreferences({ autoLockMinutes: 2, autoLockEnabled: true });
    await getPreferences();
    local.store.delete(STORAGE_SETTINGS);
    vi.resetModules();
    const fresh = await import("./preferences");

    local.store.set(STORAGE_PREFERENCES, evil);
    const prefs = await fresh.getPreferences();

    expect(prefs.autoLockEnabled).toBe(true);
    expect(prefs.unlockKeysOnOpen).toBe(false);
    expect(local.store.has(STORAGE_PREFERENCES)).toBe(false);
  });

  /** A fresh module instance: the migration settles once per worker. */
  async function freshPrefs() {
    vi.resetModules();
    return import("./preferences");
  }

  it("is never read from the attacker-writable sync area", async () => {
    // A sync user's legacy object was their sync bootstrap; a planted
    // one is cut back to the boot fields, and its settings are dropped.
    sync.store.set(STORAGE_PREFERENCES, { ...evil, storageLocation: "sync" });
    const prefs = await (await freshPrefs()).getPreferences();

    expect(prefs.autoLockEnabled).toBe(true);
    expect(prefs.advancedMode).toBe(false);
    expect(sync.store.get(STORAGE_PREFERENCES)).toEqual({
      storageLocation: "sync",
      onboardingComplete: true,
    });
    expect(sync.store.has(STORAGE_SETTINGS)).toBe(false);
  });

  it("validates every field it does migrate", async () => {
    // A genuine first-run migration still runs -- but a value out of
    // range is dropped to its default rather than sealed.
    local.store.set(STORAGE_PREFERENCES, evil);
    const prefs = await (await freshPrefs()).getPreferences();
    expect(prefs.autoLockMinutes).toBe(15);
    expect(prefs.advancedMode).toBe(true);
  });

  it("validates the sealed blob too", async () => {
    local.store.set(
      STORAGE_SETTINGS,
      domainEnvelope(
        STORAGE_SETTINGS,
        new TextEncoder().encode(
          JSON.stringify({
            autoLockMinutes: 99999,
            autoLockEnabled: "no",
            neverCacheKeys: true,
            unlockKeysOnOpen: true,
            translationTargetLanguage: "<script>",
            recentRecipients: ["ABCD", 7],
            defaultKeyId: { evil: true },
          }),
        ),
      ),
    );
    const prefs = await getPreferences();
    expect(prefs.autoLockMinutes).toBe(15);
    expect(prefs.autoLockEnabled).toBe(true);
    // Opposites: the stricter wins.
    expect(prefs.neverCacheKeys).toBe(true);
    expect(prefs.unlockKeysOnOpen).toBe(false);
    expect(prefs.translationTargetLanguage).toBe("en");
    expect(prefs.recentRecipients).toEqual([]);
    expect(prefs.defaultKeyId).toBeNull();
  });

  it("keeps a sealed field this build does not know, but no legacy one", () => {
    expect(
      sanitizeSettings({ futureFeature: 1, $gen: 5 }, { keepUnknown: true }),
    ).toEqual({ futureFeature: 1 });
    expect(sanitizeSettings({ futureFeature: 1 })).toEqual({});
  });
});

// ── C ────────────────────────────────────────────────────────────────

describe("C: whether a vault exists is read from the vault", () => {
  it("is a vault even with a forged onboardingComplete: false", async () => {
    local.store.set(STORAGE_MASTER_PROTECTION, PASSWORD_MP);
    sync.store.set(STORAGE_PREFERENCES, {
      storageLocation: "local",
      onboardingComplete: false,
    });
    expect(await resolveVaultState()).toEqual({
      kind: "ready",
      protection: PASSWORD_MP,
    });
  });

  it("says where the vault is when storageLocation was flipped", async () => {
    local.store.set(STORAGE_MASTER_PROTECTION, PASSWORD_MP);
    useSync();
    expect(await resolveVaultState()).toEqual({
      kind: "elsewhere",
      location: "local",
    });
    // ...and the master protection cannot be replaced from there.
    await expect(saveMasterProtection(PASSWORD_MP)).rejects.toThrow(
      /already exists/,
    );
  });

  it("calls sealed stores with no master protection orphaned, not new", async () => {
    await saveContact(contact("REAL"));
    expect(await resolveVaultState()).toEqual({ kind: "orphaned" });
  });

  it("is a fresh install only when nothing is stored", async () => {
    sync.store.set(STORAGE_PREFERENCES, { onboardingComplete: true });
    expect(await resolveVaultState()).toEqual({ kind: "none" });
  });
});

// ── D ────────────────────────────────────────────────────────────────

describe("D: rollback and deletion", () => {
  it("keeps a revoked contact revoked when an older blob is written back", async () => {
    useSync();
    await saveContact(contact("SAM", { usableForEncryption: true }));
    const before = sync.store.get(STORAGE_CONTACTS);

    await updateContact("SAM", (c) => ({
      ...c,
      revoked: true,
      usableForEncryption: false,
    }));
    // The attacker restores the pre-revocation copy.
    sync.store.set(STORAGE_CONTACTS, before);

    const [sam] = await loadContacts();
    expect(sam.revoked).toBe(true);
    expect(sam.usableForEncryption).toBe(false);
    expect(kinds()).toContain(`${STORAGE_CONTACTS}:rolled-back`);
  });

  it("reports deleted data that comes back", async () => {
    await saveContact(contact("KEEP"));
    await saveContact(contact("GONE"));
    const before = local.store.get(STORAGE_CONTACTS);
    await removeContact("GONE");

    local.store.set(STORAGE_CONTACTS, before);
    expect((await loadContacts()).map((c) => c.keyId)).toContain("GONE");
    expect(kinds()).toEqual([`${STORAGE_CONTACTS}:rolled-back`]);
  });

  it("reports a store that was deleted outright", async () => {
    await saveContact(contact("A"));
    await removeContact("A"); // emptied: still a sealed store
    expect(kinds()).toEqual([]);

    local.store.delete(STORAGE_CONTACTS);
    expect(await loadContacts()).toEqual([]);
    expect(kinds()).toEqual([`${STORAGE_CONTACTS}:missing`]);
  });

  it("reads deleted settings as the strictest preset, and warns", async () => {
    await savePreferences({ autoLockMinutes: 30, historyEnabled: true });
    local.store.delete(STORAGE_SETTINGS);

    const prefs = await getPreferences();
    const { storageLocation: _s, ...strict } = PRESETS.paranoid.bundle;
    expect(prefs).toMatchObject(strict);
    expect(kinds()).toContain(`${STORAGE_SETTINGS}:missing`);

    // The next change persists ON TOP of the strict values, not defaults.
    await savePreferences({ advancedMode: true });
    expect(await getPreferences()).toMatchObject({
      ...strict,
      advancedMode: true,
    });
  });

  it("does not warn on a first upgrade (no ledger, no generations)", async () => {
    // Blobs written before generations existed, on a device that has
    // never run this build.
    local.store.set(
      STORAGE_CONTACTS,
      domainEnvelope(
        STORAGE_CONTACTS,
        new TextEncoder().encode(JSON.stringify([contact("OLD")])),
      ),
    );
    expect(await loadContacts()).toHaveLength(1);
    expect(kinds()).toEqual([]);
    expect(local.store.has(STORAGE_INTEGRITY)).toBe(true);
  });

  it("replaces an unreadable ledger, and keeps saying so until acknowledged", async () => {
    local.store.set(STORAGE_INTEGRITY, { iv: "AAAA", ciphertext: "AAAA" });
    await saveContact(contact("A"));
    expect(kinds()).toEqual([`${STORAGE_INTEGRITY}:ledger-unreadable`]);
    // Replaced (detection works again), but a panel reopen still warns:
    // the marks and floor it held are gone.
    clearIntegrityIssues();
    await loadContacts();
    expect(kinds()).toEqual([`${STORAGE_INTEGRITY}:ledger-unreadable`]);

    await acknowledgeIntegrityIssues();
    await loadContacts();
    expect(kinds()).toEqual([]);
  });

  it("stores the generation inside the sealed plaintext", async () => {
    await saveContact(contact("A"));
    const { storedPlaintext } = await import("./fake-store-crypto");
    const { unpadPlaintext } = await import("./padding");
    const json = new TextDecoder().decode(
      unpadPlaintext(
        storedPlaintext(local.store.get(STORAGE_CONTACTS) as never),
      ),
    );
    expect(splitGeneration(JSON.parse(json) as unknown[]).gen).toBeGreaterThan(
      0,
    );
  });
});

describe("D: what must NOT warn", () => {
  it("a second synced device reading the first one's writes", async () => {
    const localA = local;
    const localB = fakeArea();
    useSync();

    await saveContact(contact("A1"));
    stub(localB, sync);
    await loadContacts(); // B adopts what it finds
    await saveContact(contact("B1"));

    stub(localA, sync);
    expect((await loadContacts()).map((c) => c.keyId).sort()).toEqual([
      "A1",
      "B1",
    ]);
    await saveContact(contact("A2"));

    stub(localB, sync);
    expect(await loadContacts()).toHaveLength(3);
    expect(kinds()).toEqual([]);
  });

  it("simultaneous writes where sync keeps the later one", async () => {
    const localA = local;
    const localB = fakeArea();
    useSync();
    await saveContact(contact("BASE"));
    stub(localB, sync);
    await loadContacts();

    // Both devices write from the same base before either sees the
    // other's write; B's is the later one, and sync keeps it.
    const t = Date.now();
    const now = vi.spyOn(Date, "now");
    const base = sync.store.get(STORAGE_CONTACTS);
    stub(localA, sync);
    now.mockReturnValue(t + 1_000);
    await saveContact(contact("FROM_A"));
    sync.store.set(STORAGE_CONTACTS, base); // B never saw A's write
    stub(localB, sync);
    now.mockReturnValue(t + 2_000);
    await saveContact(contact("FROM_B"));
    now.mockRestore();

    stub(localA, sync);
    await loadContacts();
    expect(kinds()).toEqual([]);
  });

  it("(documented trade-off) the losing write warns if its clock ran ahead", async () => {
    // The one false positive the timestamp generation leaves: A's clock
    // is far enough ahead that its write, which sync discarded, carries
    // a larger stamp than the write sync kept. See `integrity.ts`.
    const localA = local;
    const localB = fakeArea();
    useSync();
    await saveContact(contact("BASE"));
    stub(localB, sync);
    await loadContacts();

    const t = Date.now();
    const now = vi.spyOn(Date, "now");
    const base = sync.store.get(STORAGE_CONTACTS);
    stub(localA, sync);
    now.mockReturnValue(t + 60_000);
    await saveContact(contact("FROM_A"));
    sync.store.set(STORAGE_CONTACTS, base);
    stub(localB, sync);
    now.mockReturnValue(t + 1_000);
    await saveContact(contact("FROM_B"));
    now.mockRestore();

    stub(localA, sync);
    await loadContacts();
    expect(kinds()).toEqual([`${STORAGE_CONTACTS}:rolled-back`]);
  });

  it("moving the vault between areas", async () => {
    await saveContact(contact("A"));
    await copyEncryptedBlobRepacked(STORAGE_CONTACTS, "local", "sync");
    local.store.delete(STORAGE_CONTACTS);
    useSync();
    expect(await loadContacts()).toHaveLength(1);
    expect(kinds()).toEqual([]);
  });
});

// ── E ────────────────────────────────────────────────────────────────

const { storageLocation: _strictLocation, ...STRICT } = PRESETS.paranoid.bundle;

describe("E1: a settings blob that will not open", () => {
  it("reads as the strictest preset and is reported, not thrown", async () => {
    await savePreferences({ autoLockMinutes: 30, historyEnabled: true });
    local.store.set(STORAGE_SETTINGS, {
      iv: "AAAAAAAAAAAAAAAA",
      ciphertext: "AAAAAAAAAAAAAAAAAAAAAAAA",
    });

    const prefs = await getPreferences();
    expect(prefs).toMatchObject(STRICT);
    expect(kinds()).toContain(`${STORAGE_SETTINGS}:unreadable`);
  });

  it("treats another store's blob moved into the slot the same way", async () => {
    await savePreferences({ autoLockMinutes: 30 });
    await saveContact(contact("A"));
    local.store.set(STORAGE_SETTINGS, local.store.get(STORAGE_CONTACTS));

    expect(await getPreferences()).toMatchObject(STRICT);
    expect(kinds()).toContain(`${STORAGE_SETTINGS}:unreadable`);
  });

  it("lets the next save replace it with a valid blob on the strict values", async () => {
    await savePreferences({ autoLockMinutes: 30 });
    local.store.set(STORAGE_SETTINGS, { iv: "AAAA", ciphertext: "AAAA" });

    await savePreferences({ advancedMode: true });
    clearIntegrityIssues();
    expect(await getPreferences()).toMatchObject({
      ...STRICT,
      advancedMode: true,
    });
    expect(kinds()).toEqual([]);
  });

  it("refuses to overwrite it when nothing proves the session key", async () => {
    // No ledger that opens: the session might be a wrong passkey's, and
    // its blob would replace settings only the real key can read.
    local.store.set(STORAGE_SETTINGS, { iv: "AAAA", ciphertext: "AAAA" });
    await expect(savePreferences({ advancedMode: true })).rejects.toThrow(
      /will not open/,
    );
    expect(local.store.get(STORAGE_SETTINGS)).toEqual({
      iv: "AAAA",
      ciphertext: "AAAA",
    });
  });
});

describe("E2: a master protection planted in sync", () => {
  const PLANTED = { ...PASSWORD_MP, kdfSalt: "ZXZpbA==" };

  function plant() {
    sync.store.set(STORAGE_MASTER_PROTECTION, PLANTED);
    sync.store.set(STORAGE_PREFERENCES, {
      storageLocation: "sync",
      onboardingComplete: true,
    });
    invalidateLocationCache();
  }

  it("cannot move a device that has recorded its location", async () => {
    await savePreferences({ storageLocation: "local" }); // onboarding does
    local.store.set(STORAGE_MASTER_PROTECTION, PASSWORD_MP);
    await saveContact(contact("REAL"));
    plant();

    expect(await resolveVaultState()).toEqual({
      kind: "ready",
      protection: PASSWORD_MP,
      alternate: "sync",
    });
    expect((await loadContacts()).map((c) => c.keyId)).toEqual(["REAL"]);
  });

  it("is a choice, not a silent pick, on a device with no record yet", async () => {
    // An upgrade from a build without the device record.
    local.store.set(STORAGE_MASTER_PROTECTION, PASSWORD_MP);
    plant();
    expect(local.store.has(STORAGE_DEVICE_LOCATION)).toBe(false);
    expect(await resolveVaultState()).toEqual({ kind: "ambiguous" });

    await adoptVaultLocation("local");
    expect(local.store.get(STORAGE_DEVICE_LOCATION)).toBe("local");
    expect(await resolveVaultState()).toMatchObject({
      kind: "ready",
      protection: PASSWORD_MP,
    });
  });

  it("records the location once it is unambiguous", async () => {
    local.store.set(STORAGE_MASTER_PROTECTION, PASSWORD_MP);
    expect(await resolveVaultState()).toMatchObject({ kind: "ready" });
    expect(local.store.get(STORAGE_DEVICE_LOCATION)).toBe("local");

    // Only now does the attacker plant: too late to move this device.
    plant();
    expect(await resolveVaultState()).toMatchObject({
      kind: "ready",
      protection: PASSWORD_MP,
    });
  });
});

describe("E3: storageLocation values are normalised strictly", () => {
  it("does not let 'SYNC' hide a sync vault behind onboarding", async () => {
    useSync();
    await saveContact(contact("REAL"));
    sync.store.set(STORAGE_MASTER_PROTECTION, PASSWORD_MP);
    sync.store.set(STORAGE_PREFERENCES, {
      storageLocation: "SYNC",
      onboardingComplete: true,
    });
    invalidateLocationCache();

    expect(await resolveVaultState()).toEqual({
      kind: "elsewhere",
      location: "sync",
    });
    await expect(saveMasterProtection(PASSWORD_MP)).rejects.toBeInstanceOf(
      VaultExistsError,
    );
  });

  it("maps anything but exactly 'sync' to local", () => {
    for (const v of ["SYNC", "Sync", " sync", 1, null, undefined, {}]) {
      expect(asStorageLocation(v)).toBe("local");
    }
    expect(asStorageLocation("sync")).toBe("sync");
  });

  it("ignores a device record that is not a literal location", async () => {
    local.store.set(STORAGE_DEVICE_LOCATION, "SYNC");
    useSync();
    await saveContact(contact("A"));
    expect(sync.store.has(STORAGE_CONTACTS)).toBe(true);
  });
});

describe("E4: the ledger itself deleted or replaced", () => {
  async function revokedThenRolledBack() {
    await saveContact(contact("SAM", { usableForEncryption: true }));
    const before = local.store.get(STORAGE_CONTACTS);
    await updateContact("SAM", (c) => ({
      ...c,
      revoked: true,
      usableForEncryption: false,
    }));
    return before;
  }

  it("reports a deleted ledger, on every unlock until acknowledged", async () => {
    const before = await revokedThenRolledBack();
    local.store.set(STORAGE_CONTACTS, before);
    local.store.delete(STORAGE_INTEGRITY);

    await loadContacts();
    expect(kinds()).toContain(`${STORAGE_INTEGRITY}:missing`);

    clearIntegrityIssues(); // the panel closes and reopens
    await loadContacts();
    expect(kinds()).toContain(`${STORAGE_INTEGRITY}:missing`);

    await acknowledgeIntegrityIssues();
    await loadContacts();
    expect(kinds()).toEqual([]);
  });

  it("holds the settings at the strictest preset until acknowledged", async () => {
    await savePreferences({ autoLockMinutes: 30, historyEnabled: true });
    await saveContact(contact("A"));
    local.store.delete(STORAGE_INTEGRITY);

    expect(await getPreferences()).toMatchObject(STRICT);
    expect(kinds()).toContain(`${STORAGE_INTEGRITY}:missing`);

    await acknowledgeIntegrityIssues();
    expect(await getPreferences()).toMatchObject({
      autoLockMinutes: 30,
      historyEnabled: true,
    });
  });

  it("reads deleted ledger AND deleted settings as strictest, not defaults", async () => {
    await savePreferences({ autoLockMinutes: 30 });
    await saveContact(contact("A"));
    local.store.delete(STORAGE_INTEGRITY);
    local.store.delete(STORAGE_SETTINGS);

    expect(await getPreferences()).toMatchObject(STRICT);
    expect(kinds()).toContain(`${STORAGE_INTEGRITY}:missing`);
  });

  it("does not run the legacy settings migration over a deleted ledger", async () => {
    await savePreferences({ autoLockMinutes: 2, autoLockEnabled: true });
    await saveContact(contact("A"));
    local.store.delete(STORAGE_SETTINGS);
    local.store.delete(STORAGE_INTEGRITY);
    local.store.set(STORAGE_PREFERENCES, {
      advancedMode: true,
      autoLockEnabled: false,
      historyEnabled: true,
      encryptToSelf: false,
    });
    vi.resetModules();
    const fresh = await import("./preferences");
    const freshIntegrity = await import("./integrity");

    const prefs = await fresh.getPreferences();
    expect(prefs.autoLockEnabled).toBe(true);
    expect(prefs.encryptToSelf).toBe(true);
    expect(local.store.has(STORAGE_PREFERENCES)).toBe(false);
    expect(
      freshIntegrity.integrityIssues().map((i) => `${i.store}:${i.kind}`),
    ).toContain(`${STORAGE_INTEGRITY}:missing`);
  });

  it("rebuilds the revocation floor from the contacts blob after a junk ledger", async () => {
    const before = await revokedThenRolledBack();
    local.store.set(STORAGE_INTEGRITY, { iv: "AAAA", ciphertext: "AAAA" });

    // The blob itself still says revoked; that goes straight back into
    // the fresh ledger's floor...
    await loadContacts();
    expect(kinds()).toContain(`${STORAGE_INTEGRITY}:ledger-unreadable`);
    // ...so a rollback after that cannot un-revoke.
    local.store.set(STORAGE_CONTACTS, before);
    const [sam] = await loadContacts();
    expect(sam.revoked).toBe(true);
    expect(sam.usableForEncryption).toBe(false);
  });

  it("(documented) a rollback in the same write as the ledger loss is not undone", async () => {
    // The floor the junk ledger held is gone and the rolled-back blob
    // never said revoked. What is promised is the warning, repeating.
    const before = await revokedThenRolledBack();
    local.store.set(STORAGE_CONTACTS, before);
    local.store.set(STORAGE_INTEGRITY, { iv: "AAAA", ciphertext: "AAAA" });

    const [sam] = await loadContacts();
    expect(sam.revoked).toBeFalsy();
    clearIntegrityIssues();
    await loadContacts();
    expect(kinds()).toContain(`${STORAGE_INTEGRITY}:ledger-unreadable`);
  });

  it("does not flag a brand-new vault, whose first write precedes its ledger", async () => {
    await saveMasterProtection(PASSWORD_MP, "local");
    await savePreferences({ autoLockMinutes: 5 });
    await saveContact(contact("A"));
    await getPreferences();
    await loadContacts();
    expect(kinds()).toEqual([]);
  });

  it("still migrates a genuine pre-generation install", async () => {
    local.store.set(
      STORAGE_CONTACTS,
      domainEnvelope(
        STORAGE_CONTACTS,
        new TextEncoder().encode(JSON.stringify([contact("OLD")])),
      ),
    );
    local.store.set(STORAGE_PREFERENCES, {
      advancedMode: true,
      autoLockMinutes: 5,
    });
    vi.resetModules();
    const fresh = await import("./preferences");
    const freshIntegrity = await import("./integrity");
    const prefs = await fresh.getPreferences();
    expect(prefs).toMatchObject({ advancedMode: true, autoLockMinutes: 5 });
    expect(freshIntegrity.integrityIssues()).toEqual([]);
  });
});

describe("E5: onboarding writes the vault before the location", () => {
  it("creates the vault in the area it is given, leaving the location alone", async () => {
    await saveMasterProtection(PASSWORD_MP, "sync");
    expect(await masterProtectionIn("sync")).toEqual(PASSWORD_MP);
    expect(await masterProtectionIn("local")).toBeNull();
    expect(local.store.has(STORAGE_DEVICE_LOCATION)).toBe(false);
    expect(sync.store.has(STORAGE_PREFERENCES)).toBe(false);
  });

  it("a refusal leaves this device's location where it was", async () => {
    await savePreferences({ storageLocation: "local" });
    local.store.set(STORAGE_MASTER_PROTECTION, PASSWORD_MP);
    await expect(
      saveMasterProtection({ ...PASSWORD_MP, kdfSalt: "bmV3" }, "sync"),
    ).rejects.toBeInstanceOf(VaultExistsError);
    expect(local.store.get(STORAGE_DEVICE_LOCATION)).toBe("local");
    expect(sync.store.has(STORAGE_MASTER_PROTECTION)).toBe(false);
  });
});

// ── F: the follow-up review ──────────────────────────────────────────

/** A sealed array exactly as a 2.0.x build writes it: its validators
 *  drop the `$gen` element, so the store goes back with no generation. */
function sealedWithoutGeneration(key: string, items: unknown[]) {
  return domainEnvelope(key, new TextEncoder().encode(JSON.stringify(items)));
}

describe("F1: a 2.0.x device sharing a sync vault", () => {
  it("reads a store re-saved without a generation as the softer kind, floor kept", async () => {
    useSync();
    await saveContact(contact("SAM", { usableForEncryption: true }));
    await updateContact("SAM", (c) => ({
      ...c,
      revoked: true,
      usableForEncryption: false,
    }));
    // The old build reads, drops the generation, adds a contact, and
    // writes back -- from its own (pre-revocation) view of SAM.
    sync.store.set(
      STORAGE_CONTACTS,
      sealedWithoutGeneration(STORAGE_CONTACTS, [
        contact("SAM", { usableForEncryption: true }),
        contact("BBB"),
      ]),
    );
    clearIntegrityIssues();

    const list = await loadContacts();
    expect(list.map((c) => c.keyId).sort()).toEqual(["BBB", "SAM"]);
    expect(kinds()).toEqual([`${STORAGE_CONTACTS}:no-generation`]);
    const sam = list.find((c) => c.keyId === "SAM");
    expect(sam?.revoked).toBe(true);
    expect(sam?.usableForEncryption).toBe(false);
  });

  it("still calls a real rollback (an older generation) rolled-back", async () => {
    useSync();
    await saveContact(contact("A"));
    const before = sync.store.get(STORAGE_CONTACTS);
    await saveContact(contact("B"));
    sync.store.set(STORAGE_CONTACTS, before);
    clearIntegrityIssues();
    await loadContacts();
    expect(kinds()).toEqual([`${STORAGE_CONTACTS}:rolled-back`]);
  });

  it("still reports a store the old build removed when it emptied it", async () => {
    useSync();
    await saveContact(contact("AAA"));
    sync.store.delete(STORAGE_CONTACTS);
    clearIntegrityIssues();
    await loadContacts();
    expect(kinds()).toEqual([`${STORAGE_CONTACTS}:missing`]);
  });
});

describe("F2: the strict overlay is never saved", () => {
  const REAL = {
    autoLockMinutes: 60,
    keyDiscoveryEnabled: true,
    aiTranslateEnabled: true,
    neverCacheKeys: false,
  } as const;

  it("a routine save while the ledger is lost does not make the strictest preset permanent", async () => {
    await savePreferences(REAL);
    await saveContact(contact("AAA"));
    local.store.delete(STORAGE_INTEGRITY);
    clearIntegrityIssues();

    expect(await getPreferences()).toMatchObject(STRICT);
    // What every encrypt does.
    await savePreferences({ recentRecipients: ["AAA"] });
    expect(await getPreferences()).toMatchObject(STRICT);

    await acknowledgeIntegrityIssues();
    expect(await getPreferences()).toMatchObject({
      ...REAL,
      recentRecipients: ["AAA"],
    });
  });

  it("keeps a change the user did make while held", async () => {
    await savePreferences(REAL);
    await saveContact(contact("AAA"));
    local.store.delete(STORAGE_INTEGRITY);
    await getPreferences();

    await savePreferences({ autoLockMinutes: 30 });
    await acknowledgeIntegrityIssues();
    expect(await getPreferences()).toMatchObject({
      ...REAL,
      autoLockMinutes: 30,
    });
  });
});

describe("F3: an older settings blob is held like a lost ledger", () => {
  async function rolledBackSettings() {
    await savePreferences({ autoLockMinutes: 60, keyDiscoveryEnabled: true });
    const weak = local.store.get(STORAGE_SETTINGS);
    // The user hardens their settings; the attacker writes the old blob back.
    await savePreferences({ autoLockMinutes: 2, keyDiscoveryEnabled: false });
    local.store.set(STORAGE_SETTINGS, weak);
    clearIntegrityIssues();
  }

  it("reads as the strictest preset, even after a routine save, until acknowledged", async () => {
    await rolledBackSettings();
    expect(await getPreferences()).toMatchObject(STRICT);
    expect(kinds()).toContain(`${STORAGE_SETTINGS}:rolled-back`);

    // A routine save stamps a newer generation over the old values: that
    // must not launder them.
    await savePreferences({ recentRecipients: ["AAA"] });
    clearIntegrityIssues(); // the panel closes and reopens
    expect(await getPreferences()).toMatchObject(STRICT);
    expect(kinds()).toContain(`${STORAGE_SETTINGS}:rolled-back`);

    expect(await acknowledgeIntegrityIssues()).toBe(true);
    expect(await getPreferences()).toMatchObject({
      autoLockMinutes: 60,
      keyDiscoveryEnabled: true,
      recentRecipients: ["AAA"],
    });
    clearIntegrityIssues();
    await getPreferences();
    expect(kinds()).toEqual([]);
  });

  it("accepts the copy on acknowledge, so its next read does not hold it again", async () => {
    await rolledBackSettings();
    await getPreferences();
    await acknowledgeIntegrityIssues();
    clearIntegrityIssues();
    expect(await getPreferences()).toMatchObject({ autoLockMinutes: 60 });
    expect(kinds()).toEqual([]);
  });

  it("holds settings saved with no generation (an older device) the same way", async () => {
    useSync();
    await savePreferences({ autoLockMinutes: 2 });
    sync.store.set(
      STORAGE_SETTINGS,
      domainEnvelope(
        STORAGE_SETTINGS,
        new TextEncoder().encode(JSON.stringify({ autoLockMinutes: 60 })),
      ),
    );
    clearIntegrityIssues();
    expect(await getPreferences()).toMatchObject(STRICT);
    expect(kinds()).toEqual([`${STORAGE_SETTINGS}:no-generation`]);
    await acknowledgeIntegrityIssues();
    expect(await getPreferences()).toMatchObject({ autoLockMinutes: 60 });
  });
});

describe("F4: a new vault's ledger starts with its master protection", () => {
  const anyItem = (v: unknown): v is unknown => v !== undefined;

  it("two stores' first writes racing do not read as a lost ledger", async () => {
    await saveMasterProtection(PASSWORD_MP, "local");
    await Promise.all([
      saveEncryptedArray(
        { storageKey: STORAGE_KEYRING, isValid: anyItem, label: "k" },
        [{ keyId: "X" }],
      ),
      savePreferences({ autoLockMinutes: 30 }),
    ]);
    clearIntegrityIssues();
    const prefs = await getPreferences();
    expect(kinds()).toEqual([]);
    expect(prefs.autoLockMinutes).toBe(30);
  });

  it("a panel closed between the first store write and its ledger write does not either", async () => {
    await saveMasterProtection(PASSWORD_MP, "local");
    local.store.set(
      STORAGE_SETTINGS,
      domainEnvelope(
        STORAGE_SETTINGS,
        new TextEncoder().encode(
          JSON.stringify({ autoLockMinutes: 30, $gen: Date.now() }),
        ),
      ),
    );
    const prefs = await getPreferences();
    expect(kinds()).toEqual([]);
    expect(prefs.autoLockMinutes).toBe(30);
  });

  it("replaces a ledger left by a vault recreated elsewhere quietly", async () => {
    // Device B's ledger was sealed under the old vault's key; the vault
    // was erased and recreated on device A.
    local.store.set(STORAGE_MASTER_PROTECTION, PASSWORD_MP);
    local.store.set(STORAGE_INTEGRITY, { iv: "AAAA", ciphertext: "AAAA" });
    local.store.set(
      `${STORAGE_INTEGRITY}_vault`,
      await masterProtectionDigest({ ...PASSWORD_MP, kdfSalt: "b2xk" }),
    );
    await saveContact(contact("A"));
    await loadContacts();
    await getPreferences();
    expect(kinds()).toEqual([]);
    expect(local.store.get(`${STORAGE_INTEGRITY}_vault`)).toBe(
      await masterProtectionDigest(PASSWORD_MP),
    );
  });

  it("deleted ledger after onboarding is reported", async () => {
    // Fresh modules: the panel that onboards has never run the legacy
    // migration (its settled flag is per module instance).
    vi.resetModules();
    const mp = await import("./master-protection");
    const prefs = await import("./preferences");
    const store = await import("./encrypted-store");

    // Onboarding's own writes, in its order.
    await mp.saveMasterProtection(PASSWORD_MP, "local");
    await prefs.savePreferences({ storageLocation: "local" });
    await store.saveEncryptedArray(
      { storageKey: STORAGE_KEYRING, isValid: anyItem, label: "k" },
      [{ keyId: "X" }],
    );
    await prefs.savePreferences({ defaultKeyId: "X" });
    await prefs.savePreferences({
      storageLocation: "local",
      onboardingComplete: true,
    });

    // Onboarding is done, so the main UI's first reads must not write
    // the ledger: a write landing then (the legacy migration settling,
    // as it used to) read the ledger before a deletion and put it back
    // after, without its `lost` flag, and the deletion went unseen.
    const ledger = local.store.get(STORAGE_INTEGRITY);
    expect(ledger).toBeDefined();
    await prefs.getPreferences();
    expect(local.store.get(STORAGE_INTEGRITY)).toEqual(ledger);

    // The attacker deletes it; the next panel to unlock reports it.
    local.store.delete(STORAGE_INTEGRITY);
    vi.resetModules();
    const unlocked = await import("./preferences");
    const integrity = await import("./integrity");
    await unlocked.migrateLegacyPreferences();
    expect(await unlocked.getPreferences()).toMatchObject(STRICT);
    expect(
      integrity.integrityIssues().map((i) => `${i.store}:${i.kind}`),
    ).toContain(`${STORAGE_INTEGRITY}:missing`);
  });

  it("still warns about an unreadable ledger of the SAME vault", async () => {
    await saveMasterProtection(PASSWORD_MP, "local");
    await saveContact(contact("A"));
    local.store.set(STORAGE_INTEGRITY, { iv: "AAAA", ciphertext: "AAAA" });
    await loadContacts();
    expect(kinds()).toEqual([`${STORAGE_INTEGRITY}:ledger-unreadable`]);
  });
});

describe("F5: the storage switch", () => {
  async function localVault() {
    await saveMasterProtection(PASSWORD_MP, "local");
    await savePreferences({ storageLocation: "local" });
    await saveContact(contact("A"));
  }

  it("a failed bootstrap write leaves the device on the area that still holds the vault", async () => {
    await localVault();
    const realSet = sync.set.bind(sync);
    sync.set = (items: Record<string, unknown>) =>
      STORAGE_PREFERENCES in items
        ? Promise.reject(new Error("Resource::kQuotaBytes quota exceeded"))
        : realSet(items);

    await expect(moveVault("local", "sync")).rejects.toThrow(/quota/i);

    expect(local.store.get(STORAGE_DEVICE_LOCATION)).toBe("local");
    expect(sync.store.has(STORAGE_MASTER_PROTECTION)).toBe(false);
    expect(sync.store.has(STORAGE_CONTACTS)).toBe(false);
    invalidateLocationCache();
    expect(await resolveVaultState()).toMatchObject({ kind: "ready" });
    expect((await loadContacts()).map((c) => c.keyId)).toEqual(["A"]);
  });

  it("copies the master protection first and deletes it last", async () => {
    await localVault();
    const events: string[] = [];
    const base = (k: string) => k.split("::")[0];
    const realSet = sync.set.bind(sync);
    sync.set = (items: Record<string, unknown>) => {
      for (const k of Object.keys(items)) events.push(`copy:${base(k)}`);
      return realSet(items);
    };
    const realRemove = local.remove.bind(local);
    local.remove = (keys: string | string[]) => {
      for (const k of [keys].flat()) events.push(`purge:${base(k)}`);
      return realRemove(keys);
    };

    await moveVault("local", "sync");

    const copies = events.filter(
      (e) => e.startsWith("copy:") && e !== `copy:${STORAGE_PREFERENCES}`,
    );
    const purges = events.filter((e) => e.startsWith("purge:"));
    expect(copies[0]).toBe(`copy:${STORAGE_MASTER_PROTECTION}`);
    expect(purges.at(-1)).toBe(`purge:${STORAGE_MASTER_PROTECTION}`);
    expect(local.store.get(STORAGE_DEVICE_LOCATION)).toBe("sync");
    expect(await resolveVaultState()).toMatchObject({ kind: "ready" });
    expect((await loadContacts()).map((c) => c.keyId)).toEqual(["A"]);
  });

  it("does not call a vault orphaned on a glimpse mid-switch", async () => {
    ORPHAN_RECHECK_MS.value = 30;
    await saveContact(contact("REAL"));
    const state = resolveVaultState();
    // The master protection lands while the first look waits to re-check.
    setTimeout(
      () => local.store.set(STORAGE_MASTER_PROTECTION, PASSWORD_MP),
      5,
    );
    expect(await state).toMatchObject({ kind: "ready" });
  });
});

describe("F6: the legacy-settings migration runs before any store write", () => {
  function seedPreGenerationInstall() {
    local.store.set(
      STORAGE_CONTACTS,
      sealedWithoutGeneration(STORAGE_CONTACTS, [contact("OLD")]),
    );
    local.store.set(STORAGE_PREFERENCES, {
      advancedMode: true,
      autoLockMinutes: 5,
    });
  }

  it("migrates a genuine pre-generation install when the unlock runs it first", async () => {
    seedPreGenerationInstall();
    vi.resetModules();
    const prefs = await import("./preferences");
    const contacts = await import("./contacts");

    // App's onUnlocked: migration, then the contacts backfill's write.
    await prefs.migrateLegacyPreferences();
    await contacts.updateContact("OLD", (c) => ({ ...c, lastUsedAt: 2 }));

    expect(await prefs.getPreferences()).toMatchObject({
      advancedMode: true,
      autoLockMinutes: 5,
    });
  });

  it("(why the order matters) a store write first refuses it", async () => {
    seedPreGenerationInstall();
    vi.resetModules();
    const prefs = await import("./preferences");
    const contacts = await import("./contacts");

    await contacts.updateContact("OLD", (c) => ({ ...c, lastUsedAt: 2 }));
    const read = await prefs.getPreferences();
    expect(read.advancedMode).toBe(false);
    expect(local.store.has(STORAGE_PREFERENCES)).toBe(false);
  });
});
