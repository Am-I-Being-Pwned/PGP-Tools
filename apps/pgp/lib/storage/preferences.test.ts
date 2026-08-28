/**
 * Preferences, and the bootstrap/settings split.
 *
 * Two fields -- `storageLocation` and `onboardingComplete` -- are read
 * BEFORE the vault is unlocked: the engine needs the first to know which
 * area to read from, and App needs the second to choose between
 * onboarding and the lock screen. So they live in a plaintext sync blob
 * while every other preference is encrypted. That split is the design,
 * and these tests pin both halves of it:
 *
 *  - a write must route each field to the correct side. A settings field
 *    that leaks into the plaintext bootstrap is a privacy regression that
 *    syncs itself to every machine on the account;
 *  - a locked vault must still yield the two boot fields, and defaults
 *    for the rest, rather than throwing -- the unlock screen needs none
 *    of the encrypted ones.
 *
 * The legacy migration gets the most attention because it is the one
 * path that can DESTROY a preference: it overwrites the sync bootstrap
 * rather than merging, deliberately, and a mistake there silently drops
 * settings. It must also be idempotent and crash-safe, since it can be
 * interrupted halfway.
 *
 * `migrationSettled` is module-level, so every test re-imports the
 * module to get a clean one.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { STORAGE_PREFERENCES, STORAGE_SETTINGS } from "../constants";
import { invalidateLocationCache } from "./engine";
import { fakeArea } from "./fake-area";
import {
  fakeDecryptContacts,
  fakeDecryptStore,
  fakeEncryptContacts,
  fakeEncryptStore,
  isDomainSealed,
  legacyEnvelope,
  storedPlaintext,
} from "./fake-store-crypto";
import { unpadPlaintext } from "./padding";

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

/** Fresh module instance, so `migrationSettled` starts false. */
async function loadModule() {
  vi.resetModules();
  return import("./preferences");
}

beforeEach(() => {
  local = fakeArea();
  sync = fakeArea();
  vi.stubGlobal("chrome", { storage: { local, sync } });
  wasmMock.session = true;
  invalidateLocationCache();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** The settings object inside the encrypted blob, whichever area holds it. */
function storedSettings(area: ReturnType<typeof fakeArea> = local) {
  const blob = area.store.get(STORAGE_SETTINGS);
  if (!blob) return undefined;
  const plaintext = unpadPlaintext(storedPlaintext(blob as never));
  return JSON.parse(new TextDecoder().decode(plaintext)) as Record<
    string,
    unknown
  >;
}

function boot() {
  return sync.store.get(STORAGE_PREFERENCES) as
    Record<string, unknown> | undefined;
}

describe("getPreferences", () => {
  it("returns the defaults on a fresh install", async () => {
    const { DEFAULT_PREFERENCES, getPreferences } = await loadModule();
    await expect(getPreferences()).resolves.toEqual(DEFAULT_PREFERENCES);
  });

  it("reads the boot fields from the plaintext sync blob", async () => {
    sync.store.set(STORAGE_PREFERENCES, {
      storageLocation: "sync",
      onboardingComplete: true,
    });
    const { getPreferences } = await loadModule();

    await expect(getPreferences()).resolves.toMatchObject({
      storageLocation: "sync",
      onboardingComplete: true,
    });
  });

  it("defaults storageLocation to local when the bootstrap is absent", async () => {
    const { getPreferences } = await loadModule();
    await expect(getPreferences()).resolves.toMatchObject({
      storageLocation: "local",
    });
  });

  it("overlays stored settings on the defaults", async () => {
    // A blob written before a field existed must read back as that
    // field's default rather than as undefined.
    const { getPreferences, savePreferences, DEFAULT_PREFERENCES } =
      await loadModule();
    await savePreferences({ advancedMode: true });

    const prefs = await getPreferences();
    expect(prefs.advancedMode).toBe(true);
    expect(prefs.autoLockMinutes).toBe(DEFAULT_PREFERENCES.autoLockMinutes);
  });

  it("returns defaults for the encrypted half while locked", async () => {
    // The locked UI is just the unlock screen; it needs none of them.
    const { getPreferences, savePreferences, DEFAULT_PREFERENCES } =
      await loadModule();
    await savePreferences({ advancedMode: true });

    wasmMock.session = false;
    const prefs = await getPreferences();

    expect(prefs.advancedMode).toBe(DEFAULT_PREFERENCES.advancedMode);
  });

  it("still returns the boot fields while locked", async () => {
    // App needs onboardingComplete to decide what screen to show, and it
    // has to work before there is any session at all.
    sync.store.set(STORAGE_PREFERENCES, {
      storageLocation: "sync",
      onboardingComplete: true,
    });
    wasmMock.session = false;
    const { getPreferences } = await loadModule();

    await expect(getPreferences()).resolves.toMatchObject({
      storageLocation: "sync",
      onboardingComplete: true,
    });
  });

  it("ignores a corrupt settings blob rather than throwing", async () => {
    local.store.set(STORAGE_SETTINGS, "not-an-envelope");
    const { getPreferences, DEFAULT_PREFERENCES } = await loadModule();
    await expect(getPreferences()).resolves.toEqual(DEFAULT_PREFERENCES);
  });

  it("ignores a settings blob that decrypts to a non-object", async () => {
    local.store.set(
      STORAGE_SETTINGS,
      legacyEnvelope(new TextEncoder().encode(JSON.stringify("nope"))),
    );
    const { getPreferences, DEFAULT_PREFERENCES } = await loadModule();
    await expect(getPreferences()).resolves.toEqual(DEFAULT_PREFERENCES);
  });

  it("reads a pre-domain-separation settings blob", async () => {
    local.store.set(
      STORAGE_SETTINGS,
      legacyEnvelope(
        new TextEncoder().encode(JSON.stringify({ advancedMode: true })),
      ),
    );
    const { getPreferences } = await loadModule();
    await expect(getPreferences()).resolves.toMatchObject({
      advancedMode: true,
    });
  });

  it("falls back to the legacy object for onboardingComplete", async () => {
    // A local user's onboardingComplete may still sit in the legacy full
    // object rather than the bootstrap. Losing it re-runs onboarding for
    // someone who already finished it.
    wasmMock.session = false;
    local.store.set(STORAGE_PREFERENCES, {
      advancedMode: true,
      onboardingComplete: true,
    });
    const { getPreferences } = await loadModule();

    await expect(getPreferences()).resolves.toMatchObject({
      onboardingComplete: true,
    });
  });

  it("reads onboardingComplete as false when nothing records it", async () => {
    wasmMock.session = false;
    local.store.set(STORAGE_PREFERENCES, { advancedMode: true });
    const { getPreferences } = await loadModule();
    await expect(getPreferences()).resolves.toMatchObject({
      onboardingComplete: false,
    });
  });
});

describe("savePreferences", () => {
  it("routes boot fields to plaintext sync", async () => {
    const { savePreferences } = await loadModule();
    await savePreferences({ storageLocation: "sync" });

    expect(boot()).toMatchObject({ storageLocation: "sync" });
    expect(local.store.has(STORAGE_SETTINGS)).toBe(false);
  });

  it("routes settings fields to the encrypted blob", async () => {
    const { savePreferences } = await loadModule();
    await savePreferences({ advancedMode: true });

    expect(isDomainSealed(local.store.get(STORAGE_SETTINGS))).toBe(true);
    expect(storedSettings()).toMatchObject({ advancedMode: true });
  });

  it("never writes a settings field into the plaintext bootstrap", async () => {
    // The regression that would sync a user's settings in the clear.
    const { savePreferences } = await loadModule();
    await savePreferences({ advancedMode: true, autoLockMinutes: 30 });

    expect(boot()).toBeUndefined();
  });

  it("splits a mixed patch across both sides", async () => {
    const { savePreferences } = await loadModule();
    await savePreferences({ storageLocation: "sync", advancedMode: true });

    expect(boot()).toEqual({ storageLocation: "sync" });
    expect(storedSettings(sync)).toMatchObject({ advancedMode: true });
  });

  it("merges rather than replaces the bootstrap", async () => {
    const { savePreferences } = await loadModule();
    await savePreferences({ onboardingComplete: true });
    await savePreferences({ storageLocation: "sync" });

    expect(boot()).toEqual({
      onboardingComplete: true,
      storageLocation: "sync",
    });
  });

  it("merges rather than replaces the settings, so rapid toggles don't clobber", async () => {
    const { savePreferences } = await loadModule();
    await savePreferences({ advancedMode: true });
    await savePreferences({ autoLockMinutes: 30 });

    expect(storedSettings()).toMatchObject({
      advancedMode: true,
      autoLockMinutes: 30,
    });
  });

  it("writes nothing for an empty patch", async () => {
    const { savePreferences } = await loadModule();
    await savePreferences({});

    expect(sync.store.size).toBe(0);
    expect(local.store.size).toBe(0);
  });

  it("skips the settings write while locked rather than throwing", async () => {
    // Losing a toggle beats crashing; this path shouldn't occur anyway,
    // since settings are only written from the unlocked UI.
    wasmMock.session = false;
    const { savePreferences } = await loadModule();

    await expect(
      savePreferences({ advancedMode: true }),
    ).resolves.toBeUndefined();
    expect(local.store.has(STORAGE_SETTINGS)).toBe(false);
  });

  it("still writes the boot half while locked", async () => {
    wasmMock.session = false;
    const { savePreferences } = await loadModule();
    await savePreferences({ onboardingComplete: true, advancedMode: true });

    expect(boot()).toEqual({ onboardingComplete: true });
  });

  it("fills unset fields from the defaults on first write", async () => {
    const { savePreferences, DEFAULT_PREFERENCES } = await loadModule();
    await savePreferences({ advancedMode: true });

    expect(storedSettings()).toMatchObject({
      autoLockMinutes: DEFAULT_PREFERENCES.autoLockMinutes,
      encryptToSelf: DEFAULT_PREFERENCES.encryptToSelf,
    });
  });
});

describe("legacy migration", () => {
  /** A pre-split plaintext object: boot fields AND settings together.
   *  `advancedMode` is what marks it as legacy. */
  const legacy = {
    storageLocation: "local" as const,
    onboardingComplete: true,
    advancedMode: true,
    autoLockMinutes: 30,
  };

  it("moves the settings half into the encrypted blob", async () => {
    local.store.set(STORAGE_PREFERENCES, legacy);
    sync.store.set(STORAGE_PREFERENCES, legacy);
    const { getPreferences } = await loadModule();

    await getPreferences();

    expect(storedSettings()).toMatchObject({
      advancedMode: true,
      autoLockMinutes: 30,
    });
  });

  it("OVERWRITES the sync bootstrap, leaving no plaintext settings behind", async () => {
    // Merging here would leave the legacy settings fields in the clear in
    // the sync object -- exactly what the migration exists to prevent.
    // The object sits in BOTH areas: `storageLocation: "local"` routes
    // the migration's read to local, while sync holds the copy that has
    // to come out of this with only the two boot fields left.
    local.store.set(STORAGE_PREFERENCES, legacy);
    sync.store.set(STORAGE_PREFERENCES, legacy);
    const { getPreferences } = await loadModule();

    await getPreferences();

    expect(boot()).toEqual({
      storageLocation: "local",
      onboardingComplete: true,
    });
    expect(boot()).not.toHaveProperty("advancedMode");
  });

  it("drops the local legacy object for a local user", async () => {
    local.store.set(STORAGE_PREFERENCES, legacy);
    const { getPreferences } = await loadModule();

    await getPreferences();

    expect(local.store.has(STORAGE_PREFERENCES)).toBe(false);
  });

  it("keeps the sync bootstrap for a sync user", async () => {
    // For a sync user the legacy object WAS the bootstrap; it is
    // overwritten in place, not removed.
    const syncLegacy = { ...legacy, storageLocation: "sync" as const };
    sync.store.set(STORAGE_PREFERENCES, syncLegacy);
    const { getPreferences } = await loadModule();

    await getPreferences();

    expect(boot()).toEqual({
      storageLocation: "sync",
      onboardingComplete: true,
    });
  });

  it("preserves the migrated values through the read", async () => {
    local.store.set(STORAGE_PREFERENCES, legacy);
    sync.store.set(STORAGE_PREFERENCES, legacy);
    const { getPreferences } = await loadModule();

    await expect(getPreferences()).resolves.toMatchObject({
      advancedMode: true,
      autoLockMinutes: 30,
      onboardingComplete: true,
    });
  });

  it("does not run while locked, and retries after unlock", async () => {
    // No session means no way to encrypt. Settling here would strand the
    // legacy object unencrypted forever.
    local.store.set(STORAGE_PREFERENCES, legacy);
    wasmMock.session = false;
    const { getPreferences } = await loadModule();

    await getPreferences();
    expect(local.store.get(STORAGE_PREFERENCES)).toEqual(legacy);

    wasmMock.session = true;
    await getPreferences();
    expect(local.store.has(STORAGE_PREFERENCES)).toBe(false);
  });

  it("is idempotent", async () => {
    local.store.set(STORAGE_PREFERENCES, legacy);
    sync.store.set(STORAGE_PREFERENCES, legacy);
    const { getPreferences } = await loadModule();

    await getPreferences();
    const after = storedSettings();
    await getPreferences();

    expect(storedSettings()).toEqual(after);
  });

  it("does not overwrite settings a crashed run already wrote", async () => {
    // Crash-safety: the legacy object is both the source AND the marker
    // that cleanup is owed, so a re-run must not clobber the good blob.
    const { savePreferences } = await loadModule();
    await savePreferences({ advancedMode: false, autoLockMinutes: 60 });

    local.store.set(STORAGE_PREFERENCES, legacy);
    const { getPreferences } = await loadModule();
    await getPreferences();

    expect(storedSettings()).toMatchObject({ autoLockMinutes: 60 });
  });

  it("leaves a post-split bootstrap alone", async () => {
    // Only an object carrying settings fields is legacy; the two-field
    // bootstrap must not be mistaken for one.
    const bootstrap = { storageLocation: "local", onboardingComplete: true };
    sync.store.set(STORAGE_PREFERENCES, bootstrap);
    const { getPreferences } = await loadModule();

    await getPreferences();

    expect(boot()).toEqual(bootstrap);
    expect(local.store.has(STORAGE_SETTINGS)).toBe(false);
  });
});
