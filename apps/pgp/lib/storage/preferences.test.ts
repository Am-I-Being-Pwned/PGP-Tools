/**
 * Preferences and the bootstrap/settings split: `storageLocation` and
 * `onboardingComplete` live in a plaintext sync blob (read before unlock);
 * everything else is encrypted. A settings field leaking into the
 * bootstrap syncs in the clear. The legacy migration overwrites rather
 * than merges, so it must be idempotent and crash-safe.
 *
 * `migrationSettled` is module-level, so each test re-imports the module.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { STORAGE_PREFERENCES, STORAGE_SETTINGS } from "~/lib/constants";
import { stubChromeStorage, type FakeArea } from "./fake-area";
import {
  isDomainSealed,
  legacyEnvelope,
  storedPlaintext,
} from "./fake-store-crypto";
import { unpadPlaintext } from "./padding";

const wasmMock = vi.hoisted(() => ({ session: true }));

vi.mock("../pgp/wasm", async () =>
  (await import("./fake-store-crypto")).fakeStoreWasm(() => wasmMock.session),
);

let local: FakeArea;
let sync: FakeArea;

/** Fresh module instance, so `migrationSettled` starts false. */
async function loadModule() {
  vi.resetModules();
  return import("./preferences");
}

beforeEach(() => {
  ({ local, sync } = stubChromeStorage());
  wasmMock.session = true;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** The settings object inside the encrypted blob, whichever area holds it. */
function storedSettings(area: FakeArea = local) {
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
    // Must work before there is any session.
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

  it("reads a settings blob that decrypts to a non-object as the strictest preset", async () => {
    // A sealed blob opening to something no build writes is tampering, not
    // "nothing stored".
    local.store.set(
      STORAGE_SETTINGS,
      legacyEnvelope(new TextEncoder().encode(JSON.stringify("nope"))),
    );
    const { getPreferences, strictestPreferences } = await loadModule();
    await expect(getPreferences()).resolves.toEqual(strictestPreferences());
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
    // Pre-split fallback: losing it would re-run onboarding.
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

  it("reads unlockKeysOnOpen as false from a blob written before it existed, and round-trips true", async () => {
    // Off by default is a security property (SECURITY.md section 14).
    local.store.set(
      STORAGE_SETTINGS,
      legacyEnvelope(
        new TextEncoder().encode(JSON.stringify({ advancedMode: true })),
      ),
    );
    const { getPreferences, savePreferences } = await loadModule();

    await expect(getPreferences()).resolves.toMatchObject({
      unlockKeysOnOpen: false,
    });

    await savePreferences({ unlockKeysOnOpen: true });

    expect(storedSettings()).toMatchObject({ unlockKeysOnOpen: true });
    await expect(getPreferences()).resolves.toMatchObject({
      unlockKeysOnOpen: true,
    });
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
    // Merging would leave legacy settings in the clear in sync. The object is
    // in BOTH areas: local is the migration source, sync must end with only
    // the two boot fields.
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
    // No session: settling here would strand the legacy object unencrypted.
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
    // Crash-safety: a re-run must not clobber the good blob.
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
