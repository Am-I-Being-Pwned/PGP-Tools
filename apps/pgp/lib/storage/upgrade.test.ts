/**
 * Upgrade-path tests: storage written by the published v1.3.1 build must
 * load cleanly in the current version.
 *
 * Fixtures are built by hand from v1.3.1's storage formats (see
 * `git show main:apps/pgp/lib/storage/preferences.ts` and
 * `git show main:apps/pgp/lib/workspace-draft.ts`):
 *
 *  - sync `pgp_preferences`: plaintext bootstrap
 *    `{ storageLocation, onboardingComplete }`
 *  - `pgp_settings` (engine-routed): `{ iv, ciphertext }` where the
 *    plaintext is JSON of the twelve v1.3.1 settings fields, padded on
 *    `local`, unpadded on `sync`, and sealed under the pre-domain-
 *    separation shared envelope (one key + one AAD for every store)
 *  - workspace draft ciphertext: JSON with a single
 *    `selectedRecipientId: string | null` (now `selectedRecipientIds`)
 *  - history keys (`pgp_history*`): did not exist at all
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { WorkspaceDraft } from "../workspace-draft";
import type { StoredEnvelope } from "./envelope";
import type { PgpPreferences } from "./preferences";
import { STORAGE_PREFERENCES, STORAGE_SETTINGS } from "../constants";
import { toBase64 } from "../encoding";
import {
  decryptWorkspaceDraft,
  encryptWorkspaceDraft,
} from "../workspace-draft";
import { invalidateLocationCache } from "./engine";
import {
  isDomainSealed,
  sealedDomain,
  storedPlaintext,
} from "./fake-store-crypto";
import {
  hasUnlimitedStorage,
  historyByteSize,
  loadHistory,
  requestUnlimitedHistoryStorage,
} from "./history";
import { padPlaintext, unpadPlaintext } from "./padding";
import { getPreferences, savePreferences } from "./preferences";

// Fake WASM session (see fake-store-crypto.ts): the domain-bound
// primitives tag the plaintext with their domain, the legacy shared ones
// are the identity transform v1.3.1 effectively had. The draft key uses an
// identity transform too, except for one marker input that throws to
// simulate an undecryptable blob.
const wasmMock = vi.hoisted(() => ({ session: true }));

const UNDECRYPTABLE = new TextEncoder().encode("@@undecryptable@@");

vi.mock("../pgp/wasm", async () => {
  const fake = await import("./fake-store-crypto");
  return {
    hasContactsSession: () => Promise.resolve(wasmMock.session),
    encryptStore: (domain: string, plaintext: Uint8Array) =>
      Promise.resolve(fake.fakeEncryptStore(domain, plaintext)),
    decryptStore: (domain: string, ciphertext: Uint8Array) =>
      Promise.resolve(fake.fakeDecryptStore(domain, ciphertext)),
    encryptContacts: (plaintext: Uint8Array) =>
      Promise.resolve(fake.fakeEncryptContacts(plaintext)),
    decryptContacts: (ciphertext: Uint8Array) =>
      Promise.resolve(fake.fakeDecryptContacts(ciphertext)),
    encryptDraft: (plaintext: Uint8Array) =>
      Promise.resolve(new Uint8Array(plaintext)),
    decryptDraft: (ciphertext: Uint8Array) => {
      if (
        ciphertext.length === UNDECRYPTABLE.length &&
        ciphertext.every((b, i) => b === UNDECRYPTABLE[i])
      ) {
        return Promise.reject(new Error("decryption failed"));
      }
      return Promise.resolve(new Uint8Array(ciphertext));
    },
  };
});

/** In-memory chrome.storage area (same shape as history.test.ts). */
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
let sync: ReturnType<typeof fakeArea>;

beforeEach(() => {
  local = fakeArea();
  sync = fakeArea();
  // Deliberately NO `permissions` key: v1.3.1 never requested
  // unlimitedStorage, and Firefox doesn't expose chrome.permissions the
  // same way -- history's budget code must tolerate its absence.
  vi.stubGlobal("chrome", { storage: { local, sync } });
  wasmMock.session = true;
  invalidateLocationCache();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── v1.3.1 fixtures ──────────────────────────────────────────────────

/** The settings blob exactly as v1.3.1's saveSettings wrote it: the
 *  twelve then-known settings fields (bootstrap fields excluded), none
 *  of the fields added since. `activeTab` is deliberately still here --
 *  it has since been REMOVED as a preference, and this fixture proves an
 *  old blob carrying it still reads back fine. */
const V131_SETTINGS = {
  defaultSigningKeyId: "SIGKEY01",
  armoredOutput: false,
  advancedMode: true,
  autoLockMinutes: 5,
  signWhenEncrypting: true,
  activeTab: "keys",
  neverCacheKeys: false,
  autoDownloadFiles: true,
  autoDownloadText: false,
  autoLockEnabled: true,
  lockOnTabAway: true,
  crxSigningEnabled: true,
};

/** Encrypt a settings object the way v1.3.1 stored it: JSON, padded on
 *  `local` (unpadded on `sync`), 12-byte IV prefix stripped into the
 *  `{ iv, ciphertext }` envelope. */
function makeSettingsBlob(
  settings: Record<string, unknown>,
  location: "local" | "sync",
): { iv: string; ciphertext: string } {
  const json = new TextEncoder().encode(JSON.stringify(settings));
  const padded = padPlaintext(json, location === "local");
  return { iv: toBase64(new Uint8Array(12)), ciphertext: toBase64(padded) };
}

/** Seed the fake storage with a complete v1.3.1 profile. */
function seedV131Profile(location: "local" | "sync" = "local"): void {
  sync.store.set(STORAGE_PREFERENCES, {
    storageLocation: location,
    onboardingComplete: true,
  });
  const area = location === "local" ? local : sync;
  area.store.set(STORAGE_SETTINGS, makeSettingsBlob(V131_SETTINGS, location));
}

/** Decrypt the stored settings blob back to its JSON object (test-side
 *  mirror of loadSettings, for asserting what a write persisted).
 *  `storedPlaintext` accepts either sealing scheme, so this works on a
 *  v1.3.1 fixture and on a blob the current build rewrote. */
function readStoredSettings(
  area: ReturnType<typeof fakeArea>,
): Record<string, unknown> {
  const blob = area.store.get(STORAGE_SETTINGS) as StoredEnvelope;
  const plaintext = unpadPlaintext(storedPlaintext(blob));
  return JSON.parse(new TextDecoder().decode(plaintext)) as Record<
    string,
    unknown
  >;
}

// ── preferences ──────────────────────────────────────────────────────

describe("v1.3.1 preferences blob", () => {
  it("loads with stored values preserved and new fields at their defaults", async () => {
    seedV131Profile("local");

    const prefs = await getPreferences();

    // Every v1.3.1 value survives verbatim.
    expect(prefs).toMatchObject(V131_SETTINGS);
    expect(prefs.storageLocation).toBe("local");
    expect(prefs.onboardingComplete).toBe(true);

    // Fields added since v1.3.1 come back as the shipped defaults.
    expect(prefs.encryptToSelf).toBe(true);
    expect(prefs.historyEnabled).toBe(false);
    expect(prefs.clipboardWipeSeconds).toBe(60);
    expect(prefs.recentRecipients).toEqual([]);
    expect(prefs.defaultKeyId).toBeNull();
  });

  it("loads a sync-located v1.3.1 profile (unpadded blob)", async () => {
    seedV131Profile("sync");

    const prefs = await getPreferences();
    expect(prefs).toMatchObject(V131_SETTINGS);
    expect(prefs.storageLocation).toBe("sync");
    expect(prefs.encryptToSelf).toBe(true);
  });

  it.each([5, 15, 30, 60] as const)(
    "keeps a stored v1.3.1 autoLockMinutes of %i",
    async (minutes) => {
      sync.store.set(STORAGE_PREFERENCES, {
        storageLocation: "local",
        onboardingComplete: true,
      });
      local.store.set(
        STORAGE_SETTINGS,
        makeSettingsBlob(
          { ...V131_SETTINGS, autoLockMinutes: minutes },
          "local",
        ),
      );

      const prefs = await getPreferences();
      expect(prefs.autoLockMinutes).toBe(minutes);
    },
  );

  it("returns pure defaults on a completely fresh profile", async () => {
    const prefs = await getPreferences();
    expect(prefs.onboardingComplete).toBe(false);
    expect(prefs.storageLocation).toBe("local");
    expect(prefs.autoLockMinutes).toBe(15);
    expect(prefs.recentRecipients).toEqual([]);
  });

  it("savePreferences preserves fields it does not know (downgrade safety)", async () => {
    // Simulate a blob written by a FUTURE version: contains a field this
    // build has never heard of. A read-merge-write must carry it along.
    sync.store.set(STORAGE_PREFERENCES, {
      storageLocation: "local",
      onboardingComplete: true,
    });
    local.store.set(
      STORAGE_SETTINGS,
      makeSettingsBlob({ ...V131_SETTINGS, futureFeature: "keep-me" }, "local"),
    );

    await savePreferences({ armoredOutput: true });

    const stored = readStoredSettings(local);
    expect(stored.futureFeature).toBe("keep-me");
    expect(stored.armoredOutput).toBe(true);
    // Untouched v1.3.1 fields survive the merge too.
    expect(stored.defaultSigningKeyId).toBe("SIGKEY01");
  });

  // v1.3.1 sealed every store under one shared key and one shared AAD, so
  // its blobs carry no domain binding. They must keep opening (the legacy
  // fallback in envelope.ts), and the first write must upgrade them.
  it("reads the legacy shared-envelope settings blob and upgrades it on write", async () => {
    seedV131Profile("local");
    expect(isDomainSealed(local.store.get(STORAGE_SETTINGS))).toBe(false);

    // Reading alone must not rewrite anything...
    const before = local.store.get(STORAGE_SETTINGS);
    await expect(getPreferences()).resolves.toMatchObject(V131_SETTINGS);
    expect(local.store.get(STORAGE_SETTINGS)).toBe(before);

    // ...but the next write reseals for the settings key as its domain,
    // carrying every v1.3.1 field across.
    await savePreferences({ armoredOutput: true });
    const blob = local.store.get(STORAGE_SETTINGS);
    expect(isDomainSealed(blob)).toBe(true);
    expect(sealedDomain(blob)).toBe(STORAGE_SETTINGS);
    expect(readStoredSettings(local)).toMatchObject({
      ...V131_SETTINGS,
      armoredOutput: true,
    });
    await expect(getPreferences()).resolves.toMatchObject({
      ...V131_SETTINGS,
      armoredOutput: true,
    });
  });

  it("writing one new-field preference does not disturb v1.3.1 fields", async () => {
    seedV131Profile("local");

    await savePreferences({ historyEnabled: true });

    const prefs = await getPreferences();
    expect(prefs.historyEnabled).toBe(true);
    expect(prefs).toMatchObject({ ...V131_SETTINGS, historyEnabled: true });
  });
});

// ── workspace draft ──────────────────────────────────────────────────

describe("v1.3.1 workspace draft", () => {
  it("drops an old single-recipient draft gracefully (null, no throw)", async () => {
    // Exactly the shape v1.3.1 serialised: selectedRecipientId (singular).
    const oldDraft = {
      mode: "encrypt",
      input: "hello",
      output: "",
      selectedRecipientId: "ABCD1234",
      selectedKeyId: null,
    };
    const ciphertext = new TextEncoder().encode(JSON.stringify(oldDraft));

    await expect(decryptWorkspaceDraft(ciphertext)).resolves.toBeNull();
  });

  it("returns null (not a throw) for an undecryptable draft blob", async () => {
    await expect(
      decryptWorkspaceDraft(new Uint8Array(UNDECRYPTABLE)),
    ).resolves.toBeNull();
  });

  it("returns null for non-JSON draft plaintext", async () => {
    const garbage = new TextEncoder().encode("not json at all");
    await expect(decryptWorkspaceDraft(garbage)).resolves.toBeNull();
  });

  it("round-trips a current-shape draft", async () => {
    const draft: WorkspaceDraft = {
      mode: "encrypt",
      input: "hello",
      output: "",
      selectedRecipientIds: ["ABCD1234", "EF567890"],
      selectedKeyId: "SIGKEY01",
    };
    const ct = await encryptWorkspaceDraft(draft);
    await expect(decryptWorkspaceDraft(ct)).resolves.toEqual(draft);
  });
});

// ── history ──────────────────────────────────────────────────────────

describe("history on a v1.3.1 profile (no history keys)", () => {
  it("loads as empty without creating keys or crashing", async () => {
    seedV131Profile("local");

    await expect(loadHistory()).resolves.toEqual([]);
    await expect(historyByteSize()).resolves.toBe(0);
    // A pure read must not invent history keys on the upgraded profile.
    const historyKeys = [...local.store.keys()].filter((k) =>
      k.startsWith("pgp_history"),
    );
    expect(historyKeys).toEqual([]);
  });

  it("treats an absent chrome.permissions API as no unlimited storage", async () => {
    await expect(hasUnlimitedStorage()).resolves.toBe(false);
    await expect(requestUnlimitedHistoryStorage()).resolves.toBe(false);
  });
});

// ── preset detection for upgraders ───────────────────────────────────

describe("preset state for an upgraded v1.3.1 user", () => {
  it("all-default upgraded prefs read as custom, not as a preset", async () => {
    const { activePreset, bundledSettingsCustomized } =
      await import("../presets");
    // A v1.3.1 user who never touched settings: bootstrap present, no
    // settings blob at all (v1.3.1 only wrote it on the first change).
    sync.store.set(STORAGE_PREFERENCES, {
      storageLocation: "local",
      onboardingComplete: true,
    });

    const prefs: PgpPreferences = await getPreferences();
    expect(activePreset(prefs)).toBe("custom");
    // ...but they never changed a bundled setting, so the UI must not
    // claim they did.
    expect(bundledSettingsCustomized(prefs)).toBe(false);
  });
});
