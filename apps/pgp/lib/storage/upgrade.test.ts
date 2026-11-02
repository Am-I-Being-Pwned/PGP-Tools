/**
 * Storage written by the published v1.3.1 build must load cleanly now.
 * Fixtures are hand-built from v1.3.1's formats: plaintext sync bootstrap,
 * a `pgp_settings` blob under the pre-domain shared envelope (padded on
 * `local` only), a draft with singular `selectedRecipientId`, and no
 * history keys.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { WorkspaceDraft } from "../workspace-draft";
import type { StoredEnvelope } from "./envelope";
import type { FakeArea } from "./fake-area";
import type { PgpPreferences } from "./preferences";
import { STORAGE_PREFERENCES, STORAGE_SETTINGS } from "../constants";
import { toBase64 } from "../encoding";
import {
  decryptWorkspaceDraft,
  encryptWorkspaceDraft,
} from "../workspace-draft";
import { stubChromeStorage } from "./fake-area";
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

// Fake WASM session (see fake-store-crypto.ts). The draft key is the
// identity except for one marker input that throws (undecryptable blob).
const wasmMock = vi.hoisted(() => ({ session: true }));

const UNDECRYPTABLE = new TextEncoder().encode("@@undecryptable@@");

vi.mock("../pgp/wasm", async () => ({
  ...(await import("./fake-store-crypto")).fakeStoreWasm(
    () => wasmMock.session,
  ),
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
}));

let local: FakeArea;
let sync: FakeArea;

beforeEach(() => {
  // No `permissions` key: history's budget code must tolerate its absence
  // (v1.3.1 never requested it; Firefox differs).
  ({ local, sync } = stubChromeStorage());
  wasmMock.session = true;
});

afterEach(() => {
  vi.unstubAllGlobals();
});

/** v1.3.1's twelve settings fields. `activeTab` has since been removed and
 *  is kept to prove an old blob carrying it still reads. */
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

function makeSettingsBlob(
  settings: Record<string, unknown>,
  location: "local" | "sync",
): { iv: string; ciphertext: string } {
  const json = new TextEncoder().encode(JSON.stringify(settings));
  const padded = padPlaintext(json, location === "local");
  return { iv: toBase64(new Uint8Array(12)), ciphertext: toBase64(padded) };
}

function seedV131Profile(location: "local" | "sync" = "local"): void {
  sync.store.set(STORAGE_PREFERENCES, {
    storageLocation: location,
    onboardingComplete: true,
  });
  const area = location === "local" ? local : sync;
  area.store.set(STORAGE_SETTINGS, makeSettingsBlob(V131_SETTINGS, location));
}

/** Decrypts either sealing scheme, for asserting what a write persisted. */
function readStoredSettings(area: FakeArea): Record<string, unknown> {
  const blob = area.store.get(STORAGE_SETTINGS) as StoredEnvelope;
  const plaintext = unpadPlaintext(storedPlaintext(blob));
  return JSON.parse(new TextDecoder().decode(plaintext)) as Record<
    string,
    unknown
  >;
}

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
    // A FUTURE version's unknown field must survive a read-merge-write.
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

  // v1.3.1 blobs have no domain binding: they must keep opening and be
  // upgraded on the first write.
  it("reads the legacy shared-envelope settings blob and upgrades it on write", async () => {
    seedV131Profile("local");
    expect(isDomainSealed(local.store.get(STORAGE_SETTINGS))).toBe(false);

    // Reading alone must not rewrite anything...
    const before = local.store.get(STORAGE_SETTINGS);
    await expect(getPreferences()).resolves.toMatchObject(V131_SETTINGS);
    expect(local.store.get(STORAGE_SETTINGS)).toBe(before);

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

describe("v1.3.1 workspace draft", () => {
  it("drops an old single-recipient draft gracefully (null, no throw)", async () => {
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

describe("preset state for an upgraded v1.3.1 user", () => {
  it("all-default upgraded prefs read as custom, not as a preset", async () => {
    const { activePreset, bundledSettingsCustomized } =
      await import("../presets");
    // Never touched settings: v1.3.1 only wrote the blob on the first change.
    sync.store.set(STORAGE_PREFERENCES, {
      storageLocation: "local",
      onboardingComplete: true,
    });

    const prefs: PgpPreferences = await getPreferences();
    expect(activePreset(prefs)).toBe("custom");
    expect(bundledSettingsCustomized(prefs)).toBe(false);
  });
});
