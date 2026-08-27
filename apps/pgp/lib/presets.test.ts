import { describe, expect, it } from "vitest";

import type { PgpPreferences } from "./storage/preferences";
import {
  activePreset,
  bundledSettingsCustomized,
  describeBundle,
  PRESET_IDS,
  PRESETS,
  snapshotBundleFields,
} from "./presets";

/** A full preferences object with every field populated; tests overlay
 *  preset bundles on top of it. Mirrors the shipped defaults. */
function fullPrefs(overrides: Partial<PgpPreferences> = {}): PgpPreferences {
  return {
    defaultSigningKeyId: null,
    armoredOutput: true,
    advancedMode: false,
    storageLocation: "local",
    onboardingComplete: true,
    autoLockMinutes: 15,
    signWhenEncrypting: false,
    encryptToSelf: true,
    neverCacheKeys: false,
    autoDownloadFiles: false,
    autoDownloadText: false,
    autoLockEnabled: true,
    lockOnTabAway: false,
    crxSigningEnabled: false,
    historyEnabled: false,
    keyDiscoveryEnabled: true,
    clipboardWipeSeconds: 60,
    recentRecipients: [],
    aiTranslateEnabled: true,
    translationTargetLanguage: "en",
    defaultKeyId: null,
    ...overrides,
  };
}

describe("PRESETS", () => {
  it("casual bundles exactly the expected fields", () => {
    expect(PRESETS.casual.bundle).toEqual({
      autoLockEnabled: true,
      autoLockMinutes: 30,
      lockOnTabAway: false,
      neverCacheKeys: false,
      historyEnabled: true,
      keyDiscoveryEnabled: true,
      encryptToSelf: true,
      clipboardWipeSeconds: 60,
    });
  });

  it("careful bundles exactly the expected fields and is recommended", () => {
    expect(PRESETS.careful.bundle).toEqual({
      autoLockEnabled: true,
      autoLockMinutes: 10,
      lockOnTabAway: false,
      neverCacheKeys: false,
      historyEnabled: true,
      keyDiscoveryEnabled: true,
      encryptToSelf: true,
      storageLocation: "local",
      clipboardWipeSeconds: 60,
    });
    expect(PRESETS.careful.recommended).toBe(true);
  });

  it("paranoid bundles exactly the expected fields", () => {
    expect(PRESETS.paranoid.bundle).toEqual({
      autoLockEnabled: true,
      autoLockMinutes: 2,
      lockOnTabAway: true,
      neverCacheKeys: true,
      historyEnabled: false,
      keyDiscoveryEnabled: false,
      encryptToSelf: true,
      storageLocation: "local",
      clipboardWipeSeconds: 15,
      aiTranslateEnabled: false,
    });
  });

  it("is the only preset that decides the translation setting", () => {
    expect(PRESETS.paranoid.bundle.aiTranslateEnabled).toBe(false);
    // Casual and Careful deliberately leave an opt-in feature the user
    // turned on alone, rather than flipping it as a side effect.
    expect("aiTranslateEnabled" in PRESETS.casual.bundle).toBe(false);
    expect("aiTranslateEnabled" in PRESETS.careful.bundle).toBe(false);
  });

  it("uses the exact strictest-preset title", () => {
    expect(PRESETS.paranoid.title).toBe("If this leaks, I'm in trouble");
  });

  it("titles and taglines contain no em-dashes", () => {
    for (const id of PRESET_IDS) {
      expect(PRESETS[id].title).not.toMatch(/—/);
      expect(PRESETS[id].tagline).not.toMatch(/—/);
    }
  });
});

describe("activePreset", () => {
  it.each(PRESET_IDS)("detects %s from an exact bundle match", (id) => {
    expect(activePreset(fullPrefs(PRESETS[id].bundle))).toBe(id);
  });

  it("returns custom when one casual field is off", () => {
    const prefs = fullPrefs({
      ...PRESETS.casual.bundle,
      historyEnabled: false,
    });
    expect(activePreset(prefs)).toBe("custom");
  });

  it("returns custom when one careful field is off", () => {
    const prefs = fullPrefs({ ...PRESETS.careful.bundle, autoLockMinutes: 15 });
    expect(activePreset(prefs)).toBe("custom");
  });

  it("returns custom when one paranoid field is off", () => {
    const prefs = fullPrefs({
      ...PRESETS.paranoid.bundle,
      historyEnabled: true,
    });
    expect(activePreset(prefs)).toBe("custom");
  });

  it("returns custom when paranoid users later disable encrypt-to-self", () => {
    const prefs = fullPrefs({
      ...PRESETS.paranoid.bundle,
      encryptToSelf: false,
    });
    expect(activePreset(prefs)).toBe("custom");
  });

  it("ignores preferences outside the bundles", () => {
    const prefs = fullPrefs({
      ...PRESETS.careful.bundle,
      advancedMode: true,
      armoredOutput: false,
    });
    expect(activePreset(prefs)).toBe("careful");
  });

  it("is unaffected by the default key preference", () => {
    const prefs = fullPrefs({
      ...PRESETS.careful.bundle,
      defaultKeyId: "ABCD1234",
    });
    expect(activePreset(prefs)).toBe("careful");
  });

  it("reads all-default prefs (an upgrader who never chose) as custom", () => {
    expect(activePreset(fullPrefs())).toBe("custom");
  });
});

describe("bundledSettingsCustomized", () => {
  it("is false on shipped defaults (upgrader who never chose a preset)", () => {
    expect(bundledSettingsCustomized(fullPrefs())).toBe(false);
  });

  it("is true once any bundled setting deviates from the defaults", () => {
    expect(bundledSettingsCustomized(fullPrefs({ autoLockMinutes: 30 }))).toBe(
      true,
    );
    expect(bundledSettingsCustomized(fullPrefs({ encryptToSelf: false }))).toBe(
      true,
    );
  });

  it("ignores preferences outside every bundle", () => {
    expect(
      bundledSettingsCustomized(
        fullPrefs({ advancedMode: true, defaultKeyId: "ABCD1234" }),
      ),
    ).toBe(false);
  });

  it("is true after applying any preset bundle (they all deviate)", () => {
    for (const id of PRESET_IDS) {
      expect(bundledSettingsCustomized(fullPrefs(PRESETS[id].bundle))).toBe(
        true,
      );
    }
  });
});

describe("describeBundle", () => {
  it("describes casual", () => {
    expect(describeBundle(PRESETS.casual.bundle)).toEqual([
      "Auto-lock after 30 minutes",
      "Unlocked keys stay cached until you lock",
      "Keeps an encrypted history of what you do",
      "Keys can be looked up on GitHub and keys.openpgp.org",
      "Copied secrets clear from the clipboard after 60 seconds",
    ]);
  });

  it("describes careful", () => {
    expect(describeBundle(PRESETS.careful.bundle)).toEqual([
      "Auto-lock after 10 minutes",
      "Unlocked keys stay cached until you lock",
      "Keeps an encrypted history of what you do",
      "Keys can be looked up on GitHub and keys.openpgp.org",
      "Keys stay on this device",
      "Copied secrets clear from the clipboard after 60 seconds",
    ]);
  });

  it("describes paranoid", () => {
    expect(describeBundle(PRESETS.paranoid.bundle)).toEqual([
      "Auto-lock after 2 minutes and when you switch tabs",
      "Keys drop from memory after every use",
      "No history is kept",
      "No key lookups - nothing leaves this device to find a key",
      "Keys stay on this device",
      "Copied secrets clear from the clipboard after 15 seconds",
    ]);
  });

  it("contains no em-dashes", () => {
    for (const id of PRESET_IDS) {
      for (const line of describeBundle(PRESETS[id].bundle)) {
        expect(line).not.toMatch(/—/);
      }
    }
  });
});

describe("snapshotBundleFields", () => {
  it("captures exactly the bundled fields, with the CURRENT values", () => {
    const prefs = fullPrefs({
      autoLockEnabled: false,
      autoLockMinutes: 60,
      lockOnTabAway: true,
      neverCacheKeys: true,
      historyEnabled: true,
      encryptToSelf: false,
      clipboardWipeSeconds: 15,
    });
    expect(snapshotBundleFields(prefs, PRESETS.casual.bundle)).toEqual({
      autoLockEnabled: false,
      autoLockMinutes: 60,
      lockOnTabAway: true,
      neverCacheKeys: true,
      historyEnabled: true,
      // Captured from `prefs`, which leaves it at the shipped default --
      // the point of the snapshot is the CURRENT value, not the
      // bundle's.
      keyDiscoveryEnabled: true,
      encryptToSelf: false,
      clipboardWipeSeconds: 15,
    });
  });

  it("includes storageLocation only when the bundle sets it", () => {
    const prefs = fullPrefs({ storageLocation: "sync" });
    expect(
      snapshotBundleFields(prefs, PRESETS.casual.bundle),
    ).not.toHaveProperty("storageLocation");
    expect(
      snapshotBundleFields(prefs, PRESETS.paranoid.bundle).storageLocation,
    ).toBe("sync");
  });

  it("never captures fields outside the bundle", () => {
    const prefs = fullPrefs({ advancedMode: true, defaultKeyId: "abc" });
    const snapshot = snapshotBundleFields(prefs, PRESETS.careful.bundle);
    expect(Object.keys(snapshot).sort()).toEqual(
      Object.keys(PRESETS.careful.bundle).sort(),
    );
  });

  it("round-trips: applying a bundle then the snapshot restores prefs", () => {
    const before = fullPrefs({ autoLockMinutes: 60, historyEnabled: false });
    const snapshot = snapshotBundleFields(before, PRESETS.casual.bundle);
    const applied = { ...before, ...PRESETS.casual.bundle };
    expect({ ...applied, ...snapshot }).toEqual(before);
  });
});
