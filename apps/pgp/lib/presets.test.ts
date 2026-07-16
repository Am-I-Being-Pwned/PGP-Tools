import { describe, expect, it } from "vitest";

import type { PgpPreferences } from "./storage/preferences";
import { activePreset, describeBundle, PRESET_IDS, PRESETS } from "./presets";

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
    activeTab: "workspace",
    neverCacheKeys: false,
    autoDownloadFiles: false,
    autoDownloadText: false,
    autoLockEnabled: true,
    lockOnTabAway: false,
    crxSigningEnabled: false,
    historyEnabled: false,
    clipboardWipeSeconds: 60,
    recentRecipients: [],
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
      encryptToSelf: true,
      storageLocation: "local",
      clipboardWipeSeconds: 15,
    });
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
});

describe("describeBundle", () => {
  it("describes casual", () => {
    expect(describeBundle(PRESETS.casual.bundle)).toEqual([
      "Auto-lock after 30 minutes",
      "Unlocked keys stay cached until you lock",
      "Keeps an encrypted history of what you do",
      "Copied secrets clear from the clipboard after 60 seconds",
    ]);
  });

  it("describes careful", () => {
    expect(describeBundle(PRESETS.careful.bundle)).toEqual([
      "Auto-lock after 10 minutes",
      "Unlocked keys stay cached until you lock",
      "Keeps an encrypted history of what you do",
      "Keys stay on this device",
      "Copied secrets clear from the clipboard after 60 seconds",
    ]);
  });

  it("describes paranoid", () => {
    expect(describeBundle(PRESETS.paranoid.bundle)).toEqual([
      "Auto-lock after 2 minutes and when you switch tabs",
      "Keys drop from memory after every use",
      "No history is kept",
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
