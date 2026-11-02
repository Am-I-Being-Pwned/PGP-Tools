import type { PgpPreferences } from "./storage/preferences";
import { t, tn } from "./i18n";
import { DEFAULT_PREFERENCES } from "./storage/preferences";

export type PresetId = "casual" | "careful" | "paranoid";

/** Bundles apply only on explicit selection; nothing enforces them after. */
export interface SecurityPreset {
  /** Getter so `t()` runs at read time, not module load. */
  readonly title: string;
  readonly tagline: string;
  recommended?: boolean;
  bundle: Partial<PgpPreferences>;
}

/** Fallback when the sealed settings blob goes missing on a device that has
 *  seen it: tampering must not loosen settings (`storage/preferences.ts`). */
export const STRICTEST_PRESET: PresetId = "paranoid";

/** Picker display order (also the match order for activePreset). */
export const PRESET_IDS: readonly PresetId[] = [
  "casual",
  "careful",
  "paranoid",
];

export const PRESETS: Record<PresetId, SecurityPreset> = {
  casual: {
    get title() {
      return t("shared_preset_casual_title");
    },
    get tagline() {
      return t("shared_preset_casual_tagline");
    },
    bundle: {
      autoLockEnabled: true,
      autoLockMinutes: 30,
      lockOnTabAway: false,
      neverCacheKeys: false,
      // Passkey masters only (a password master has no PRF output to reuse).
      unlockKeysOnOpen: true,
      historyEnabled: true,
      keyDiscoveryEnabled: true,
      encryptToSelf: true,
    },
  },
  careful: {
    get title() {
      return t("shared_preset_careful_title");
    },
    get tagline() {
      return t("shared_preset_careful_tagline");
    },
    recommended: true,
    bundle: {
      autoLockEnabled: true,
      autoLockMinutes: 10,
      lockOnTabAway: false,
      neverCacheKeys: false,
      historyEnabled: true,
      keyDiscoveryEnabled: true,
      encryptToSelf: true,
      storageLocation: "local",
    },
  },
  paranoid: {
    get title() {
      return t("shared_preset_paranoid_title");
    },
    get tagline() {
      return t("shared_preset_paranoid_tagline");
    },
    bundle: {
      autoLockEnabled: true,
      autoLockMinutes: 2,
      lockOnTabAway: true,
      neverCacheKeys: true,
      // Opposite of never-cache; other presets leave the user's opt-in alone.
      unlockKeysOnOpen: false,
      historyEnabled: false,
      // A lookup tells GitHub/keys.openpgp.org this network is about to
      // write to that person.
      keyDiscoveryEnabled: false,
      encryptToSelf: true,
      storageLocation: "local",
      // Hands plaintext to a model of unverifiable locality
      // (T-AI-PLAINTEXT-DISCLOSURE). Other presets leave the opt-in alone.
      aiTranslateEnabled: false,
    },
  },
};

/** First preset whose bundle matches exactly, else "custom". Never stored. */
export function activePreset(prefs: PgpPreferences): PresetId | "custom" {
  for (const id of PRESET_IDS) {
    const bundle: Partial<PgpPreferences> = PRESETS[id].bundle;
    const matches = Object.entries(bundle).every(
      ([key, value]) => prefs[key as keyof PgpPreferences] === value,
    );
    if (matches) return id;
  }
  return "custom";
}

/** Whether any bundle-settable preference differs from defaults; tells a
 *  "custom" user who changed something from one who never picked a preset. */
export function bundledSettingsCustomized(prefs: PgpPreferences): boolean {
  const keys = new Set<keyof PgpPreferences>();
  for (const id of PRESET_IDS) {
    for (const key of Object.keys(PRESETS[id].bundle)) {
      keys.add(key as keyof PgpPreferences);
    }
  }
  return [...keys].some((key) => prefs[key] !== DEFAULT_PREFERENCES[key]);
}

/** Current values of exactly the bundle's keys, for Undo. */
export function snapshotBundleFields(
  prefs: PgpPreferences,
  bundle: Partial<PgpPreferences>,
): Partial<PgpPreferences> {
  const snapshot: Partial<PgpPreferences> = {};
  for (const key of Object.keys(bundle) as (keyof PgpPreferences)[]) {
    (snapshot as Record<string, unknown>)[key] = prefs[key];
  }
  return snapshot;
}

/** Canonical line order so cards read consistently across presets. */
type BundleLine = (bundle: Partial<PgpPreferences>) => string | null;

const LINE_BUILDERS: BundleLine[] = [
  (b) => {
    if (b.autoLockEnabled === false) return t("shared_bundle_auto_lock_off");
    if (b.autoLockMinutes === undefined) return null;
    const duration = tn("shared_minutes", b.autoLockMinutes);
    return b.lockOnTabAway
      ? t("shared_bundle_auto_lock_tabs", { duration })
      : t("shared_bundle_auto_lock", { duration });
  },
  (b) => {
    if (b.neverCacheKeys === undefined) return null;
    return b.neverCacheKeys
      ? t("shared_bundle_never_cache_on")
      : t("shared_bundle_never_cache_off");
  },
  (b) => {
    if (b.unlockKeysOnOpen === undefined) return null;
    return b.unlockKeysOnOpen
      ? t("shared_bundle_unlock_on_open_on")
      : t("shared_bundle_unlock_on_open_off");
  },
  (b) => {
    if (b.historyEnabled === undefined) return null;
    return b.historyEnabled
      ? t("shared_bundle_history_on")
      : t("shared_bundle_history_off");
  },
  (b) => {
    if (b.keyDiscoveryEnabled === undefined) return null;
    return b.keyDiscoveryEnabled
      ? t("shared_bundle_discovery_on")
      : t("shared_bundle_discovery_off");
  },
  (b) => {
    if (b.storageLocation === undefined) return null;
    return b.storageLocation === "local"
      ? t("shared_bundle_storage_local")
      : t("shared_bundle_storage_sync");
  },
  // On everywhere by default, so only an explicit "off" gets a line.
  (b) => {
    if (b.encryptToSelf !== false) return null;
    return t("shared_bundle_no_encrypt_to_self");
  },
];

export function describeBundle(bundle: Partial<PgpPreferences>): string[] {
  return LINE_BUILDERS.map((build) => build(bundle)).filter(
    (line): line is string => line !== null,
  );
}
