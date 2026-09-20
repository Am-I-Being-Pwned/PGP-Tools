import type { PgpPreferences } from "./storage/preferences";
import { t, tn } from "./i18n";
import { DEFAULT_PREFERENCES } from "./storage/preferences";

/** Identifier for a named security preset. */
export type PresetId = "casual" | "careful" | "paranoid";

/** A named threat-model preset: a title, a one-line tagline, and the
 *  bundle of preference values it applies. Bundles are applied only on
 *  explicit selection (onboarding or settings) via savePreferences;
 *  nothing enforces them afterwards. */
export interface SecurityPreset {
  /** Localised; a getter so `t()` runs at read time, not module load. */
  readonly title: string;
  readonly tagline: string;
  /** Highlight this preset as the recommended default in pickers. */
  recommended?: boolean;
  bundle: Partial<PgpPreferences>;
}

/** Picker display order (also the match order for activePreset). */
export const PRESET_IDS: readonly PresetId[] = [
  "casual",
  "careful",
  "paranoid",
];

/** The three threat-model presets, keyed by id. */
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
      // Convenience first: the vault prompt opens the keys too. Only
      // takes effect with a passkey master (a password master has no
      // PRF output to reuse); the app ignores it otherwise.
      unlockKeysOnOpen: true,
      historyEnabled: true,
      keyDiscoveryEnabled: true,
      encryptToSelf: true,
      clipboardWipeSeconds: 60,
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
      clipboardWipeSeconds: 60,
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
      // The only preset that touches this. Never-cache and unlock-on-open
      // are opposites (see `preferences.ts`), and this preset picks the
      // former; the other two leave the user's opt-in alone.
      unlockKeysOnOpen: false,
      historyEnabled: false,
      // The only preset that turns key discovery off. Looking someone up
      // tells GitHub or keys.openpgp.org that this network is about to
      // write to that person, and a user who has picked this card has
      // said that is a cost they do not want to pay.
      keyDiscoveryEnabled: false,
      encryptToSelf: true,
      storageLocation: "local",
      clipboardWipeSeconds: 15,
      // The only preset that touches this. Translation is the one
      // feature that hands decrypted plaintext to a model whose
      // locality we cannot verify (T-AI-PLAINTEXT-DISCLOSURE), which is
      // squarely against what this preset promises. Casual and Careful
      // leave the user's own choice alone rather than turning a
      // deliberately opt-in feature back on or off behind their back.
      aiTranslateEnabled: false,
    },
  },
};

/**
 * Which preset the given preferences currently match, or "custom" when
 * none matches exactly. Computed by diffing against each bundle (first
 * exact match in PRESET_IDS order wins); never stored, so editing any
 * bundled setting naturally flips the answer to "custom".
 */
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

/**
 * Whether any preference a preset bundle can set differs from the
 * shipped defaults. Distinguishes the two "custom" states: a user who
 * changed a bundled setting (true) vs. one who simply never picked a
 * preset -- e.g. upgraded from a version without presets -- and is
 * still on all defaults (false). The Settings preset row uses this to
 * avoid claiming "a bundled setting was changed" to upgraders.
 */
export function bundledSettingsCustomized(prefs: PgpPreferences): boolean {
  const keys = new Set<keyof PgpPreferences>();
  for (const id of PRESET_IDS) {
    for (const key of Object.keys(PRESETS[id].bundle)) {
      keys.add(key as keyof PgpPreferences);
    }
  }
  return [...keys].some((key) => prefs[key] !== DEFAULT_PREFERENCES[key]);
}

/**
 * Snapshot the current values of exactly the fields a preset bundle
 * would overwrite, so an Undo can restore them afterwards. Only keys
 * present in the bundle are captured; restoring the snapshot can never
 * touch an unrelated preference.
 */
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
  // Locking behaviour, folded into one line.
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
  (b) => {
    if (b.clipboardWipeSeconds === undefined) return null;
    return tn("shared_bundle_clipboard", b.clipboardWipeSeconds);
  },
  // Encrypt-to-self is on in every preset (and by default), so only an
  // explicit "off" is worth a line; pickers surface the "on" nuance
  // themselves where it matters (the strictest preset's card).
  (b) => {
    if (b.encryptToSelf !== false) return null;
    return t("shared_bundle_no_encrypt_to_self");
  },
];

/**
 * Human-readable lines describing exactly what a preset bundle sets,
 * for transparency on the preset cards.
 */
export function describeBundle(bundle: Partial<PgpPreferences>): string[] {
  return LINE_BUILDERS.map((build) => build(bundle)).filter(
    (line): line is string => line !== null,
  );
}
