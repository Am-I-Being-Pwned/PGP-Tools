import type { PgpPreferences } from "./storage/preferences";
import { DEFAULT_PREFERENCES } from "./storage/preferences";

/** Identifier for a named security preset. */
export type PresetId = "casual" | "careful" | "paranoid";

/** A named threat-model preset: a title, a one-line tagline, and the
 *  bundle of preference values it applies. Bundles are applied only on
 *  explicit selection (onboarding or settings) via savePreferences;
 *  nothing enforces them afterwards. */
export interface SecurityPreset {
  title: string;
  tagline: string;
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
    title: "Casual",
    tagline: "Convenience first - for keys that guard low-stakes stuff",
    bundle: {
      autoLockEnabled: true,
      autoLockMinutes: 30,
      lockOnTabAway: false,
      neverCacheKeys: false,
      historyEnabled: true,
      keyDiscoveryEnabled: true,
      encryptToSelf: true,
      clipboardWipeSeconds: 60,
    },
  },
  careful: {
    title: "Careful",
    tagline: "Sensible defaults for real secrets",
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
    title: "If this leaks, I'm in trouble",
    tagline:
      "Nothing sticks around. Shortest locks, no history, no cached keys.",
    bundle: {
      autoLockEnabled: true,
      autoLockMinutes: 2,
      lockOnTabAway: true,
      neverCacheKeys: true,
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
    if (b.autoLockEnabled === false) return "Auto-lock is off";
    if (b.autoLockMinutes === undefined) return null;
    const base = `Auto-lock after ${formatMinutes(b.autoLockMinutes)}`;
    return b.lockOnTabAway ? `${base} and when you switch tabs` : base;
  },
  (b) => {
    if (b.neverCacheKeys === undefined) return null;
    return b.neverCacheKeys
      ? "Keys drop from memory after every use"
      : "Unlocked keys stay cached until you lock";
  },
  (b) => {
    if (b.historyEnabled === undefined) return null;
    return b.historyEnabled
      ? "Keeps an encrypted history of what you do"
      : "No history is kept";
  },
  (b) => {
    if (b.keyDiscoveryEnabled === undefined) return null;
    return b.keyDiscoveryEnabled
      ? "Keys can be looked up on GitHub and keys.openpgp.org"
      : "No key lookups - nothing leaves this device to find a key";
  },
  (b) => {
    if (b.storageLocation === undefined) return null;
    return b.storageLocation === "local"
      ? "Keys stay on this device"
      : "Keys sync across your Chrome profile";
  },
  (b) => {
    if (b.clipboardWipeSeconds === undefined) return null;
    return `Copied secrets clear from the clipboard after ${b.clipboardWipeSeconds} seconds`;
  },
  // Encrypt-to-self is on in every preset (and by default), so only an
  // explicit "off" is worth a line; pickers surface the "on" nuance
  // themselves where it matters (the strictest preset's card).
  (b) => {
    if (b.encryptToSelf !== false) return null;
    return "Messages you encrypt are not readable by you afterwards";
  },
];

function formatMinutes(minutes: number): string {
  return minutes === 1 ? "1 minute" : `${minutes} minutes`;
}

/**
 * Human-readable lines describing exactly what a preset bundle sets,
 * for transparency on the preset cards.
 */
export function describeBundle(bundle: Partial<PgpPreferences>): string[] {
  return LINE_BUILDERS.map((build) => build(bundle)).filter(
    (line): line is string => line !== null,
  );
}
