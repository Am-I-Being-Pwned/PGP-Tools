import type { PgpPreferences } from "./storage/preferences";

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
      encryptToSelf: true,
      storageLocation: "local",
      clipboardWipeSeconds: 15,
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
