import { STORAGE_PREFERENCES, STORAGE_SETTINGS } from "~/lib/constants";
import { hasContactsSession } from "~/lib/pgp/wasm";
import { PRESETS, STRICTEST_PRESET } from "~/lib/presets";
import { getChunked, removeChunked } from "./chunked";
import {
  asStorageLocation,
  currentStorageLocation,
  getItem,
  invalidateLocationCache,
  pinStorageLocation,
  setItem,
  withLock,
} from "./engine";
import {
  isStoredEnvelope,
  openEnvelope,
  sealEnvelope,
  type StoredEnvelope,
} from "./envelope";
import {
  claimGeneration,
  GEN_FIELD,
  isSettled,
  localStoresCarryGenerations,
  markSettled,
  noteAbsent,
  objectGeneration,
  observeGeneration,
  recordWrite,
  reportIntegrityIssue,
  sessionOpensLedger,
} from "./integrity";
import { padPlaintext, unpadPlaintext } from "./padding";

export type StorageLocation = "local" | "sync";

export type AutoLockTimeout = 2 | 5 | 10 | 15 | 30 | 60; // minutes

export interface PgpPreferences {
  defaultSigningKeyId: string | null;
  armoredOutput: boolean;
  advancedMode: boolean;
  storageLocation: StorageLocation;
  onboardingComplete: boolean;
  autoLockMinutes: AutoLockTimeout;
  signWhenEncrypting: boolean;
  /** Also encrypt to one of the user's own keys so they can read their own
   *  ciphertext. On by default. */
  encryptToSelf: boolean;
  // NB: no `activeTab` -- UI state, not a preference; old blobs may carry it.
  neverCacheKeys: boolean;
  autoDownloadFiles: boolean;
  autoDownloadText: boolean;
  /** Master enable for the inactivity timer; `autoLockMinutes` is only
   *  consulted when true. */
  autoLockEnabled: boolean;
  /** Lock the moment the side panel isn't visible. Instant; no grace. */
  lockOnTabAway: boolean;
  /** Master enable for CRX signing. Off by default. */
  crxSigningEnabled: boolean;
  /** Opt-in encrypted history of workspace operations. Off by default. */
  historyEnabled: boolean;
  /** One switch for both network key lookups (GitHub SSH keys,
   *  keys.openpgp.org). Off means the import step makes no outbound request
   *  at all (the strictest preset; `lib/presets.ts`). On by default. */
  keyDiscoveryEnabled: boolean;
  /** Recently used recipient fingerprints, most recent first (capped). */
  recentRecipients: string[];
  /** Whether the on-device Translate BUTTON is offered. Nothing reaches a
   *  model until it is pressed (T-AI-PLAINTEXT-DISCLOSURE). */
  aiTranslateEnabled: boolean;
  /** BCP 47 target language. Packs are downloaded from Settings only. */
  translationTargetLanguage: string;
  /** Preferred own key (sign/decrypt default, encrypt-to-self). Null: the
   *  first key acts as the implicit default. */
  defaultKeyId: string | null;
  /** Unlock every key sealed under the master passkey off the vault's own
   *  WebAuthn ceremony (T-VAULT-UNLOCK-OPENS-KEYS). OFF by default; passkey
   *  masters only; mutually exclusive with `neverCacheKeys`. Keys under
   *  their own salt/passkey/password keep their prompt
   *  (`lib/protection/vault-unlock.ts`). */
  unlockKeysOnOpen: boolean;
}

/** Shipped defaults. Stored blobs are partial overlays on these, so newer
 *  fields read back at their defaults. */
export const DEFAULT_PREFERENCES: PgpPreferences = {
  defaultSigningKeyId: null,
  armoredOutput: true,
  advancedMode: false,
  storageLocation: "local",
  onboardingComplete: false,
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
  recentRecipients: [],
  aiTranslateEnabled: true,
  translationTargetLanguage: "en",
  defaultKeyId: null,
  unlockKeysOnOpen: false,
};

// -- bootstrap vs settings split --
// `storageLocation` and `onboardingComplete` are read before unlock, so
// they stay in a plaintext sync blob (`resolveLocation` reads
// `storageLocation` from there); everything else is encrypted. Both are
// UNAUTHENTICATED (anyone in the user's Google account can write them),
// so neither may decide anything that can destroy data -- vault existence
// is read from the vault itself (`vault-state.ts`).

type BootPrefs = Pick<PgpPreferences, "storageLocation" | "onboardingComplete">;
type SettingsPrefs = Omit<PgpPreferences, keyof BootPrefs>;

const BOOT_KEYS: (keyof BootPrefs)[] = [
  "storageLocation",
  "onboardingComplete",
];

function isBootKey(k: string): k is keyof BootPrefs {
  return (BOOT_KEYS as string[]).includes(k);
}

/** A pre-split plaintext object still carries settings fields. */
function isLegacyFullPrefs(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && "advancedMode" in v;
}

// -- validation --
// EVERY settings value read back passes through here; a known field of the
// wrong type/range is dropped (reads as default). The legacy plaintext
// object is attacker-plantable. Unknown fields are kept from the SEALED
// blob only, so a read-merge-write doesn't wipe a newer build's settings.

const BOOLEAN_SETTINGS = [
  "armoredOutput",
  "advancedMode",
  "signWhenEncrypting",
  "encryptToSelf",
  "neverCacheKeys",
  "autoDownloadFiles",
  "autoDownloadText",
  "autoLockEnabled",
  "lockOnTabAway",
  "crxSigningEnabled",
  "historyEnabled",
  "keyDiscoveryEnabled",
  "aiTranslateEnabled",
  "unlockKeysOnOpen",
] as const satisfies readonly (keyof SettingsPrefs)[];

const AUTO_LOCK_MINUTES: readonly number[] = [
  2, 5, 10, 15, 30, 60,
] satisfies readonly AutoLockTimeout[];

/** Generous over `RECENT_RECIPIENTS_CAP`: only a bound, not the policy. */
const MAX_RECENT_RECIPIENTS = 50;

/** An OpenPGP fingerprint/key id (hex) or OpenSSH `SHA256:` fingerprint. */
function isKeyIdLike(v: unknown): v is string {
  return (
    typeof v === "string" &&
    v.length > 0 &&
    v.length <= 128 &&
    /^[A-Za-z0-9:+/=]+$/.test(v)
  );
}

/** A BCP 47 tag in the shape the translator takes ("en", "pt-BR"). */
function isLanguageTag(v: unknown): v is string {
  return (
    typeof v === "string" &&
    v.length <= 35 &&
    /^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$/.test(v)
  );
}

const KNOWN_SETTINGS = new Set<string>(
  Object.keys(DEFAULT_PREFERENCES).filter((k) => !isBootKey(k)),
);

/** The well-formed settings fields of `raw`; `keepUnknown` keeps unknown
 *  fields (never boot fields or the generation). Exported for tests. */
export function sanitizeSettings(
  raw: unknown,
  { keepUnknown = false }: { keepUnknown?: boolean } = {},
): Partial<SettingsPrefs> {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return {};
  }
  const o = raw as Record<string, unknown>;
  const out: Partial<SettingsPrefs> = {};
  if (keepUnknown) {
    for (const [k, v] of Object.entries(o)) {
      if (!KNOWN_SETTINGS.has(k) && !isBootKey(k) && k !== GEN_FIELD) {
        (out as Record<string, unknown>)[k] = v;
      }
    }
  }
  for (const k of BOOLEAN_SETTINGS) {
    if (typeof o[k] === "boolean") out[k] = o[k];
  }
  if (
    typeof o.autoLockMinutes === "number" &&
    AUTO_LOCK_MINUTES.includes(o.autoLockMinutes)
  ) {
    out.autoLockMinutes = o.autoLockMinutes as AutoLockTimeout;
  }
  for (const k of ["defaultSigningKeyId", "defaultKeyId"] as const) {
    if (o[k] === null || isKeyIdLike(o[k])) out[k] = o[k];
  }
  if (
    Array.isArray(o.recentRecipients) &&
    o.recentRecipients.length <= MAX_RECENT_RECIPIENTS &&
    o.recentRecipients.every(isKeyIdLike)
  ) {
    out.recentRecipients = [...o.recentRecipients];
  }
  if (isLanguageTag(o.translationTargetLanguage)) {
    out.translationTargetLanguage = o.translationTargetLanguage;
  }
  // Opposites: if both read true, the stricter one wins.
  if (out.neverCacheKeys === true && out.unlockKeysOnOpen === true) {
    out.unlockKeysOnOpen = false;
  }
  return out;
}

/** Settings when the sealed blob is missing-though-seen, unopenable, or
 *  can't be shown current: the strictest preset, so deleting/mangling the
 *  blob can't relax a Paranoid user's settings. */
function strictestSettings(): Partial<SettingsPrefs> {
  const { storageLocation: _s, ...bundle } = PRESETS[STRICTEST_PRESET].bundle;
  return sanitizeSettings(bundle);
}

/** Defaults with the strictest preset over them, for when preferences
 *  can't be read at all. */
export function strictestPreferences(): PgpPreferences {
  return { ...DEFAULT_PREFERENCES, ...strictestSettings() };
}

// -- bootstrap (plaintext, sync) --

async function readBoot(): Promise<Partial<BootPrefs>> {
  const result = await chrome.storage.sync.get(STORAGE_PREFERENCES);
  const stored = result[STORAGE_PREFERENCES] as Partial<BootPrefs> | undefined;
  return stored ?? {};
}

async function writeBoot(patch: Partial<BootPrefs>): Promise<void> {
  const current = await readBoot();
  await chrome.storage.sync.set({
    [STORAGE_PREFERENCES]: { ...current, ...patch },
  });
  // This device's local location record routes (`engine.ts`). Recorded
  // LAST, after the bootstrap write lands, so a rejected sync write can't
  // leave the device routed to an area the rollback then empties.
  if (patch.storageLocation !== undefined) {
    await pinStorageLocation(asStorageLocation(patch.storageLocation));
  }
}

// -- settings (encrypted, user area, padded) --
// Sealed for the `STORAGE_SETTINGS` domain (`envelope.ts`); pre-domain
// blobs read via the legacy fallback and upgrade on the next save.

// Carries a `$gen` inside the seal (`integrity.ts`), so an older copy
// reads as rolled back and a deleted one as missing.

async function saveSettings(settings: SettingsPrefs): Promise<void> {
  const gen = await claimGeneration(STORAGE_SETTINGS);
  const json = new TextEncoder().encode(
    JSON.stringify({ ...settings, [GEN_FIELD]: gen }),
  );
  const pad = (await currentStorageLocation()) === "local";
  await setItem<StoredEnvelope>(
    STORAGE_SETTINGS,
    await sealEnvelope(STORAGE_SETTINGS, padPlaintext(json, pad)),
  );
  await recordWrite(STORAGE_SETTINGS, gen);
}

interface SettingsRead {
  /** What the panel runs on: `stored`, with the strictest preset over it
   *  while the stored copy cannot be shown current. */
  settings: Partial<SettingsPrefs>;
  /** What is actually stored (validated), and what a save merges onto.
   *  Never carries the strict overlay -- persisting it would make it
   *  permanent on the next routine save. Where nothing real is stored it IS
   *  the strictest preset. */
  stored: Partial<SettingsPrefs>;
  /** A sealed envelope was there but would not open or parse. */
  unreadable: boolean;
}

/** The stored settings, validated per field. Missing-though-seen,
 *  unopenable, rolled back, or ledger lost: the strictest preset (security
 *  fields forced strict, in `settings` only, never in `stored`), reported
 *  rather than thrown. Never seen: nothing stored. */
async function readSettings(): Promise<SettingsRead> {
  const blob = await getItem<unknown>(STORAGE_SETTINGS);
  if (!isStoredEnvelope(blob)) {
    const seen = await noteAbsent(STORAGE_SETTINGS);
    const settings = seen ? strictestSettings() : {};
    return { settings, stored: settings, unreadable: false };
  }
  let parsed: unknown;
  try {
    const { plaintext } = await openEnvelope(STORAGE_SETTINGS, blob);
    parsed = JSON.parse(new TextDecoder().decode(unpadPlaintext(plaintext)));
  } catch {
    parsed = undefined;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    reportIntegrityIssue({ store: STORAGE_SETTINGS, kind: "unreadable" });
    const settings = strictestSettings();
    return { settings, stored: settings, unreadable: true };
  }
  // False while the ledger is lost or this blob is held as an older copy,
  // until the user dismisses the warning.
  const current = await observeGeneration(
    STORAGE_SETTINGS,
    objectGeneration(parsed),
  );
  const stored = sanitizeSettings(parsed, { keepUnknown: true });
  return {
    settings: current ? stored : { ...stored, ...strictestSettings() },
    stored,
    unreadable: false,
  };
}

async function loadSettings(): Promise<Partial<SettingsPrefs>> {
  return (await readSettings()).settings;
}

/**
 * One-time migration of a pre-split plaintext preferences object into the
 * bootstrap + encrypted settings. Gated so planted values can't be sealed
 * as the user's settings:
 *  - source is ONLY `chrome.storage.local`, read directly (the sync
 *    bootstrap is writable by anyone in the Google account);
 *  - at most once per device (sealed "settled" marker in the local ledger);
 *  - never over a sealed settings blob, nor once a local store carries a
 *    generation (`localStoresCarryGenerations`);
 *  - every value goes through {@link sanitizeSettings}.
 */
// Per-worker cache so repeated getPreferences calls skip the reads + lock.
let migrationSettled = false;

const LEGACY_PREFS_MIGRATION = "legacy-prefs";

/** Run the legacy migration now. Must run on unlock BEFORE any store write:
 *  the gate refuses once a local store carries a generation, which would
 *  delete a genuine install's plaintext settings unmigrated. Idempotent. */
export function migrateLegacyPreferences(): Promise<void> {
  return migrateLegacyIfNeeded();
}

async function migrateLegacyIfNeeded(): Promise<void> {
  if (migrationSettled) return;
  // No session: can't encrypt. Don't settle -- retry after unlock.
  if (!(await hasContactsSession())) return;
  await withLock(STORAGE_SETTINGS, async () => {
    const boot = await readBoot();
    // A sync bootstrap carrying settings fields is cut back to the boot
    // fields; its settings are NOT migrated.
    if (isLegacyFullPrefs(boot)) {
      await chrome.storage.sync.set({
        [STORAGE_PREFERENCES]: {
          ...(boot.storageLocation === "sync" ||
          boot.storageLocation === "local"
            ? { storageLocation: boot.storageLocation }
            : {}),
          ...(typeof boot.onboardingComplete === "boolean"
            ? { onboardingComplete: boot.onboardingComplete }
            : {}),
        },
      });
    }

    const local = chrome.storage.local;
    const legacy: unknown = await getChunked(local, STORAGE_PREFERENCES);
    if (isLegacyFullPrefs(legacy)) {
      const eligible =
        asStorageLocation(boot.storageLocation) === "local" &&
        (await currentStorageLocation()) === "local" &&
        !(await isSettled(LEGACY_PREFS_MIGRATION)) &&
        !isStoredEnvelope(await getItem<unknown>(STORAGE_SETTINGS)) &&
        !(await localStoresCarryGenerations({ unreadableCounts: true }));
      if (eligible) {
        await saveSettings({
          ...pickSettings(DEFAULT_PREFERENCES),
          ...sanitizeSettings(legacy),
        });
        if (boot.onboardingComplete === undefined) {
          await writeBoot({
            onboardingComplete: legacy.onboardingComplete === true,
          });
        }
      }
      // Migrated or refused, the plaintext copy goes.
      await removeChunked(local, STORAGE_PREFERENCES);
    }
    await markSettled(LEGACY_PREFS_MIGRATION);
    // Settled only once the marker is actually stored (needs a ledger),
    // otherwise a later planted legacy object could still migrate.
    migrationSettled = await isSettled(LEGACY_PREFS_MIGRATION);
  });
}

function pickSettings(prefs: PgpPreferences): SettingsPrefs {
  const { storageLocation: _s, onboardingComplete: _o, ...rest } = prefs;
  return rest;
}

// -- public API --

export async function getPreferences(): Promise<PgpPreferences> {
  await migrateLegacyIfNeeded();

  const boot = await readBoot();
  const storageLocation = await currentStorageLocation();

  // Pre-split fallback; informational only (see the bootstrap note).
  let onboardingComplete = boot.onboardingComplete;
  if (typeof onboardingComplete !== "boolean") {
    const legacy: unknown = await getChunked(
      chrome.storage.local,
      STORAGE_PREFERENCES,
    );
    onboardingComplete =
      isLegacyFullPrefs(legacy) && legacy.onboardingComplete === true;
  }

  // Locked: defaults (App re-reads on unlock). A failed read is the
  // strictest preset, never the defaults.
  let settings: Partial<SettingsPrefs> = {};
  if (await hasContactsSession()) {
    try {
      settings = await loadSettings();
    } catch {
      reportIntegrityIssue({ store: STORAGE_SETTINGS, kind: "unreadable" });
      settings = strictestSettings();
    }
  }

  return {
    ...DEFAULT_PREFERENCES,
    ...settings,
    storageLocation,
    onboardingComplete,
  };
}

export async function savePreferences(
  prefs: Partial<PgpPreferences>,
): Promise<void> {
  const bootPatch: Partial<BootPrefs> = {};
  const settingsPatch: Partial<SettingsPrefs> = {};
  for (const [k, v] of Object.entries(prefs)) {
    if (isBootKey(k)) {
      (bootPatch as Record<string, unknown>)[k] = v;
    } else {
      (settingsPatch as Record<string, unknown>)[k] = v;
    }
  }

  if (Object.keys(bootPatch).length > 0) {
    await writeBoot(bootPatch);
    // The engine caches its route; without this the new vault's master
    // protection lands in the area the bootstrap doesn't point at.
    if ("storageLocation" in bootPatch) invalidateLocationCache();
  }

  if (Object.keys(settingsPatch).length > 0) {
    // Should not happen (unlocked UI only); skip rather than throw.
    if (!(await hasContactsSession())) return;
    // Legacy migration FIRST: this write stamps a generation, after which its
    // gate refuses. Outside the lock below, which it takes itself.
    await migrateLegacyIfNeeded();
    await withLock(STORAGE_SETTINGS, async () => {
      // An unopenable blob is replaced (strictest preset + this change) only
      // when the session provably holds the vault key -- otherwise a wrong-
      // passkey session could replace the real settings. Merge onto `stored`,
      // never the strict overlay.
      const { stored: current, unreadable } = await readSettings();
      if (unreadable && !(await sessionOpensLedger())) {
        throw new Error(
          "Cannot save settings: the stored settings will not open",
        );
      }
      await saveSettings({
        ...pickSettings(DEFAULT_PREFERENCES),
        ...current,
        ...settingsPatch,
      });
    });
  }
}
