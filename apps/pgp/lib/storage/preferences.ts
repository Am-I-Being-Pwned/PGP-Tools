import type { StoredEnvelope } from "./envelope";
import { STORAGE_PREFERENCES, STORAGE_SETTINGS } from "../constants";
import { hasContactsSession } from "../pgp/wasm";
import { PRESETS, STRICTEST_PRESET } from "../presets";
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
import { isStoredEnvelope, openEnvelope, sealEnvelope } from "./envelope";
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
  /** When encrypting to a contact, also encrypt to one of the user's own
   *  keys so they can decrypt their own ciphertext later. On by default;
   *  turning it off produces output only the recipient can read. */
  encryptToSelf: boolean;
  // NB: no `activeTab`. Which tab is open is UI state for one panel
  // session, not a preference: persisting it made the panel reopen on
  // whatever tab the last action happened to end on (usually Keys,
  // since importing/generating live there). The panel always launches
  // on the workspace -- that's what the app is for. Blobs written by
  // older versions may still carry the key; nothing reads it.
  neverCacheKeys: boolean;
  autoDownloadFiles: boolean;
  autoDownloadText: boolean;
  /** Master enable for the inactivity timer. When false, unlocked keys
   *  stay unlocked until the user manually locks, the app closes, or
   *  the OS lockscreen fires. `autoLockMinutes` is only consulted when
   *  this is true. */
  autoLockEnabled: boolean;
  /** When true, lock the moment the side panel isn't visible
   *  (alt-tab / collapsed / window hidden). Instant; no grace. */
  lockOnTabAway: boolean;
  /** Master enable for the CRX (Chrome extension) signing feature. Off by
   *  default; when true the CRX signing UI surfaces in Keys/Settings. */
  crxSigningEnabled: boolean;
  /** Opt-in encrypted history of workspace operations. Off by default. */
  historyEnabled: boolean;
  /** Master enable for the two network key lookups on the import step:
   *  a GitHub user's published SSH keys, and a certificate from
   *  keys.openpgp.org. ON by default, so an existing install keeps the
   *  GitHub lookup it already had (a stored settings blob is a partial
   *  overlay on these defaults, so a blob written before this field
   *  existed reads back as `true`).
   *
   *  It is one switch for both because it gates one capability: the
   *  panel asking a third party who someone is. Off means the import
   *  step makes no outbound request at all, whatever is typed -- which
   *  is what the strictest preset wants, and the only reason this
   *  preference exists (see `lib/presets.ts`). */
  keyDiscoveryEnabled: boolean;
  /** Fingerprints of recently used encrypt recipients, most recent
   *  first (capped). Orders the recipient picker's suggestions. */
  recentRecipients: string[];
  /** Master enable for on-device translation of decrypted messages.
   *
   *  ON by default, and what that does NOT mean is the important part:
   *  it controls whether the Translate BUTTON is offered, not whether
   *  anything is translated. No text reaches a model, and no model is
   *  downloaded, until the button is pressed. A user who never presses
   *  it is in exactly the position they were in before the feature
   *  existed. The strictest security preset still turns it off, and
   *  T-AI-PLAINTEXT-DISCLOSURE records what pressing it costs. */
  aiTranslateEnabled: boolean;
  /** BCP 47 tag to translate INTO -- the language the user reads.
   *  Language packs are downloaded per direction, from Settings only. */
  translationTargetLanguage: string;
  /** The user's preferred own key: preselected for sign/decrypt and
   *  used as the encrypt-to-self key. Null means no explicit choice
   *  (the first key acts as the implicit default). */
  defaultKeyId: string | null;
  /** Unlock every key sealed under the master passkey the moment the
   *  vault unlocks, off the SAME WebAuthn ceremony -- no per-key prompt.
   *
   *  OFF by default, and an existing install reads back `false` (the
   *  stored blob is a partial overlay on these defaults). Only meaningful
   *  with a passkey master; a password master has no PRF output to
   *  reuse, so the toggle is not offered. Mutually exclusive with
   *  `neverCacheKeys`: one says "keys are live from the first prompt",
   *  the other "keys are never live between operations".
   *
   *  What it costs: the one ceremony that opens the vault now opens every
   *  key sealed under it too (T-VAULT-UNLOCK-OPENS-KEYS). Keys sealed
   *  under their own PRF salt, another passkey, or a password are NOT
   *  touched by the vault ceremony. A key on the master credential moves
   *  over by itself the next time its own prompt is answered (the same
   *  ceremony evaluates the master salt too); the others keep their
   *  prompt (`lib/protection/vault-unlock.ts`). */
  unlockKeysOnOpen: boolean;
}

/** Shipped defaults. Stored blobs are partial overlays on top of these,
 *  so a blob written by an older version (missing newer fields) reads
 *  back with the new fields at their defaults. Exported so callers
 *  (e.g. preset detection) can tell "still on defaults" apart from
 *  "explicitly customized". */
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

// ── bootstrap vs settings split ──────────────────────────────────────
// `storageLocation` and `onboardingComplete` are the only prefs read
// before the vault is unlocked (the engine needs the former to route
// reads), so they stay in a plaintext sync blob. Everything else is
// encrypted.
// NB: the engine's `resolveLocation` reads `storageLocation` straight
// from sync `STORAGE_PREFERENCES`, so that field must remain there.
//
// Both fields are UNAUTHENTICATED: anyone signed in to the user's Google
// account can write them, local vault or not. So neither decides
// anything that can destroy data. `onboardingComplete` is still written
// (an older build reads it) but App no longer trusts it to choose
// between onboarding and the lock screen -- whether a vault exists is
// read from the vault itself (`vault-state.ts`). A flipped
// `storageLocation` is caught there too.

type BootPrefs = Pick<PgpPreferences, "storageLocation" | "onboardingComplete">;
type SettingsPrefs = Omit<PgpPreferences, keyof BootPrefs>;

const BOOT_KEYS: (keyof BootPrefs)[] = [
  "storageLocation",
  "onboardingComplete",
];

function isBootKey(k: string): k is keyof BootPrefs {
  return (BOOT_KEYS as string[]).includes(k);
}

/** A stored plaintext object that predates the split still carries the
 *  settings fields (e.g. `advancedMode`); the post-split bootstrap only
 *  has `storageLocation`/`onboardingComplete`. */
function isLegacyFullPrefs(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && "advancedMode" in v;
}

// ── validation ───────────────────────────────────────────────────────
// EVERY settings value read back -- from the sealed blob or the legacy
// plaintext object -- passes through here, and a KNOWN field that is not
// exactly the right type and range is dropped (so it reads as its
// default). The sealed blob can't be forged, but the legacy object can be
// planted by anyone who can write storage, and a value from a buggy build
// (`autoLockMinutes: 99999`) must not reach the lock timer either.
//
// Fields this build does not know are kept from the SEALED blob, and only
// from it: they are what a newer build wrote, and `savePreferences`
// read-merge-writes, so dropping them would wipe a newer build's settings
// the first time this one saves (downgrade safety). Nothing here reads
// them. The legacy object is attacker-plantable, so it keeps nothing.

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

/** A key id as this app stores one: an OpenPGP fingerprint or key id
 *  (hex), or an OpenSSH `SHA256:<base64>` fingerprint. */
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

/** The well-formed settings fields of `raw`. With `keepUnknown`, fields
 *  this build has no definition for ride along untouched (see above);
 *  boot fields and the generation never do. Exported for tests. */
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
  // Opposites (see `unlockKeysOnOpen`): if both somehow read true, the
  // stricter one wins.
  if (out.neverCacheKeys === true && out.unlockKeysOnOpen === true) {
    out.unlockKeysOnOpen = false;
  }
  return out;
}

/** What the settings read as when the sealed blob is MISSING although
 *  this device has seen it, will not open, or cannot be shown current
 *  (the ledger was lost): tampering, so the strictest preset rather than
 *  the defaults. Deleting or mangling one blob must not be a way to turn
 *  a Paranoid user's auto-lock back up to 15 minutes. `storageLocation`
 *  is a boot field, not a setting, so the bundle's copy is left out. */
function strictestSettings(): Partial<SettingsPrefs> {
  const { storageLocation: _s, ...bundle } = PRESETS[STRICTEST_PRESET].bundle;
  return sanitizeSettings(bundle);
}

/** The defaults with the strictest preset over them: what a caller
 *  applies when it could not read the preferences at all. */
export function strictestPreferences(): PgpPreferences {
  return { ...DEFAULT_PREFERENCES, ...strictestSettings() };
}

// ── bootstrap (plaintext, sync) ──────────────────────────────────────

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
  // A location choice is this device's own fact first (`engine.ts`): the
  // local record is what routes; the synced copy is only the default a
  // new device starts from. Recorded LAST, once the bootstrap write has
  // landed: recording it first meant a rejected sync write (sync's quota
  // or rate limit, mid storage switch) left this device routed to the
  // destination area -- which the switch's rollback then emptied.
  if (patch.storageLocation !== undefined) {
    await pinStorageLocation(asStorageLocation(patch.storageLocation));
  }
}

// ── settings (encrypted, user area, padded) ──────────────────────────
// Sealed for `STORAGE_SETTINGS` as its domain (see `envelope.ts`), so the
// settings blob and, say, a keyring or history blob are no longer
// interchangeable. Blobs written before domain separation are read via
// `openEnvelope`'s legacy fallback; every settings write goes through
// `saveSettings`, so the first preference change upgrades them, and
// `savePreferences` read-merge-writes so nothing is lost in the process.

// The blob carries a generation (`$gen`, see `integrity.ts`) inside the
// seal, so an older copy written back reads as rolled back, and a deleted
// one as missing, rather than either being silently believed.

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
   *  Never carries the strict overlay: persisting it would make a lost
   *  ledger, or a rolled-back blob, turn into permanent strictest
   *  settings with the first routine save (every encrypt saves
   *  `recentRecipients`), long after the warning was dismissed. Where
   *  nothing real is stored (missing although seen, or unreadable) it IS
   *  the strictest preset: there is nothing better to keep. */
  stored: Partial<SettingsPrefs>;
  /** A sealed envelope was there but would not open or parse. */
  unreadable: boolean;
}

/** The stored settings, validated field by field. A missing blob this
 *  device has seen before reads as the STRICTEST preset (and is reported
 *  by `noteAbsent`); one it has never seen reads as "nothing stored".
 *
 *  A blob that will not open or parse -- junk, or another store's blob
 *  copied into this slot -- also reads as the strictest preset, and is
 *  reported. It used to throw, and every caller let it go: the panel kept
 *  the DEFAULTS (a Paranoid user silently back on a 15-minute auto-lock)
 *  and every later save threw the same way. So does a blob that opens
 *  while the ledger is lost, or that is older than this device's mark
 *  (`observeGeneration`), with the security fields forced strict but the
 *  rest kept -- in `settings` only, never in `stored`. */
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
  // False while the ledger is lost, or while this blob is held as an
  // older copy (rolled back, or saved with no generation after one was
  // recorded) -- both until the user dismisses the warning.
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
 * bootstrap + encrypted-settings pair. Requires an active session (to
 * encrypt).
 *
 * This used to run whenever the encrypted blob was absent and a legacy
 * object existed, and merged the legacy values over the defaults with no
 * checks -- so anyone who could write storage could delete `pgp_settings`,
 * plant `{ advancedMode, autoLockEnabled: false, ... }`, and have it
 * sealed as the user's own settings on the next unlock. Now it is gated
 * three ways:
 *
 *  - the source is ONLY `chrome.storage.local`, read directly rather than
 *    through the engine. A sync user's legacy object was their sync
 *    bootstrap, which anyone signed in to their Google account can write
 *    -- and so can flipping `storageLocation` to route the engine there.
 *    Their settings are not migrated (the bootstrap is still cleaned);
 *    only builds before 2026-07-05 wrote this format, and every build
 *    since migrates it on the first unlock, so the loss is limited to a
 *    sync user who has not unlocked on any device since then.
 *  - it runs at most once per device: a sealed "settled" marker in the
 *    integrity ledger (local-only, so a sync attacker cannot reset it).
 *  - it never runs over a sealed settings blob, nor on a device whose
 *    local stores show a ledger-keeping build has run here (a sealed
 *    store with a generation, `localStoresCarryGenerations`). Deleting
 *    the ledger -- and with it the settled marker -- used to make it run
 *    again over planted values; only an install that predates this build
 *    still qualifies. And every value is validated by
 *    {@link sanitizeSettings}.
 */
// Once settled (under a session) there's nothing to migrate for the rest
// of this worker's lifetime -- getPreferences is called from several
// effects, so skip the storage reads + lock on every subsequent call.
// Resets on worker restart, which just re-confirms once.
let migrationSettled = false;

const LEGACY_PREFS_MIGRATION = "legacy-prefs";

/**
 * Run the legacy-preferences migration now. The panel calls this on
 * unlock BEFORE anything can write a store: the gate above refuses once a
 * local store carries a generation, so a store write landing first -- the
 * contacts backfill that the unlock kicks off, on exactly the old installs
 * that still have a legacy object -- would refuse a genuine install's
 * migration and delete its plaintext settings unmigrated. Idempotent, and
 * a no-op without a session.
 */
export function migrateLegacyPreferences(): Promise<void> {
  return migrateLegacyIfNeeded();
}

async function migrateLegacyIfNeeded(): Promise<void> {
  if (migrationSettled) return;
  // No session yet: can't encrypt. Don't settle -- retry after unlock.
  if (!(await hasContactsSession())) return;
  // Serialize with settings writes so concurrent getPreferences /
  // savePreferences calls can't double-migrate or interleave.
  await withLock(STORAGE_SETTINGS, async () => {
    const boot = await readBoot();
    // A sync bootstrap that still carries settings fields (a sync user's
    // legacy object, or one planted there) is cut back to the two boot
    // fields. Its settings are NOT migrated -- see above.
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
      // Migrated or refused, the plaintext copy goes: it is either now
      // sealed, or not something to keep in the clear.
      await removeChunked(local, STORAGE_PREFERENCES);
    }
    await markSettled(LEGACY_PREFS_MIGRATION);
    // Only once the marker is actually stored: with no ledger yet,
    // markSettled cannot create one, and skipping every later run in this
    // worker would leave the device unsettled -- open to a legacy object
    // planted after the settings are deleted. Re-run (cheaply: nothing
    // left to migrate) until a ledger exists to hold the marker.
    migrationSettled = await isSettled(LEGACY_PREFS_MIGRATION);
  });
}

function pickSettings(prefs: PgpPreferences): SettingsPrefs {
  const { storageLocation: _s, onboardingComplete: _o, ...rest } = prefs;
  return rest;
}

// ── public API ───────────────────────────────────────────────────────

export async function getPreferences(): Promise<PgpPreferences> {
  await migrateLegacyIfNeeded();

  const boot = await readBoot();
  // Where this device's vault actually lives (its own record first; the
  // synced bootstrap only as a default -- see `engine.ts`).
  const storageLocation = await currentStorageLocation();

  // Pre-split fallback: a local user's onboardingComplete may still live
  // in the legacy full object rather than the bootstrap. Informational
  // only -- see the note on the bootstrap above.
  let onboardingComplete = boot.onboardingComplete;
  if (typeof onboardingComplete !== "boolean") {
    const legacy: unknown = await getChunked(
      chrome.storage.local,
      STORAGE_PREFERENCES,
    );
    onboardingComplete =
      isLegacyFullPrefs(legacy) && legacy.onboardingComplete === true;
  }

  // Settings are only readable with a session; while locked the caller
  // gets defaults (the locked UI is just the unlock screen, which needs
  // none of them). App re-reads and re-applies on unlock. A read that
  // fails outright (a torn sync read, say) is the strictest preset, not
  // the defaults, for the same reason as a blob that will not open.
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
    // The engine caches the location it routes to. Without this, choosing
    // "sync" during onboarding left the cache on the "local" it had read
    // at mount, and the new vault's master protection was written to the
    // area the bootstrap does NOT point at.
    if ("storageLocation" in bootPatch) invalidateLocationCache();
  }

  if (Object.keys(settingsPatch).length > 0) {
    // Settings writes only happen from the unlocked UI, so a session is
    // present. If somehow locked, skip rather than throw -- losing a
    // toggle is better than a crash, and this path shouldn't occur.
    if (!(await hasContactsSession())) return;
    // The legacy migration first, for the same reason the panel runs it
    // first on unlock: its gate refuses once a local store carries a
    // generation, and this very write stamps one. It also settles the
    // migration (a ledger write) HERE, inside onboarding's own saves,
    // rather than from the first getPreferences after the main UI has
    // mounted -- an unproven read-modify-write landing then could put
    // back a ledger deleted in the meantime, without its `lost` flag.
    // Outside the lock below: the migration takes the same one.
    await migrateLegacyIfNeeded();
    // Serialize read-merge-write so rapid toggles can't clobber fields.
    await withLock(STORAGE_SETTINGS, async () => {
      // A blob that will not open is replaced -- strictest preset plus
      // this change -- so one bad write cannot wedge every later save.
      // Only when the session provably holds the vault key (it opens the
      // ledger): a session minted from the wrong passkey would otherwise
      // replace the real settings with a blob only it can read.
      // Merge onto what is STORED, not onto the strict overlay the panel
      // may be running on: only the fields this save names change.
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
