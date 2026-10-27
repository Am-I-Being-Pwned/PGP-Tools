import { useEffect, useRef, useState } from "react";
import { ChevronRightIcon } from "lucide-react";

import { Block, BlockStack } from "@amibeingpwned/ui/block";
import { Button } from "@amibeingpwned/ui/button";
import { Switch } from "@amibeingpwned/ui/switch";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { PresetId } from "../../lib/presets";
import type { MasterPasskey } from "../../lib/protection/vault-unlock";
import type { PublicContactKey } from "../../lib/storage/contacts";
import type { ProtectedKeyBlob } from "../../lib/storage/keyring";
import type {
  AutoLockTimeout,
  PgpPreferences,
  StorageLocation,
} from "../../lib/storage/preferences";
import {
  STORAGE_CONTACTS,
  STORAGE_CRX_KEYS,
  STORAGE_KEYRING,
  STORAGE_MASTER_PROTECTION,
  STORAGE_SETTINGS,
} from "../../lib/constants";
import { t, tn } from "../../lib/i18n";
import { enterNeverCacheMode } from "../../lib/never-cache";
import {
  activePreset,
  bundledSettingsCustomized,
  PRESETS,
  snapshotBundleFields,
} from "../../lib/presets";
import { isQuotaExceeded } from "../../lib/storage/chunked";
import {
  copyEncryptedBlobRepacked,
  purgeEncryptedBlob,
} from "../../lib/storage/encrypted-store";
import { invalidateLocationCache } from "../../lib/storage/engine";
import { historyByteSize } from "../../lib/storage/history";
import { getPreferences, savePreferences } from "../../lib/storage/preferences";
import { toast } from "../../lib/toast";
import { formatFileSize } from "../../lib/utils/formatting";
import { ExportKeysPage } from "../keys/ExportKeysPage";
import { CrxSigningInfoPage } from "../settings/CrxSigningInfoPage";
import { DevToolsPage } from "../settings/DevToolsPage";
import { ImportAllKeysPage } from "../settings/ImportAllKeysPage";
import { ImportFlowPreviewPage } from "../settings/ImportFlowPreviewPage";
import { KeyboardShortcutsPage } from "../settings/KeyboardShortcutsPage";
import { SecurityPresetPage } from "../settings/SecurityPresetPage";
import { TranslationPage } from "../settings/TranslationPage";
import { ConfirmPage } from "./ConfirmPage";
import { StorageLocationPicker } from "./StorageLocationPicker";

const AUTO_LOCK_OPTIONS: AutoLockTimeout[] = [2, 5, 10, 15, 30, 60];

/** The muted underline links in the About block: green is kept for
 *  "on" and "go", so a plain link reads as text, not as an action. */
const ABOUT_LINK_CLASS =
  "text-foreground/80 hover:text-foreground underline decoration-white/20 underline-offset-2 transition-colors";

/** A group's label. A real h2 -- screen readers (and the e2e helpers)
 *  navigate Settings by these headings -- drawn as the small muted
 *  label that sits above a block stack. */
function GroupLabel({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="text-muted-foreground px-1 text-xs font-medium">
      {children}
    </h2>
  );
}

/** A setting that is a plain on/off: title and description on the left,
 *  the switch on the right. The whole row is the switch's <label>, so
 *  its accessible name is the title plus the description, and a click
 *  anywhere on the row flips it. */
function SwitchRow({
  title,
  description,
  checked,
  onCheckedChange,
}: {
  title: string;
  description?: string;
  checked: boolean;
  onCheckedChange: (v: boolean) => void;
}) {
  return (
    <Block>
      <label className="flex cursor-pointer items-center justify-between gap-4 px-3.5 py-3">
        <div>
          <span className="text-sm font-medium">{title}</span>
          {description && (
            <p className="text-muted-foreground text-xs">{description}</p>
          )}
        </div>
        <Switch checked={checked} onCheckedChange={onCheckedChange} />
      </label>
    </Block>
  );
}

/** A row that opens a subpage: title (plus an optional line under it),
 *  the current value muted on the right, and a chevron. The focus ring
 *  is inset because the stack clips anything drawn outside its blocks. */
function NavRow({
  title,
  description,
  value,
  onClick,
}: {
  title: string;
  description?: React.ReactNode;
  value?: string;
  onClick: () => void;
}) {
  return (
    <Block>
      <button
        type="button"
        onClick={onClick}
        className="hover:bg-accent focus-visible:ring-ring/50 flex w-full items-center justify-between gap-4 rounded-[3px] px-3.5 py-3 text-left transition-colors focus-visible:ring-2 focus-visible:outline-none focus-visible:ring-inset"
      >
        <div className="min-w-0">
          <span className="text-sm font-medium">{title}</span>
          {description}
        </div>
        <span className="flex min-w-0 items-center gap-1">
          {value && (
            <span className="text-muted-foreground truncate text-sm">
              {value}
            </span>
          )}
          <ChevronRightIcon className="text-muted-foreground h-4 w-4 shrink-0" />
        </span>
      </button>
    </Block>
  );
}

function autoLockLabel(minutes: AutoLockTimeout): string {
  return minutes === 60 ? t("shared_one_hour") : tn("shared_minutes", minutes);
}

interface SettingsViewProps {
  advancedMode: boolean;
  onAdvancedModeChange: (v: boolean) => void;
  storageLocation: StorageLocation;
  onStorageLocationChange: (loc: StorageLocation) => void;
  autoLockEnabled: boolean;
  onAutoLockEnabledChange: (v: boolean) => void;
  autoLockMinutes: AutoLockTimeout;
  onAutoLockChange: (v: AutoLockTimeout) => void;
  neverCacheKeys: boolean;
  onNeverCacheKeysChange: (v: boolean) => void;
  autoDownloadFiles: boolean;
  onAutoDownloadFilesChange: (v: boolean) => void;
  autoDownloadText: boolean;
  onAutoDownloadTextChange: (v: boolean) => void;
  lockOnTabAway: boolean;
  onLockOnTabAwayChange: (v: boolean) => void;
  unlockKeysOnOpen: boolean;
  onUnlockKeysOnOpenChange: (v: boolean) => void;
  /** The master passkey, or null for a password master -- in which case
   *  the unlock-on-open toggle is not offered (nothing to reuse). */
  masterPasskey: MasterPasskey | null;
  /** See `ImportAllKeysPage`. */
  masterSealSalt?: ArrayBuffer;
  crxSigningEnabled: boolean;
  onCrxSigningEnabledChange: (v: boolean) => void;
  keyDiscoveryEnabled: boolean;
  onKeyDiscoveryEnabledChange: (v: boolean) => void;
  aiTranslateEnabled: boolean;
  onAiTranslateEnabledChange: (v: boolean) => void;
  translationTargetLanguage: string;
  onTranslationTargetLanguageChange: (code: string) => void;
  /** Fired after a preset bundle rewrites preference-backed toggles the
   *  workspace also renders (historyEnabled, encryptToSelf, ...), so the
   *  always-mounted workspace can re-read them. */
  onWorkspacePrefsChanged?: () => void;
  // Backup (export/import all keys)
  myKeys: ProtectedKeyBlob[];
  contacts: PublicContactKey[];
  isUnlocked: (keyId: string) => boolean;
  getKeyHandle: (keyId: string) => number | null;
  onUnlockWithPassword: (
    blob: ProtectedKeyBlob,
    password: string,
  ) => Promise<boolean>;
  onUnlockWithPasskey: (
    blob: ProtectedKeyBlob,
  ) => Promise<boolean | "cancelled">;
  onAddKey: (blob: ProtectedKeyBlob) => Promise<void>;
  onAddContact: (contact: PublicContactKey) => Promise<void>;
  crxKeys?: CrxSigningKeyBlob[];
  onAddCrxKey?: (blob: CrxSigningKeyBlob) => Promise<void>;
  primaryPasskeyCredentialId?: string;
  /** One-shot request to open the security-presets subpage (palette's
   *  "Open security presets"); consumed via the callback below. */
  autoOpenPresets?: boolean;
  onAutoOpenPresetsConsumed?: () => void;
}

export function SettingsView({
  advancedMode,
  onAdvancedModeChange,
  storageLocation,
  onStorageLocationChange,
  autoLockEnabled,
  onAutoLockEnabledChange,
  autoLockMinutes,
  onAutoLockChange,
  neverCacheKeys,
  onNeverCacheKeysChange,
  autoDownloadFiles,
  onAutoDownloadFilesChange,
  autoDownloadText,
  onAutoDownloadTextChange,
  lockOnTabAway,
  onLockOnTabAwayChange,
  unlockKeysOnOpen,
  onUnlockKeysOnOpenChange,
  masterPasskey,
  masterSealSalt,
  crxSigningEnabled,
  onCrxSigningEnabledChange,
  keyDiscoveryEnabled,
  onKeyDiscoveryEnabledChange,
  aiTranslateEnabled,
  onAiTranslateEnabledChange,
  translationTargetLanguage,
  onTranslationTargetLanguageChange,
  onWorkspacePrefsChanged,
  myKeys,
  contacts,
  isUnlocked,
  getKeyHandle,
  onUnlockWithPassword,
  onUnlockWithPasskey,
  onAddKey,
  onAddContact,
  crxKeys,
  onAddCrxKey,
  primaryPasskeyCredentialId,
  autoOpenPresets,
  onAutoOpenPresetsConsumed,
}: SettingsViewProps) {
  const [migratingTo, setMigratingTo] = useState<StorageLocation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showExportAll, setShowExportAll] = useState(false);
  const [showImportAll, setShowImportAll] = useState(false);
  const [showCrxInfo, setShowCrxInfo] = useState(false);
  const [showDevTools, setShowDevTools] = useState(false);
  const [showImportFlow, setShowImportFlow] = useState(false);
  const [showPresets, setShowPresets] = useState(false);
  const [showShortcuts, setShowShortcuts] = useState(false);
  const [showTranslation, setShowTranslation] = useState(false);
  // Stored-history byte size at the moment the user tried to turn
  // never-cache on; non-null renders the delete-history confirm page.
  const [neverCacheConfirmBytes, setNeverCacheConfirmBytes] = useState<
    number | null
  >(null);

  // Open the presets subpage when routed here by the palette action.
  useEffect(() => {
    if (!autoOpenPresets) return;
    setShowPresets(true);
    onAutoOpenPresetsConsumed?.();
  }, [autoOpenPresets, onAutoOpenPresetsConsumed]);

  // Full preferences snapshot for computing the active preset: the
  // bundles cover fields this view has no props for (historyEnabled,
  // encryptToSelf). Re-read whenever a bundled
  // setting editable in this view changes, so the "Custom" state tracks
  // live edits. Toggles in other views can't change while this tab is
  // showing in the same panel.
  const [prefs, setPrefs] = useState<PgpPreferences | null>(null);
  useEffect(() => {
    void getPreferences().then(setPrefs);
  }, [
    autoLockEnabled,
    autoLockMinutes,
    lockOnTabAway,
    neverCacheKeys,
    unlockKeysOnOpen,
    storageLocation,
  ]);

  const currentPreset = prefs ? activePreset(prefs) : null;

  const toggleAdvanced = () => {
    const next = !advancedMode;
    onAdvancedModeChange(next);
    void savePreferences({ advancedMode: next });
  };

  const handleStorageChange = async (next: StorageLocation) => {
    if (next === storageLocation) return;
    setMigratingTo(next);
    setError(null);
    // Re-pack each blob for the destination rather than a raw byte-copy:
    // padding differs by area (local pads to hide item counts; sync can't,
    // due to its 8 KB/item cap), so moving a padded local blob to sync
    // verbatim could blow the quota. Large blobs are chunked across items
    // on sync (see storage/chunked.ts). The settings blob lives in the
    // user area too, so it moves alongside the keyring/contacts.
    //
    // Every engine-routed blob must move, or it strands in the old area:
    // the master protection especially -- leave it behind and the switched
    // vault (here after reload, or on another synced device) has keys it
    // can never unlock. CRX keys are the same encrypted store as the
    // keyring. Non-{iv,ciphertext} blobs (master protection) copy verbatim.
    const keys = [
      STORAGE_KEYRING,
      STORAGE_CONTACTS,
      STORAGE_SETTINGS,
      STORAGE_MASTER_PROTECTION,
      STORAGE_CRX_KEYS,
    ];
    // Once the location is committed (step 2), the destination is the ONLY
    // authoritative copy -- a later failure must never roll it back.
    let committed = false;
    try {
      // 1. Copy everything to the destination (originals untouched).
      for (const key of keys) {
        await copyEncryptedBlobRepacked(key, storageLocation, next);
      }
      // 2. Commit: switch the active location. Reads now resolve to the
      //    destination, which holds every blob. A crash before here left
      //    the originals authoritative; after, only stale dups remain.
      await savePreferences({ storageLocation: next });
      committed = true;
      invalidateLocationCache();
      // 3. Drop the now-stale originals from the old area. Best-effort: the
      //    move is already committed, so a purge failure (e.g. sync's write
      //    rate limit mid-loop) only leaves harmless duplicates -- it must
      //    NOT bubble to the rollback below and delete the live copy.
      for (const key of keys) {
        try {
          await purgeEncryptedBlob(key, storageLocation);
        } catch {
          /* stale originals are harmless; leave them */
        }
      }
      onStorageLocationChange(next);
    } catch (e) {
      // Pre-commit failure only (step 1 copy, or step 2 persist): the
      // active location is still the origin, so the originals remain
      // authoritative. Roll back any partial copies written to the
      // destination -- e.g. sync's ~100 KB total quota exhausted mid-copy.
      // Guarded by `committed` so a committed move is never unwound.
      if (!committed) {
        for (const key of keys) {
          try {
            await purgeEncryptedBlob(key, next);
          } catch {
            /* best-effort cleanup */
          }
        }
      }
      setError(
        isQuotaExceeded(e)
          ? t("shared_sync_quota_error")
          : e instanceof Error
            ? e.message
            : t("shared_migration_failed"),
      );
    } finally {
      setMigratingTo(null);
    }
  };

  const handleAutoLockChange = (v: AutoLockTimeout) => {
    onAutoLockChange(v);
    void savePreferences({ autoLockMinutes: v });
  };

  // Enter never-cache via the shared transition (flip prefs + wipe
  // history), then sync this view's snapshot and the workspace toggles.
  const enableNeverCache = async () => {
    await enterNeverCacheMode();
    onNeverCacheKeysChange(true);
    // Mirror what the transition persisted (see `enterNeverCacheMode`).
    onUnlockKeysOnOpenChange(false);
    setPrefs(await getPreferences());
    // The transition also turned historyEnabled off; the always-mounted
    // workspace renders that toggle, so tell it to re-read.
    onWorkspacePrefsChanged?.();
  };

  const handleUnlockOnOpenToggle = async (v: boolean) => {
    // State mirrors storage AFTER the write lands: a failed write must
    // not leave the toggle saying "off" while the next vault unlock
    // reads "on" from storage.
    if (!v) {
      await savePreferences({ unlockKeysOnOpen: false });
      onUnlockKeysOnOpenChange(false);
      return;
    }
    // Entering unlock-on-open leaves never-cache (see enableNeverCache
    // for the converse). History stays as the user had it.
    await savePreferences({ unlockKeysOnOpen: true, neverCacheKeys: false });
    onNeverCacheKeysChange(false);
    onUnlockKeysOnOpenChange(true);
    setPrefs(await getPreferences());
  };

  const handleNeverCacheToggle = async (v: boolean) => {
    if (!v) {
      // Turning never-cache OFF never re-enables history; the user
      // opted out of retention and must opt back in explicitly.
      onNeverCacheKeysChange(false);
      void savePreferences({ neverCacheKeys: false });
      return;
    }
    const bytes = await historyByteSize();
    if (bytes > 0) {
      // Stored history exists: entering never-cache deletes it, so
      // confirm with the cost spelled out before flipping anything.
      setNeverCacheConfirmBytes(bytes);
      return;
    }
    await enableNeverCache();
  };

  // Sync the parent-held state for fields this view has props for
  // (shared by applyPreset and its Undo).
  const syncBundledProps = (values: Partial<PgpPreferences>) => {
    if (values.autoLockEnabled !== undefined) {
      onAutoLockEnabledChange(values.autoLockEnabled);
    }
    if (values.autoLockMinutes !== undefined) {
      onAutoLockChange(values.autoLockMinutes);
    }
    if (values.lockOnTabAway !== undefined) {
      onLockOnTabAwayChange(values.lockOnTabAway);
    }
    if (values.neverCacheKeys !== undefined) {
      onNeverCacheKeysChange(values.neverCacheKeys);
    }
    if (values.unlockKeysOnOpen !== undefined) {
      onUnlockKeysOnOpenChange(values.unlockKeysOnOpen);
    }
    if (values.keyDiscoveryEnabled !== undefined) {
      onKeyDiscoveryEnabledChange(values.keyDiscoveryEnabled);
    }
  };

  // Restore the pre-apply snapshot of the bundled fields. Cleared
  // history is gone for good; the apply toast says so. storageLocation
  // can't be restored by a plain save, it needs the full migration.
  const undoPresetApply = async (snapshot: Partial<PgpPreferences>) => {
    const { storageLocation: prevLocation, ...rest } = snapshot;
    await savePreferences(rest);
    syncBundledProps(rest);
    setPrefs(await getPreferences());
    onWorkspacePrefsChanged?.();
    if (prevLocation !== undefined && prevLocation !== storageLocation) {
      await handleStorageChange(prevLocation);
    }
  };
  // The undo toast can outlive this render (and a preset may have
  // migrated storage, changing the props undoPresetApply closes over),
  // so the toast action always calls the latest instance via a ref.
  const undoPresetApplyRef = useRef(undoPresetApply);
  useEffect(() => {
    undoPresetApplyRef.current = undoPresetApply;
  });

  const applyPreset = async (id: PresetId) => {
    // Snapshot exactly the bundled fields first, so Undo can restore
    // what the preset overwrote and nothing else.
    const snapshot = snapshotBundleFields(
      await getPreferences(),
      PRESETS[id].bundle,
    );
    // storageLocation can't go through plain savePreferences: flipping
    // it without migrating the vault blobs would strand them in the
    // old area. Apply the rest, then run the real migration if needed.
    const { storageLocation: bundleLocation, ...bundle } = PRESETS[id].bundle;
    let historyCleared = false;
    if (bundle.neverCacheKeys === true) {
      historyCleared = (await historyByteSize()) > 0;
      // Route the never-cache flip (and its history wipe) through the
      // shared transition so this path can't diverge from the toggle.
      const {
        neverCacheKeys: _never,
        historyEnabled: _history,
        ...rest
      } = bundle;
      await savePreferences(rest);
      await enterNeverCacheMode();
    } else {
      await savePreferences(bundle);
    }

    syncBundledProps(bundle);
    setPrefs(await getPreferences());
    // The bundle rewrote toggles the always-mounted workspace renders
    // (historyEnabled, encryptToSelf); tell it to re-read.
    onWorkspacePrefsChanged?.();

    if (bundleLocation !== undefined && bundleLocation !== storageLocation) {
      await handleStorageChange(bundleLocation);
    }

    toast.success(t("shared_preset_applied", { title: PRESETS[id].title }), {
      id: "preset-applied",
      // Undo restores the bundled preferences, but a paranoid apply
      // wiped stored history and that is unrecoverable; say so.
      description: historyCleared
        ? t("shared_preset_applied_history_deleted")
        : undefined,
      action: {
        label: t("shared_undo"),
        onClick: () => void undoPresetApplyRef.current(snapshot),
      },
    });
  };

  return (
    <div className="space-y-4">
      <BlockStack>
        <NavRow
          title={t("shared_security_preset")}
          description={
            prefs &&
            currentPreset === "custom" && (
              <p className="text-muted-foreground text-xs">
                {bundledSettingsCustomized(prefs)
                  ? t("shared_preset_bundled_changed")
                  : t("shared_preset_none_selected")}
              </p>
            )
          }
          value={
            currentPreset === null
              ? ""
              : currentPreset === "custom"
                ? t("shared_preset_custom")
                : PRESETS[currentPreset].title
          }
          onClick={() => setShowPresets(true)}
        />
        <NavRow
          title={t("shared_translation")}
          value={aiTranslateEnabled ? t("common_on") : t("common_off")}
          onClick={() => setShowTranslation(true)}
        />
        <NavRow
          title={t("shared_keyboard_shortcuts")}
          onClick={() => setShowShortcuts(true)}
        />
      </BlockStack>

      <div className="space-y-1.5">
        <GroupLabel>{t("shared_key_storage")}</GroupLabel>
        <StorageLocationPicker
          value={storageLocation}
          onChange={handleStorageChange}
          disabled={migratingTo !== null}
        />
        {error && <p className="text-bad px-1 text-xs">{error}</p>}
      </div>

      <div className="space-y-1.5">
        <GroupLabel>{t("shared_key_security")}</GroupLabel>
        <BlockStack>
          <SwitchRow
            title={t("shared_auto_lock_title")}
            description={t("shared_auto_lock_desc")}
            checked={autoLockEnabled}
            onCheckedChange={(v) => {
              onAutoLockEnabledChange(v);
              void savePreferences({ autoLockEnabled: v });
            }}
          />
          {autoLockEnabled && (
            <Block className="flex items-center justify-between gap-4 px-3.5 py-2.5">
              <label
                htmlFor="auto-lock-after"
                className="text-muted-foreground text-xs"
              >
                {t("shared_lock_after")}
              </label>
              <select
                id="auto-lock-after"
                value={autoLockMinutes}
                onChange={(e) =>
                  handleAutoLockChange(
                    Number(e.target.value) as AutoLockTimeout,
                  )
                }
                className="surface-field focus:ring-ring rounded-md px-2 py-1.5 text-sm focus:ring-2 focus:outline-none"
              >
                {AUTO_LOCK_OPTIONS.map((minutes) => (
                  <option key={minutes} value={minutes}>
                    {autoLockLabel(minutes)}
                  </option>
                ))}
              </select>
            </Block>
          )}
          <SwitchRow
            title={t("shared_lock_tab_away_title")}
            description={t("shared_lock_tab_away_desc")}
            checked={lockOnTabAway}
            onCheckedChange={(v) => {
              onLockOnTabAwayChange(v);
              void savePreferences({ lockOnTabAway: v });
            }}
          />
          <SwitchRow
            title={t("shared_never_cache_title")}
            description={t("shared_never_cache_desc")}
            checked={neverCacheKeys}
            onCheckedChange={(v) => void handleNeverCacheToggle(v)}
          />
          {masterPasskey && (
            <SwitchRow
              title={t("shared_unlock_with_vault_title")}
              description={t("shared_unlock_with_vault_desc")}
              checked={unlockKeysOnOpen}
              onCheckedChange={(v) => void handleUnlockOnOpenToggle(v)}
            />
          )}
        </BlockStack>
      </div>

      <div className="space-y-1.5">
        <GroupLabel>{t("shared_downloads")}</GroupLabel>
        <BlockStack>
          <SwitchRow
            title={t("shared_auto_download_files_title")}
            description={t("shared_auto_download_files_desc")}
            checked={autoDownloadFiles}
            onCheckedChange={(v) => {
              onAutoDownloadFilesChange(v);
              void savePreferences({ autoDownloadFiles: v });
            }}
          />
          <SwitchRow
            title={t("shared_auto_download_text_title")}
            description={t("shared_auto_download_text_desc")}
            checked={autoDownloadText}
            onCheckedChange={(v) => {
              onAutoDownloadTextChange(v);
              void savePreferences({ autoDownloadText: v });
            }}
          />
        </BlockStack>
      </div>

      <div className="space-y-1.5">
        <GroupLabel>{t("shared_key_discovery")}</GroupLabel>
        <BlockStack>
          {/* The description says exactly which hosts and exactly what
              they learn. This is the only preference that lets the
              extension talk to anyone, so a vague "enable lookups" would
              be hiding the thing worth deciding about. */}
          <SwitchRow
            title={t("shared_lookup_online_title")}
            description={t("shared_lookup_online_desc")}
            checked={keyDiscoveryEnabled}
            onCheckedChange={(v) => {
              onKeyDiscoveryEnabledChange(v);
              void savePreferences({ keyDiscoveryEnabled: v });
            }}
          />
        </BlockStack>
      </div>

      <div className="space-y-1.5">
        <GroupLabel>{t("shared_crx_signing")}</GroupLabel>
        <BlockStack>
          <SwitchRow
            title={t("shared_crx_enable_title")}
            description={t("shared_crx_enable_desc")}
            checked={crxSigningEnabled}
            onCheckedChange={(v) => {
              onCrxSigningEnabledChange(v);
              void savePreferences({ crxSigningEnabled: v });
            }}
          />
          <NavRow
            title={t("shared_crx_how")}
            onClick={() => setShowCrxInfo(true)}
          />
        </BlockStack>
      </div>

      <div className="space-y-1.5">
        <GroupLabel>{t("shared_backup")}</GroupLabel>
        <BlockStack>
          <Block className="px-3.5 py-3">
            <p className="text-muted-foreground text-xs">
              {t("shared_backup_desc")}
            </p>
          </Block>
          <NavRow
            title={t("shared_export_all_keys")}
            onClick={() => setShowExportAll(true)}
          />
          <NavRow
            title={t("shared_import_keys")}
            onClick={() => setShowImportAll(true)}
          />
        </BlockStack>
      </div>

      <div className="space-y-1.5">
        <GroupLabel>{t("shared_display")}</GroupLabel>
        <BlockStack>
          <SwitchRow
            title={t("shared_advanced_mode")}
            checked={advancedMode}
            onCheckedChange={toggleAdvanced}
          />
        </BlockStack>
        <p className="text-muted-foreground px-1 text-xs">
          {t("shared_advanced_mode_desc")}
        </p>
      </div>

      {import.meta.env.DEV && (
        <div className="space-y-1.5">
          <GroupLabel>{t("shared_developer")}</GroupLabel>
          <BlockStack>
            <Block className="px-3.5 py-3">
              <p className="text-muted-foreground text-xs">
                {t("shared_developer_desc")}
              </p>
            </Block>
            <NavRow
              title={t("shared_open_dev_tools")}
              onClick={() => setShowDevTools(true)}
            />
            <NavRow
              title={t("shared_import_flow_states")}
              onClick={() => setShowImportFlow(true)}
            />
          </BlockStack>
        </div>
      )}

      <div className="space-y-1.5">
        <GroupLabel>{t("shared_about")}</GroupLabel>
        <Block className="rounded-xl px-3.5 py-3">
          {/* i18n-ignore */}
          <p className="text-sm font-medium">PGP Tools</p>
          <p className="text-muted-foreground mt-1 text-xs">
            {t("shared_byline_before")}{" "}
            <a
              href="https://amibeingpwned.com"
              target="_blank"
              rel="noopener noreferrer"
              className={ABOUT_LINK_CLASS}
            >
              {/* i18n-ignore */}
              Am I Being Pwned
            </a>
            . <br />
            <a
              href="https://github.com/Am-I-Being-Pwned/PGP-Tools"
              target="_blank"
              rel="noopener noreferrer"
              className={ABOUT_LINK_CLASS}
            >
              {t("shared_source_on_github")}
            </a>
            .
          </p>
          <p className="text-muted-foreground mt-2 text-xs">
            {t("shared_about_extensions")}
          </p>
          <a
            href="https://amibeingpwned.com"
            target="_blank"
            rel="noopener noreferrer"
          >
            <Button variant="outline" size="sm" className="mt-2">
              {t("shared_check_extensions")}
            </Button>
          </a>
        </Block>
      </div>

      {showExportAll && (
        <ExportKeysPage
          title={t("shared_export_all_keys")}
          onClose={() => setShowExportAll(false)}
          myKeys={myKeys}
          contacts={contacts}
          crxKeys={crxKeys}
          isUnlocked={isUnlocked}
          getKeyHandle={getKeyHandle}
          onUnlockWithPassword={onUnlockWithPassword}
          onUnlockWithPasskey={onUnlockWithPasskey}
        />
      )}

      {showImportAll && (
        <ImportAllKeysPage
          onClose={() => setShowImportAll(false)}
          myKeys={myKeys}
          contacts={contacts}
          onAddKey={onAddKey}
          onAddContact={onAddContact}
          onAddCrxKey={onAddCrxKey}
          crxKeys={crxKeys}
          reusePasskeyCredentialId={primaryPasskeyCredentialId}
          masterSealSalt={masterSealSalt}
        />
      )}

      {showCrxInfo && (
        <CrxSigningInfoPage onClose={() => setShowCrxInfo(false)} />
      )}

      {showShortcuts && (
        <KeyboardShortcutsPage onClose={() => setShowShortcuts(false)} />
      )}

      {showTranslation && (
        <TranslationPage
          onClose={() => setShowTranslation(false)}
          enabled={aiTranslateEnabled}
          onEnabledChange={(v) => {
            onAiTranslateEnabledChange(v);
            void savePreferences({ aiTranslateEnabled: v });
          }}
          targetLanguage={translationTargetLanguage}
          onTargetLanguageChange={(code) => {
            onTranslationTargetLanguageChange(code);
            void savePreferences({ translationTargetLanguage: code });
          }}
        />
      )}

      {neverCacheConfirmBytes !== null && (
        <ConfirmPage
          title={t("shared_delete_history_title")}
          confirmLabel={t("shared_delete_history_confirm")}
          onCancel={() => setNeverCacheConfirmBytes(null)}
          onConfirm={enableNeverCache}
        >
          <p>
            {t("shared_delete_history_body", {
              size: formatFileSize(neverCacheConfirmBytes),
            })}
          </p>
        </ConfirmPage>
      )}

      {showPresets && (
        <SecurityPresetPage
          currentPreset={currentPreset}
          onApply={applyPreset}
          onClose={() => setShowPresets(false)}
        />
      )}

      {import.meta.env.DEV && showDevTools && (
        <DevToolsPage onClose={() => setShowDevTools(false)} />
      )}

      {import.meta.env.DEV && showImportFlow && (
        <ImportFlowPreviewPage onClose={() => setShowImportFlow(false)} />
      )}
    </div>
  );
}
