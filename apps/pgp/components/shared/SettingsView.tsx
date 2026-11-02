import { useEffect, useRef, useState } from "react";
import { ChevronRightIcon } from "lucide-react";

import { Block, BlockLabel, BlockStack } from "@amibeingpwned/ui/block";
import { Button } from "@amibeingpwned/ui/button";
import { SwitchRow } from "@amibeingpwned/ui/switch-row";

import type { PresetId } from "../../lib/presets";
import type {
  AutoLockTimeout,
  PgpPreferences,
  StorageLocation,
} from "../../lib/storage/preferences";
import { useAsyncAction } from "../../hooks/useAsyncAction";
import { useContacts } from "../../hooks/useContacts";
import { useCrxKeys } from "../../hooks/useCrxKeys";
import { useKeyring } from "../../hooks/useKeyring";
import { useNav } from "../../hooks/useNav";
import { savePreference, usePreferences } from "../../hooks/usePreferences";
import { useVault } from "../../hooks/useVault";
import { t, tn } from "../../lib/i18n";
import { enterNeverCacheMode } from "../../lib/never-cache";
import {
  activePreset,
  bundledSettingsCustomized,
  PRESETS,
  snapshotBundleFields,
} from "../../lib/presets";
import { isQuotaExceeded } from "../../lib/storage/chunked";
import { historyByteSize } from "../../lib/storage/history";
import { getPreferences } from "../../lib/storage/preferences";
import { preferencesStore } from "../../lib/storage/preferences-store";
import { refreshVaultLists } from "../../lib/storage/vault-lists";
import { moveVault } from "../../lib/storage/vault-state";
import { toast } from "../../lib/toast";
import { errorMessage } from "../../lib/utils/errors";
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

export function SettingsView() {
  const keyring = useKeyring();
  const contactStore = useContacts();
  const crx = useCrxKeys();
  const { session, ...vault } = useVault();
  const appNav = useNav();
  const onVaultMoved = refreshVaultLists;
  const masterPasskey = vault.masterPasskey;
  const masterSealSalt = vault.masterSealSalt;
  const myKeys = keyring.keys;
  const contacts = contactStore.contacts;
  const isUnlocked = session.isUnlocked;
  const getKeyHandle = session.getKeyHandle;
  const onUnlockWithPassword = session.unlockWithPassword;
  const onUnlockWithPasskey = session.unlockWithPasskey;
  const onAddKey = vault.addKey;
  const onAddContact = contactStore.add;
  const onRemoveContact = contactStore.remove;
  const crxKeys = crx.keys;
  const onAddCrxKey = crx.add;
  const primaryPasskeyCredentialId = vault.masterPasskeyCredentialId;
  const autoOpenPresets = appNav.presets;
  const consumeIntent = appNav.consume;
  const prefs = usePreferences();
  const {
    advancedMode,
    storageLocation,
    autoLockEnabled,
    autoLockMinutes,
    neverCacheKeys,
    autoDownloadFiles,
    autoDownloadText,
    lockOnTabAway,
    unlockKeysOnOpen,
    crxSigningEnabled,
    keyDiscoveryEnabled,
    aiTranslateEnabled,
    translationTargetLanguage,
  } = prefs;
  const migration = useAsyncAction((e) => ({
    message: isQuotaExceeded(e)
      ? t("shared_sync_quota_error")
      : errorMessage(e, t("shared_migration_failed")),
  }));
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
    consumeIntent("presets");
  }, [autoOpenPresets, consumeIntent]);

  const currentPreset = activePreset(prefs);

  // Ordering and rollback live in `moveVault`.
  const handleStorageChange = async (next: StorageLocation) => {
    if (next === storageLocation) return;
    await migration.run(async () => {
      await moveVault(storageLocation, next);
      await preferencesStore.reload();
      void onVaultMoved();
    });
  };

  // Enter never-cache via the shared transition (flip prefs + wipe
  // history), which saves directly; read back what it persisted.
  const enableNeverCache = async () => {
    await enterNeverCacheMode();
    await preferencesStore.reload();
  };

  // Not optimistic: the next vault unlock reads the STORED value, so the
  // toggle must not say "off" while storage still says "on".
  const handleUnlockOnOpenToggle = (v: boolean) =>
    // Entering unlock-on-open leaves never-cache (see enableNeverCache
    // for the converse). History stays as the user had it.
    savePreference(
      v
        ? { unlockKeysOnOpen: true, neverCacheKeys: false }
        : { unlockKeysOnOpen: false },
      { optimistic: false },
    );

  const handleNeverCacheToggle = async (v: boolean) => {
    if (!v) {
      // Turning never-cache OFF never re-enables history; the user
      // opted out of retention and must opt back in explicitly.
      void savePreference({ neverCacheKeys: false });
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

  // Restore the pre-apply snapshot of the bundled fields. Cleared
  // history is gone for good; the apply toast says so. storageLocation
  // can't be restored by a plain save, it needs the full migration.
  const undoPresetApply = async (snapshot: Partial<PgpPreferences>) => {
    const { storageLocation: prevLocation, ...rest } = snapshot;
    await preferencesStore.update(rest);
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
      await preferencesStore.update(rest);
      await enableNeverCache();
    } else {
      await preferencesStore.update(bundle);
    }

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
            currentPreset === "custom" && (
              <p className="text-muted-foreground text-xs">
                {bundledSettingsCustomized(prefs)
                  ? t("shared_preset_bundled_changed")
                  : t("shared_preset_none_selected")}
              </p>
            )
          }
          value={
            currentPreset === "custom"
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
        <BlockLabel as="h2">{t("shared_key_storage")}</BlockLabel>
        <StorageLocationPicker
          value={storageLocation}
          onChange={handleStorageChange}
          disabled={migration.busy}
        />
        {migration.error && (
          <p className="text-bad px-1 text-xs">{migration.error.message}</p>
        )}
      </div>

      <div className="space-y-1.5">
        <BlockLabel as="h2">{t("shared_key_security")}</BlockLabel>
        <BlockStack>
          <SwitchRow
            title={t("shared_auto_lock_title")}
            description={t("shared_auto_lock_desc")}
            checked={autoLockEnabled}
            onCheckedChange={(v) => {
              void savePreference({ autoLockEnabled: v });
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
                  void savePreference({
                    autoLockMinutes: Number(e.target.value) as AutoLockTimeout,
                  })
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
              void savePreference({ lockOnTabAway: v });
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
        <BlockLabel as="h2">{t("shared_downloads")}</BlockLabel>
        <BlockStack>
          <SwitchRow
            title={t("shared_auto_download_files_title")}
            description={t("shared_auto_download_files_desc")}
            checked={autoDownloadFiles}
            onCheckedChange={(v) => {
              void savePreference({ autoDownloadFiles: v });
            }}
          />
          <SwitchRow
            title={t("shared_auto_download_text_title")}
            description={t("shared_auto_download_text_desc")}
            checked={autoDownloadText}
            onCheckedChange={(v) => {
              void savePreference({ autoDownloadText: v });
            }}
          />
        </BlockStack>
      </div>

      <div className="space-y-1.5">
        <BlockLabel as="h2">{t("shared_key_discovery")}</BlockLabel>
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
              void savePreference({ keyDiscoveryEnabled: v });
            }}
          />
        </BlockStack>
      </div>

      <div className="space-y-1.5">
        <BlockLabel as="h2">{t("shared_crx_signing")}</BlockLabel>
        <BlockStack>
          <SwitchRow
            title={t("shared_crx_enable_title")}
            description={t("shared_crx_enable_desc")}
            checked={crxSigningEnabled}
            onCheckedChange={(v) => {
              void savePreference({ crxSigningEnabled: v });
            }}
          />
          <NavRow
            title={t("shared_crx_how")}
            onClick={() => setShowCrxInfo(true)}
          />
        </BlockStack>
      </div>

      <div className="space-y-1.5">
        <BlockLabel as="h2">{t("shared_backup")}</BlockLabel>
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
        <BlockLabel as="h2">{t("shared_display")}</BlockLabel>
        <BlockStack>
          <SwitchRow
            title={t("shared_advanced_mode")}
            checked={advancedMode}
            onCheckedChange={(v) => void savePreference({ advancedMode: v })}
          />
        </BlockStack>
        <p className="text-muted-foreground px-1 text-xs">
          {t("shared_advanced_mode_desc")}
        </p>
      </div>

      {import.meta.env.DEV && (
        <div className="space-y-1.5">
          <BlockLabel as="h2">{t("shared_developer")}</BlockLabel>
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
        <BlockLabel as="h2">{t("shared_about")}</BlockLabel>
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
          onRemoveContact={onRemoveContact}
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
            void savePreference({ aiTranslateEnabled: v });
          }}
          targetLanguage={translationTargetLanguage}
          onTargetLanguageChange={(code) => {
            void savePreference({ translationTargetLanguage: code });
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
