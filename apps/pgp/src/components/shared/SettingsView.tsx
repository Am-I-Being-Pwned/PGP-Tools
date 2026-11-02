import { useEffect, useRef } from "react";
import { ChevronRightIcon } from "lucide-react";

import {
  Block,
  BlockLabel,
  BlockStack,
  Button,
  SwitchRow,
} from "@amibeingpwned/ui";

import { ExportKeysPage } from "~/components/keys/ExportKeysPage";
import { CrxSigningInfoPage } from "~/components/settings/CrxSigningInfoPage";
import { DevToolsPage } from "~/components/settings/DevToolsPage";
import { ImportAllKeysPage } from "~/components/settings/ImportAllKeysPage";
import { ImportFlowPreviewPage } from "~/components/settings/ImportFlowPreviewPage";
import { KeyboardShortcutsPage } from "~/components/settings/KeyboardShortcutsPage";
import { SecurityPresetPage } from "~/components/settings/SecurityPresetPage";
import { TranslationPage } from "~/components/settings/TranslationPage";
import { useAsyncAction } from "~/hooks/useAsyncAction";
import { useContacts } from "~/hooks/useContacts";
import { useCrxKeys } from "~/hooks/useCrxKeys";
import { useKeyring } from "~/hooks/useKeyring";
import { useNavIntent } from "~/hooks/useNav";
import { savePreference, usePreferences } from "~/hooks/usePreferences";
import { useVault } from "~/hooks/useVault";
import { t, tn } from "~/lib/i18n";
import { enterNeverCacheMode } from "~/lib/never-cache";
import {
  activePreset,
  bundledSettingsCustomized,
  PRESETS,
  snapshotBundleFields,
  type PresetId,
} from "~/lib/presets";
import { isQuotaExceeded } from "~/lib/storage/chunked";
import { historyByteSize } from "~/lib/storage/history";
import {
  getPreferences,
  type AutoLockTimeout,
  type PgpPreferences,
  type StorageLocation,
} from "~/lib/storage/preferences";
import { preferencesStore } from "~/lib/storage/preferences-store";
import { refreshVaultLists } from "~/lib/storage/vault-lists";
import { moveVault } from "~/lib/storage/vault-state";
import { toast } from "~/lib/toast";
import { errorMessage } from "~/lib/utils/errors";
import { formatFileSize } from "~/lib/utils/formatting";
import { ConfirmPage } from "./ConfirmPage";
import { StorageLocationPicker } from "./StorageLocationPicker";
import { useNavStack } from "./useNavStack";

const AUTO_LOCK_OPTIONS: AutoLockTimeout[] = [2, 5, 10, 15, 30, 60];

/** Muted links: green is reserved for "on" and "go". */
const ABOUT_LINK_CLASS =
  "text-foreground/80 hover:text-foreground underline decoration-white/20 underline-offset-2 transition-colors";

/** Focus ring inset: the stack clips anything outside its blocks. */
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

type SettingsRoute =
  | { page: "presets" }
  | { page: "translation" }
  | { page: "shortcuts" }
  | { page: "crx-info" }
  | { page: "export-all" }
  | { page: "import-all" }
  /** Turning never-cache on deletes this much stored history. */
  | { page: "never-cache-confirm"; historyBytes: number }
  | { page: "dev-tools" }
  | { page: "import-flow" };

function autoLockLabel(minutes: AutoLockTimeout): string {
  return minutes === 60 ? t("shared_one_hour") : tn("shared_minutes", minutes);
}

export function SettingsView() {
  const keyring = useKeyring();
  const contactStore = useContacts();
  const crx = useCrxKeys();
  const { session, ...vault } = useVault();
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
  const nav = useNavStack<SettingsRoute>();

  // The palette's "security presets" action lands here.
  useNavIntent("presets", () => nav.push({ page: "presets" }));

  const currentPreset = activePreset(prefs);

  // Ordering and rollback live in `moveVault`.
  const handleStorageChange = async (next: StorageLocation) => {
    if (next === storageLocation) return;
    await migration.run(async () => {
      await moveVault(storageLocation, next);
      await preferencesStore.reload();
      void refreshVaultLists();
    });
  };

  // Shared transition (flip prefs + wipe history).
  const enableNeverCache = async () => {
    await enterNeverCacheMode();
    await preferencesStore.reload();
  };

  // Not optimistic: the next vault unlock reads the STORED value, so the
  // toggle must not say "off" while storage still says "on".
  const handleUnlockOnOpenToggle = (v: boolean) =>
    // Entering unlock-on-open leaves never-cache.
    savePreference(
      v
        ? { unlockKeysOnOpen: true, neverCacheKeys: false }
        : { unlockKeysOnOpen: false },
      { optimistic: false },
    );

  const handleNeverCacheToggle = async (v: boolean) => {
    if (!v) {
      // Turning never-cache off never re-enables history.
      void savePreference({ neverCacheKeys: false });
      return;
    }
    const bytes = await historyByteSize();
    if (bytes > 0) {
      // Entering never-cache deletes history: confirm the cost first.
      nav.push({ page: "never-cache-confirm", historyBytes: bytes });
      return;
    }
    await enableNeverCache();
  };

  // Cleared history is gone for good, and storageLocation needs the full
  // migration, not a plain save.
  const undoPresetApply = async (snapshot: Partial<PgpPreferences>) => {
    const { storageLocation: prevLocation, ...rest } = snapshot;
    await preferencesStore.update(rest);
    if (prevLocation !== undefined && prevLocation !== storageLocation) {
      await handleStorageChange(prevLocation);
    }
  };
  // Via a ref: the undo toast can outlive this render.
  const undoPresetApplyRef = useRef(undoPresetApply);
  useEffect(() => {
    undoPresetApplyRef.current = undoPresetApply;
  });

  const applyPreset = async (id: PresetId) => {
    // Exactly the bundled fields, so Undo restores only those.
    const snapshot = snapshotBundleFields(
      await getPreferences(),
      PRESETS[id].bundle,
    );
    // storageLocation goes through the real migration, never a plain save.
    const { storageLocation: bundleLocation, ...bundle } = PRESETS[id].bundle;
    let historyCleared = false;
    if (bundle.neverCacheKeys === true) {
      historyCleared = (await historyByteSize()) > 0;
      // Shared transition, so this can't diverge from the toggle.
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
          onClick={() => nav.push({ page: "presets" })}
        />
        <NavRow
          title={t("shared_translation")}
          value={aiTranslateEnabled ? t("common_on") : t("common_off")}
          onClick={() => nav.push({ page: "translation" })}
        />
        <NavRow
          title={t("shared_keyboard_shortcuts")}
          onClick={() => nav.push({ page: "shortcuts" })}
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
          {vault.masterPasskey && (
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
          {/* The only network preference: name the exact hosts and what
              they learn. */}
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
            onClick={() => nav.push({ page: "crx-info" })}
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
            onClick={() => nav.push({ page: "export-all" })}
          />
          <NavRow
            title={t("shared_import_keys")}
            onClick={() => nav.push({ page: "import-all" })}
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
              onClick={() => nav.push({ page: "dev-tools" })}
            />
            <NavRow
              title={t("shared_import_flow_states")}
              onClick={() => nav.push({ page: "import-flow" })}
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

      {nav.stack.map(({ id, route }) => {
        const close = () => nav.remove(id);
        switch (route.page) {
          case "presets":
            return (
              <SecurityPresetPage
                key={id}
                currentPreset={currentPreset}
                onApply={applyPreset}
                onClose={close}
              />
            );
          case "translation":
            return (
              <TranslationPage
                key={id}
                onClose={close}
                enabled={aiTranslateEnabled}
                onEnabledChange={(v) => {
                  void savePreference({ aiTranslateEnabled: v });
                }}
                targetLanguage={translationTargetLanguage}
                onTargetLanguageChange={(code) => {
                  void savePreference({ translationTargetLanguage: code });
                }}
              />
            );
          case "shortcuts":
            return <KeyboardShortcutsPage key={id} onClose={close} />;
          case "crx-info":
            return <CrxSigningInfoPage key={id} onClose={close} />;
          case "export-all":
            return (
              <ExportKeysPage
                key={id}
                title={t("shared_export_all_keys")}
                onClose={close}
                myKeys={keyring.keys}
                contacts={contactStore.contacts}
                crxKeys={crx.keys}
                isUnlocked={session.isUnlocked}
                getKeyHandle={session.getKeyHandle}
                onUnlockWithPassword={session.unlockWithPassword}
                onUnlockWithPasskey={session.unlockWithPasskey}
              />
            );
          case "import-all":
            return (
              <ImportAllKeysPage
                key={id}
                onClose={close}
                myKeys={keyring.keys}
                contacts={contactStore.contacts}
                onAddKey={vault.addKey}
                onAddContact={contactStore.add}
                onRemoveContact={contactStore.remove}
                onAddCrxKey={crx.add}
                crxKeys={crx.keys}
                reusePasskeyCredentialId={vault.masterPasskeyCredentialId}
                masterSealSalt={vault.masterSealSalt}
              />
            );
          case "never-cache-confirm":
            return (
              <ConfirmPage
                key={id}
                title={t("shared_delete_history_title")}
                confirmLabel={t("shared_delete_history_confirm")}
                onCancel={close}
                onConfirm={enableNeverCache}
              >
                <p>
                  {t("shared_delete_history_body", {
                    size: formatFileSize(route.historyBytes),
                  })}
                </p>
              </ConfirmPage>
            );
          case "dev-tools":
            return import.meta.env.DEV ? (
              <DevToolsPage key={id} onClose={close} />
            ) : null;
          case "import-flow":
            return import.meta.env.DEV ? (
              <ImportFlowPreviewPage key={id} onClose={close} />
            ) : null;
        }
      })}
    </div>
  );
}
