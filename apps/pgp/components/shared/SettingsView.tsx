import { useEffect, useState } from "react";
import { ChevronRightIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";
import { Switch } from "@amibeingpwned/ui/switch";

import type { CrxSigningKeyBlob } from "../../lib/crx/types";
import type { PresetId } from "../../lib/presets";
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
import { activePreset, PRESETS } from "../../lib/presets";
import { isQuotaExceeded } from "../../lib/storage/chunked";
import {
  copyEncryptedBlobRepacked,
  purgeEncryptedBlob,
} from "../../lib/storage/encrypted-store";
import { invalidateLocationCache } from "../../lib/storage/engine";
import { getPreferences, savePreferences } from "../../lib/storage/preferences";
import { ExportKeysPage } from "../keys/ExportKeysPage";
import { CrxSigningInfoPage } from "../settings/CrxSigningInfoPage";
import { DevToolsPage } from "../settings/DevToolsPage";
import { ImportAllKeysPage } from "../settings/ImportAllKeysPage";
import { SecurityPresetPage } from "../settings/SecurityPresetPage";
import { StorageLocationPicker } from "./StorageLocationPicker";

const AUTO_LOCK_OPTIONS: { value: AutoLockTimeout; label: string }[] = [
  { value: 2, label: "2 minutes" },
  { value: 5, label: "5 minutes" },
  { value: 10, label: "10 minutes" },
  { value: 15, label: "15 minutes" },
  { value: 30, label: "30 minutes" },
  { value: 60, label: "1 hour" },
];

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
  crxSigningEnabled: boolean;
  onCrxSigningEnabledChange: (v: boolean) => void;
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
  crxSigningEnabled,
  onCrxSigningEnabledChange,
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
  const [showPresets, setShowPresets] = useState(false);

  // Open the presets subpage when routed here by the palette action.
  useEffect(() => {
    if (!autoOpenPresets) return;
    setShowPresets(true);
    onAutoOpenPresetsConsumed?.();
  }, [autoOpenPresets, onAutoOpenPresetsConsumed]);

  // Full preferences snapshot for computing the active preset: the
  // bundles cover fields this view has no props for (historyEnabled,
  // encryptToSelf, clipboardWipeSeconds). Re-read whenever a bundled
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
          ? "Not enough sync space. Chrome caps synced data at about 100 KB total, so this vault is too large to sync across devices. Keep it on this device, or remove some keys and try again."
          : e instanceof Error
            ? e.message
            : "Migration failed",
      );
    } finally {
      setMigratingTo(null);
    }
  };

  const handleAutoLockChange = (v: AutoLockTimeout) => {
    onAutoLockChange(v);
    void savePreferences({ autoLockMinutes: v });
  };

  const applyPreset = async (id: PresetId) => {
    // storageLocation can't go through plain savePreferences: flipping
    // it without migrating the vault blobs would strand them in the
    // old area. Apply the rest, then run the real migration if needed.
    const { storageLocation: bundleLocation, ...bundle } = PRESETS[id].bundle;
    await savePreferences(bundle);

    // Sync the parent-held state for fields this view has props for.
    if (bundle.autoLockEnabled !== undefined) {
      onAutoLockEnabledChange(bundle.autoLockEnabled);
    }
    if (bundle.autoLockMinutes !== undefined) {
      onAutoLockChange(bundle.autoLockMinutes);
    }
    if (bundle.lockOnTabAway !== undefined) {
      onLockOnTabAwayChange(bundle.lockOnTabAway);
    }
    if (bundle.neverCacheKeys !== undefined) {
      onNeverCacheKeysChange(bundle.neverCacheKeys);
    }
    setPrefs(await getPreferences());
    // The bundle rewrote toggles the always-mounted workspace renders
    // (historyEnabled, encryptToSelf); tell it to re-read.
    onWorkspacePrefsChanged?.();

    if (bundleLocation !== undefined && bundleLocation !== storageLocation) {
      await handleStorageChange(bundleLocation);
    }
  };

  return (
    <div className="space-y-5">
      <div>
        <button
          type="button"
          onClick={() => setShowPresets(true)}
          className="border-border hover:border-muted-foreground/40 flex w-full items-center justify-between gap-4 rounded-md border p-4 text-left transition-colors"
        >
          <div className="min-w-0">
            <span className="text-sm">Security preset</span>
            {currentPreset === "custom" && (
              <p className="text-muted-foreground text-xs">
                A bundled setting was changed
              </p>
            )}
          </div>
          <span className="flex min-w-0 items-center gap-1">
            <span className="text-muted-foreground truncate text-sm">
              {currentPreset === null
                ? ""
                : currentPreset === "custom"
                  ? "Custom"
                  : PRESETS[currentPreset].title}
            </span>
            <ChevronRightIcon className="text-muted-foreground h-4 w-4 shrink-0" />
          </span>
        </button>
      </div>

      <div>
        <h2 className="mb-2 text-sm font-semibold">Key storage</h2>
        <StorageLocationPicker
          value={storageLocation}
          onChange={handleStorageChange}
          disabled={migratingTo !== null}
        />
        {error && <p className="text-destructive mt-1 text-xs">{error}</p>}
      </div>

      <div>
        <h2 className="mb-2 text-sm font-semibold">Key security</h2>

        <div className="border-border rounded-md border p-4">
          <label className="flex items-center justify-between gap-4">
            <div>
              <span className="text-sm">Auto-lock after inactivity</span>
              <p className="text-muted-foreground text-xs">
                Lock unlocked keys after a period of no activity in the panel.
                The OS lockscreen always locks immediately regardless of this
                setting.
              </p>
            </div>
            <Switch
              checked={autoLockEnabled}
              onCheckedChange={(v) => {
                onAutoLockEnabledChange(v);
                void savePreferences({ autoLockEnabled: v });
              }}
            />
          </label>
          {autoLockEnabled && (
            <div className="mt-3">
              <label
                htmlFor="auto-lock-after"
                className="text-muted-foreground mb-1 block text-xs"
              >
                Lock after
              </label>
              <select
                id="auto-lock-after"
                value={autoLockMinutes}
                onChange={(e) =>
                  handleAutoLockChange(
                    Number(e.target.value) as AutoLockTimeout,
                  )
                }
                className="border-border bg-background focus:ring-ring w-full rounded-md border px-2 py-1.5 text-sm focus:ring-2 focus:outline-none"
              >
                {AUTO_LOCK_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </div>
          )}
        </div>

        <label className="border-border mt-2 flex items-center justify-between gap-4 rounded-md border p-4">
          <div>
            <span className="text-sm">Lock when I tab away</span>
            <p className="text-muted-foreground text-xs">
              Lock the moment the side panel isn't visible (alt-tab, collapsed,
              or window minimised).
            </p>
          </div>
          <Switch
            checked={lockOnTabAway}
            onCheckedChange={(v) => {
              onLockOnTabAwayChange(v);
              void savePreferences({ lockOnTabAway: v });
            }}
          />
        </label>

        <label className="border-border mt-2 flex items-center justify-between gap-4 rounded-md border p-4">
          <div>
            <span className="text-sm">Never auto-cache keys</span>
            <p className="text-muted-foreground text-xs">
              Keys are wiped from memory after each operation. You can still
              manually unlock keys from the Keys tab.
            </p>
          </div>
          <Switch
            checked={neverCacheKeys}
            onCheckedChange={(v) => {
              onNeverCacheKeysChange(v);
              void savePreferences({ neverCacheKeys: v });
            }}
          />
        </label>
      </div>

      <div>
        <h2 className="mb-2 text-sm font-semibold">Downloads</h2>
        <label className="border-border flex items-center justify-between gap-4 rounded-md border p-4">
          <div>
            <span className="text-sm">Auto-download file results</span>
            <p className="text-muted-foreground text-xs">
              Automatically download after encrypting or decrypting files.
            </p>
          </div>
          <Switch
            checked={autoDownloadFiles}
            onCheckedChange={(v) => {
              onAutoDownloadFilesChange(v);
              void savePreferences({ autoDownloadFiles: v });
            }}
          />
        </label>

        <label className="border-border mt-2 flex items-center justify-between gap-4 rounded-md border p-4">
          <div>
            <span className="text-sm">Auto-download text results</span>
            <p className="text-muted-foreground text-xs">
              Automatically download after encrypting or decrypting text.
            </p>
          </div>
          <Switch
            checked={autoDownloadText}
            onCheckedChange={(v) => {
              onAutoDownloadTextChange(v);
              void savePreferences({ autoDownloadText: v });
            }}
          />
        </label>
      </div>

      <div>
        <h2 className="mb-2 text-sm font-semibold">CRX signing</h2>
        <label className="border-border flex items-center justify-between gap-4 rounded-md border p-4">
          <div>
            <span className="text-sm">Enable CRX signing</span>
            <p className="text-muted-foreground text-xs">
              Sign Chrome extension packages (.crx) for the Web Store&rsquo;s
              Verified CRX Uploads, using a key kept in your vault instead of
              your build pipeline.
            </p>
          </div>
          <Switch
            checked={crxSigningEnabled}
            onCheckedChange={(v) => {
              onCrxSigningEnabledChange(v);
              void savePreferences({ crxSigningEnabled: v });
            }}
          />
        </label>
        <Button
          variant="outline"
          size="sm"
          className="mt-2 w-full"
          onClick={() => setShowCrxInfo(true)}
        >
          How CRX signing works
        </Button>
      </div>

      <div>
        <h2 className="mb-2 text-sm font-semibold">Backup</h2>
        <div className="border-border rounded-md border p-4">
          <p className="text-muted-foreground text-xs">
            Export your keys and contacts as a single armored file, or restore
            from one. Exported private keys are encrypted with a passphrase of
            your choice.
          </p>
          <div className="mt-2 flex gap-2">
            <Button
              variant="outline"
              size="sm"
              className="flex-1"
              onClick={() => setShowExportAll(true)}
            >
              Export all keys
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="flex-1"
              onClick={() => setShowImportAll(true)}
            >
              Import keys
            </Button>
          </div>
        </div>
      </div>

      <div>
        <h2 className="mb-2 text-sm font-semibold">Display</h2>
        <label className="border-border flex items-center justify-between gap-4 rounded-md border p-4">
          <span className="text-sm">Advanced mode</span>
          <Switch checked={advancedMode} onCheckedChange={toggleAdvanced} />
        </label>
        <p className="text-muted-foreground mt-1 text-xs">
          Show key fingerprints, algorithms, and output format options.
        </p>
      </div>

      {import.meta.env.DEV && (
        <div>
          <h2 className="mb-2 text-sm font-semibold">Developer</h2>
          <div className="border-border rounded-md border p-4">
            <p className="text-muted-foreground text-xs">
              Inspect chrome.storage and dump WASM memory for testing. This
              section only appears in development builds.
            </p>
            <Button
              variant="outline"
              size="sm"
              className="mt-2 w-full"
              onClick={() => setShowDevTools(true)}
            >
              Open dev tools
            </Button>
          </div>
        </div>
      )}

      <div>
        <h2 className="mb-2 text-sm font-semibold">About</h2>
        <div className="border-border rounded-md border p-4">
          <p className="text-sm">PGP Tools</p>
          <p className="text-muted-foreground mt-1 text-xs">
            A privacy tool by{" "}
            <a
              href="https://amibeingpwned.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary underline"
            >
              Am I Being Pwned
            </a>
            . <br />
            <a
              href="https://github.com/Am-I-Being-Pwned/PGP-Tools"
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary underline"
            >
              Source on GitHub
            </a>
            .
          </p>
          <p className="text-muted-foreground mt-2 text-xs">
            Worried about malicious browser extensions? Scan your extensions for
            data harvesting, session hijacking, and other threats.
          </p>
          <a
            href="https://amibeingpwned.com"
            target="_blank"
            rel="noopener noreferrer"
          >
            <Button variant="outline" size="sm" className="mt-2">
              Check your extensions
            </Button>
          </a>
        </div>
      </div>

      {showExportAll && (
        <ExportKeysPage
          title="Export all keys"
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
        />
      )}

      {showCrxInfo && (
        <CrxSigningInfoPage onClose={() => setShowCrxInfo(false)} />
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
    </div>
  );
}
