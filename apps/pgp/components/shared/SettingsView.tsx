import { useState } from "react";

import { Button } from "@amibeingpwned/ui/button";
import { Switch } from "@amibeingpwned/ui/switch";

import type {
  AutoLockTimeout,
  StorageLocation,
} from "../../lib/storage/preferences";
import { STORAGE_CONTACTS, STORAGE_KEYRING } from "../../lib/constants";
import { invalidateLocationCache, migrate } from "../../lib/storage/engine";
import { savePreferences } from "../../lib/storage/preferences";
import { StorageLocationPicker } from "./StorageLocationPicker";

const AUTO_LOCK_OPTIONS: { value: AutoLockTimeout; label: string }[] = [
  { value: 5, label: "5 minutes" },
  { value: 15, label: "15 minutes" },
  { value: 30, label: "30 minutes" },
  { value: 60, label: "1 hour" },
];

interface SettingsViewProps {
  advancedMode: boolean;
  onAdvancedModeChange: (v: boolean) => void;
  storageLocation: StorageLocation;
  onStorageLocationChange: (loc: StorageLocation) => void;
  autoLockMinutes: AutoLockTimeout;
  onAutoLockChange: (v: AutoLockTimeout) => void;
  neverCacheKeys: boolean;
  onNeverCacheKeysChange: (v: boolean) => void;
  autoDownloadFiles: boolean;
  onAutoDownloadFilesChange: (v: boolean) => void;
  autoDownloadText: boolean;
  onAutoDownloadTextChange: (v: boolean) => void;
}

export function SettingsView({
  advancedMode,
  onAdvancedModeChange,
  storageLocation,
  onStorageLocationChange,
  autoLockMinutes,
  onAutoLockChange,
  neverCacheKeys,
  onNeverCacheKeysChange,
  autoDownloadFiles,
  onAutoDownloadFilesChange,
  autoDownloadText,
  onAutoDownloadTextChange,
}: SettingsViewProps) {
  const [migrating, setMigrating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const toggleAdvanced = () => {
    const next = !advancedMode;
    onAdvancedModeChange(next);
    void savePreferences({ advancedMode: next });
  };

  const handleStorageChange = async (next: StorageLocation) => {
    if (next === storageLocation) return;
    setMigrating(true);
    try {
      await migrate([STORAGE_KEYRING, STORAGE_CONTACTS], storageLocation, next);
      await savePreferences({ storageLocation: next });
      invalidateLocationCache();
      onStorageLocationChange(next);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Migration failed");
    } finally {
      setMigrating(false);
    }
  };

  const handleAutoLockChange = (v: AutoLockTimeout) => {
    onAutoLockChange(v);
    void savePreferences({ autoLockMinutes: v });
  };

  return (
    <div className="space-y-5">
      <div>
        <h2 className="mb-2 text-sm font-semibold">Key storage</h2>
        <StorageLocationPicker
          value={storageLocation}
          onChange={handleStorageChange}
          disabled={migrating}
        />
        {migrating && (
          <p className="text-muted-foreground mt-1 text-xs">
            Migrating keys...
          </p>
        )}
        {error && <p className="text-destructive mt-1 text-xs">{error}</p>}
      </div>

      <div>
        <h2 className="mb-2 text-sm font-semibold">Key security</h2>

        <div className="border-border rounded-md border p-3">
          <label className="mb-1 block text-sm">
            Auto-lock after inactivity
          </label>
          <select
            value={autoLockMinutes}
            onChange={(e) =>
              handleAutoLockChange(Number(e.target.value) as AutoLockTimeout)
            }
            className="border-border bg-background focus:ring-ring w-full rounded-md border px-2 py-1.5 text-sm focus:ring-2 focus:outline-none"
          >
            {AUTO_LOCK_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
          <p className="text-muted-foreground mt-1 text-xs">
            Unlocked keys are automatically locked after this period of
            inactivity.
          </p>
        </div>

        <label className="border-border mt-2 flex items-center justify-between rounded-md border p-3">
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
        <label className="border-border flex items-center justify-between rounded-md border p-3">
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

        <label className="border-border mt-2 flex items-center justify-between rounded-md border p-3">
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
        <h2 className="mb-2 text-sm font-semibold">Display</h2>
        <label className="border-border flex items-center justify-between rounded-md border p-3">
          <span className="text-sm">Advanced mode</span>
          <Switch checked={advancedMode} onCheckedChange={toggleAdvanced} />
        </label>
        <p className="text-muted-foreground mt-1 text-xs">
          Show key fingerprints, algorithms, and output format options.
        </p>
      </div>

      <div>
        <h2 className="mb-2 text-sm font-semibold">About</h2>
        <div className="border-border rounded-md border p-3">
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
            .{" "}
            <br />
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
    </div>
  );
}
