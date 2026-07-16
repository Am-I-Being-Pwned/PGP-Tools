import { useEffect, useState } from "react";

import { Button } from "@amibeingpwned/ui/button";

import { useCopyToClipboard } from "../../hooks/useCopyToClipboard";
import {
  clearAllStorage,
  dumpAllStorage,
  isStorageDump,
  restoreAllStorage,
} from "../../lib/dev/dump";
import { hasContactsSession, ping } from "../../lib/pgp/wasm";
import { dumpWasmMemoryForDev } from "../../lib/pgp/wasm-loader";
import { toast } from "../../lib/toast";
import { downloadBinary, downloadText } from "../../lib/utils/download";
import { formatFileSize } from "../../lib/utils/formatting";
import { SubPage } from "../shared/SubPage";

interface WasmInfo {
  pong: string;
  sessionActive: boolean;
  memoryBytes: number | null;
}

export function DevToolsPage({ onClose }: { onClose: () => void }) {
  const [storageJson, setStorageJson] = useState<string | null>(null);
  const [wasm, setWasm] = useState<WasmInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [restoreName, setRestoreName] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { copy } = useCopyToClipboard();

  const refresh = async () => {
    setLoading(true);
    try {
      const [dump, pong, sessionActive] = await Promise.all([
        dumpAllStorage(),
        ping(),
        hasContactsSession(),
      ]);
      setStorageJson(JSON.stringify(dump, null, 2));
      // Read the memory snapshot only for its size here; the full bytes
      // are re-read on demand by the download button.
      setWasm({
        pong,
        sessionActive,
        memoryBytes: dumpWasmMemoryForDev()?.byteLength ?? null,
      });
    } catch (e) {
      // Stable ids on the dev-tool errors: retrying a failing action
      // updates the toast instead of stacking duplicates.
      toast.error(e instanceof Error ? e.message : "Dev dump failed", {
        id: "dev-dump-failed",
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);

  const stamp = () =>
    new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);

  const handleCopy = () => {
    if (!storageJson) return;
    void copy(storageJson, { label: "Storage JSON" });
  };

  const handleDownloadStorage = () => {
    if (!storageJson) return;
    downloadText(storageJson, `pgp-storage-${stamp()}.json`);
  };

  const handleDownloadMemory = () => {
    const bytes = dumpWasmMemoryForDev();
    if (!bytes) {
      toast.error("WASM memory unavailable", { id: "dev-wasm-memory" });
      return;
    }
    downloadBinary(bytes, `pgp-wasm-memory-${stamp()}.bin`);
  };

  const handleRestoreFile = async (file: File | undefined) => {
    if (!file) return;
    setBusy(true);
    setRestoreName(file.name);
    try {
      const parsed: unknown = JSON.parse(await file.text());
      if (!isStorageDump(parsed)) {
        toast.error("Not a storage dump ({ local, sync, session }).", {
          id: "dev-restore-failed",
        });
        return;
      }
      await restoreAllStorage(parsed);
      await refresh();
      toast.success("Storage restored. Reload the panel to apply.");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Restore failed", {
        id: "dev-restore-failed",
      });
    } finally {
      setBusy(false);
    }
  };

  const handleClearAll = async () => {
    setBusy(true);
    try {
      await clearAllStorage();
      await refresh();
      toast.success("Storage cleared. Reload the panel to apply.");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Clear failed", {
        id: "dev-clear-failed",
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <SubPage title="Developer tools" onClose={onClose}>
      <div className="space-y-4">
        <p className="text-muted-foreground text-xs">
          Dev-only diagnostics. Not shipped in production builds.
        </p>

        <div>
          <div className="mb-1.5 flex items-center justify-between">
            <h3 className="text-xs font-semibold">WASM</h3>
            <Button size="sm" variant="outline" onClick={() => void refresh()}>
              {loading ? "..." : "Refresh"}
            </Button>
          </div>
          <div className="border-border space-y-1 rounded-md border p-2.5 text-xs">
            <Row label="ping" value={wasm?.pong ?? "-"} />
            <Row
              label="vault session"
              value={wasm ? (wasm.sessionActive ? "active" : "locked") : "-"}
            />
            <Row
              label="linear memory"
              value={
                wasm?.memoryBytes != null
                  ? formatFileSize(wasm.memoryBytes)
                  : "-"
              }
            />
          </div>
          <Button
            size="sm"
            variant="outline"
            className="mt-2 w-full"
            disabled={wasm?.memoryBytes == null}
            onClick={handleDownloadMemory}
          >
            Download WASM memory
          </Button>
          <p className="text-muted-foreground/70 mt-1 text-[10px]">
            Raw linear memory can contain decrypted key material - handle the
            dump like a secret.
          </p>
        </div>

        <div>
          <h3 className="mb-1.5 text-xs font-semibold">chrome.storage</h3>
          <pre className="border-border bg-muted/30 max-h-64 overflow-auto rounded-md border p-2 font-mono text-[10px] leading-relaxed">
            {storageJson ?? (loading ? "Loading…" : "-")}
          </pre>
          <div className="mt-2 flex gap-2">
            <Button
              size="sm"
              variant="outline"
              className="flex-1"
              disabled={!storageJson}
              onClick={handleCopy}
            >
              Copy JSON
            </Button>
            <Button
              size="sm"
              variant="outline"
              className="flex-1"
              disabled={!storageJson}
              onClick={handleDownloadStorage}
            >
              Download JSON
            </Button>
          </div>
        </div>

        <div>
          <h3 className="mb-1.5 text-xs font-semibold">
            Restore / reset (migration testing)
          </h3>
          <p className="text-muted-foreground mb-2 text-[11px]">
            Overwrite chrome.storage from a dump (e.g. a pre-migration
            snapshot), then reload and unlock to exercise the migration. Both
            actions replace current storage.
          </p>
          <label className="border-border hover:bg-muted/40 flex cursor-pointer items-center justify-between gap-2 rounded-md border p-2 text-xs transition-colors">
            <span className="text-muted-foreground truncate">
              {restoreName ?? "Choose a dump .json to restore…"}
            </span>
            <span className="text-foreground shrink-0 font-medium">Browse</span>
            <input
              type="file"
              accept="application/json,.json"
              className="hidden"
              disabled={busy}
              onChange={(e) => {
                void handleRestoreFile(e.target.files?.[0]);
                e.target.value = ""; // allow re-selecting the same file
              }}
            />
          </label>
          <Button
            size="sm"
            variant="destructive"
            className="mt-2 w-full"
            disabled={busy}
            onClick={() => void handleClearAll()}
          >
            Clear all storage (fresh install)
          </Button>
        </div>
      </div>
    </SubPage>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-3">
      <span className="text-muted-foreground">{label}</span>
      <span className="font-mono">{value}</span>
    </div>
  );
}
