/* i18n-ignore-file */
import { useEffect, useState } from "react";

import { Button } from "@amibeingpwned/ui";

import { SubPage } from "~/components/shared/SubPage";
import { engineMessage, useAsyncAction, useCopyToClipboard } from "~/hooks";
import {
  clearAllStorage,
  dumpAllStorage,
  isStorageDump,
  restoreAllStorage,
} from "~/lib/dev/dump";
import { hasContactsSession, ping } from "~/lib/pgp/wasm";
import { dumpWasmMemoryForDev } from "~/lib/pgp/wasm-loader";
import { toast } from "~/lib/toast";
import { downloadBinary, downloadText } from "~/lib/utils/download";
import { formatFileSize } from "~/lib/utils/formatting";

interface WasmInfo {
  pong: string;
  sessionActive: boolean;
  memoryBytes: number | null;
}

export function DevToolsPage({ onClose }: { onClose: () => void }) {
  const [storageJson, setStorageJson] = useState<string | null>(null);
  const [wasm, setWasm] = useState<WasmInfo | null>(null);
  const [restoreName, setRestoreName] = useState<string | null>(null);
  const loader = useAsyncAction(engineMessage("Dev dump failed"));
  const writer = useAsyncAction(engineMessage("Storage write failed"));
  const loading = loader.busy;
  const busy = writer.busy;
  const { copy } = useCopyToClipboard();

  const load = async () => {
    const [dump, pong, sessionActive] = await Promise.all([
      dumpAllStorage(),
      ping(),
      hasContactsSession(),
    ]);
    setStorageJson(JSON.stringify(dump, null, 2));
    // Size only; the download button re-reads the bytes.
    setWasm({
      pong,
      sessionActive,
      memoryBytes: dumpWasmMemoryForDev()?.byteLength ?? null,
    });
  };

  // Stable toast ids: a retried failure updates in place.
  const refresh = async () => {
    const error = await loader.run(load);
    if (error) toast.error(error.message, { id: "dev-dump-failed" });
  };

  useEffect(() => {
    void refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- load once on open
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
    const error = await writer.run(async () => {
      setRestoreName(file.name);
      const parsed: unknown = JSON.parse(await file.text());
      if (!isStorageDump(parsed)) {
        toast.error("Not a storage dump ({ local, sync, session }).", {
          id: "dev-restore-failed",
        });
        return;
      }
      await restoreAllStorage(parsed);
      await refresh();
      toast.success("Storage restored. Reload the panel to apply", {
        id: "dev-restored",
      });
    });
    if (error) toast.error(error.message, { id: "dev-restore-failed" });
  };

  const handleClearAll = async () => {
    const error = await writer.run(async () => {
      await clearAllStorage();
      await refresh();
      toast.success("Storage cleared. Reload the panel to apply", {
        id: "dev-cleared",
      });
    });
    if (error) toast.error(error.message, { id: "dev-clear-failed" });
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
          <div className="bg-card space-y-1 rounded-xl p-3 text-xs">
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
          <pre className="surface-field max-h-64 overflow-auto rounded-lg p-2 font-mono text-[10px] leading-relaxed">
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
          <label className="bg-card hover:bg-accent flex cursor-pointer items-center justify-between gap-2 rounded-xl px-3 py-2.5 text-xs transition-colors">
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
