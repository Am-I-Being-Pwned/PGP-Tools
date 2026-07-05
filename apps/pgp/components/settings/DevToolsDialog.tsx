import { useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "@amibeingpwned/ui/button";

import { dumpAllStorage } from "../../lib/dev/dump";
import { hasContactsSession, ping } from "../../lib/pgp/wasm";
import { dumpWasmMemoryForDev } from "../../lib/pgp/wasm-loader";
import { downloadBinary, downloadText } from "../../lib/utils/download";
import { formatFileSize } from "../../lib/utils/formatting";
import { Dialog } from "../shared/Dialog";

interface WasmInfo {
  pong: string;
  sessionActive: boolean;
  memoryBytes: number | null;
}

export function DevToolsDialog({
  open,
  onClose,
}: {
  open: boolean;
  onClose: () => void;
}) {
  const [storageJson, setStorageJson] = useState<string | null>(null);
  const [wasm, setWasm] = useState<WasmInfo | null>(null);
  const [loading, setLoading] = useState(false);

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
      toast.error(e instanceof Error ? e.message : "Dev dump failed");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (open) void refresh();
    else {
      setStorageJson(null);
      setWasm(null);
    }
  }, [open]);

  const stamp = () =>
    new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);

  const handleCopy = () => {
    if (!storageJson) return;
    void navigator.clipboard.writeText(storageJson);
    toast.success("Storage JSON copied");
  };

  const handleDownloadStorage = () => {
    if (!storageJson) return;
    downloadText(storageJson, `pgp-storage-${stamp()}.json`);
  };

  const handleDownloadMemory = () => {
    const bytes = dumpWasmMemoryForDev();
    if (!bytes) {
      toast.error("WASM memory unavailable");
      return;
    }
    downloadBinary(bytes, `pgp-wasm-memory-${stamp()}.bin`);
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Developer tools"
      className="mx-4 max-h-[85vh] w-full max-w-md overflow-y-auto"
    >
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
      </div>
    </Dialog>
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
