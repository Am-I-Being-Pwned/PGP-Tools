import { useCallback, useRef, useState } from "react";

import { Button } from "@amibeingpwned/ui/button";

import type { PublicContactKey } from "../../lib/storage/contacts";
import { parsePublicKey } from "../../lib/pgp/key-management";

interface ContactDropZoneProps {
  onImport: (contact: PublicContactKey) => Promise<void>;
}

export function ContactDropZone({ onImport }: ContactDropZoneProps) {
  const [dragOver, setDragOver] = useState(false);
  const [status, setStatus] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const tryImport = useCallback(
    async (text: string) => {
      setStatus(null);
      const trimmed = text.trim();
      if (!trimmed.includes("PUBLIC KEY")) {
        setStatus({ type: "error", message: "Not a public key" });
        return;
      }
      try {
        const keyInfo = await parsePublicKey(trimmed);
        await onImport({
          keyId: keyInfo.keyId,
          userIds: keyInfo.userIds,
          algorithm: keyInfo.algorithm,
          armoredPublicKey: trimmed,
          addedAt: Date.now(),
          lastUsedAt: Date.now(),
        });
        setStatus({
          type: "success",
          message: `Added ${keyInfo.userIds[0] ?? keyInfo.keyId.slice(-16)}`,
        });
        setTimeout(() => setStatus(null), 3000);
      } catch (e) {
        setStatus({
          type: "error",
          message: e instanceof Error ? e.message : "Invalid key",
        });
      }
    },
    [onImport],
  );

  const handleDrop = useCallback(
    async (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);

      if (e.dataTransfer.files.length > 0) {
        const text = await e.dataTransfer.files[0].text();
        await tryImport(text);
        return;
      }

      const text = e.dataTransfer.getData("text/plain");
      if (text) await tryImport(text);
    },
    [tryImport],
  );

  const handlePaste = useCallback(
    (e: React.ClipboardEvent) => {
      const text = e.clipboardData.getData("text/plain");
      if (text.includes("PUBLIC KEY")) {
        e.preventDefault();
        void tryImport(text);
      }
    },
    [tryImport],
  );

  const handleFileSelect = useCallback(
    async (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) {
        const text = await file.text();
        await tryImport(text);
      }
      e.target.value = "";
    },
    [tryImport],
  );

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
      onPaste={handlePaste}
      tabIndex={0}
      className={`rounded-md border-2 border-dashed p-3 text-center text-xs transition-colors focus:outline-none ${
        dragOver
          ? "border-primary bg-primary/10"
          : "border-border hover:border-muted-foreground/50"
      }`}
    >
      {status ? (
        <p
          className={
            status.type === "success" ? "text-green-400" : "text-destructive"
          }
        >
          {status.message}
        </p>
      ) : (
        <>
          <p className="text-muted-foreground">
            Drop, paste, or browse for a public key
          </p>
          <input
            ref={fileInputRef}
            type="file"
            accept=".asc,.gpg,.pub,.key,.pgp,.txt"
            className="hidden"
            onChange={handleFileSelect}
          />
          <Button
            variant="outline"
            size="sm"
            className="mt-2"
            onClick={() => fileInputRef.current?.click()}
          >
            Browse files
          </Button>
        </>
      )}
    </div>
  );
}
