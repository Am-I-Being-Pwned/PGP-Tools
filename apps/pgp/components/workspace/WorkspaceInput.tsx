import { useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "@amibeingpwned/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@amibeingpwned/ui/select";

import type { WorkspaceAction } from "../../lib/messages";
import { DropZone } from "./DropZone";

type Mode = WorkspaceAction;

interface WorkspaceInputProps {
  mode: Mode;
  onModeChange: (mode: Mode) => void;
  input: string;
  onInputChange: (text: string) => void;
  files: File[];
  onFileDrop: (files: File[]) => void;
  onRemoveFile: (index: number) => void;
  onClearFiles: () => void;
  publicKeyDetected: boolean;
  privateKeyDetected: boolean;
  onNavigateToKeys?: (importPrefill?: string) => void;
  operationDone: boolean;
  onReset: () => void;
  onResetOutput: () => void;
}

export function WorkspaceInput({
  mode,
  onModeChange,
  input,
  onInputChange,
  files,
  onFileDrop,
  onRemoveFile,
  onClearFiles,
  publicKeyDetected,
  privateKeyDetected,
  onNavigateToKeys,
  operationDone,
  onReset,
  onResetOutput,
}: WorkspaceInputProps) {
  // Per-detection mask override. Re-arms whenever a fresh private-key
  // paste is detected so the user can't accidentally leave the mask off
  // across two separate pastes.
  const [maskIgnored, setMaskIgnored] = useState(false);
  useEffect(() => {
    if (privateKeyDetected) setMaskIgnored(false);
  }, [privateKeyDetected]);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3">
      <Select
        value={mode}
        onValueChange={(v) => {
          onModeChange(v as Mode);
          if (operationDone) onReset();
          else onResetOutput();
        }}
      >
        <SelectTrigger>
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem
            className="cursor-pointer focus:bg-border/70"
            value="encrypt"
          >
            Encrypt
          </SelectItem>
          <SelectItem
            className="cursor-pointer focus:bg-border/70"
            value="decrypt"
          >
            Decrypt
          </SelectItem>
          <SelectItem className="cursor-pointer focus:bg-border/70" value="sign">
            Sign
          </SelectItem>
          <SelectItem
            className="cursor-pointer focus:bg-border/70"
            value="verify"
          >
            Verify
          </SelectItem>
        </SelectContent>
      </Select>

      {input.length > 0 ? (
        <div className="border-border shrink-0 rounded-lg border-2 border-dashed p-5 text-center">
          <p className="text-muted-foreground mb-2 text-sm">
            Text entered below
          </p>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              const prev = input;
              onInputChange("");
              if (!operationDone) {
                toast("Text cleared", {
                  duration: 4000,
                  action: {
                    label: "Undo",
                    onClick: () => onInputChange(prev),
                  },
                });
              }
            }}
          >
            Clear text
          </Button>
        </div>
      ) : (
        <DropZone
          onTextDrop={onInputChange}
          onFileDrop={onFileDrop}
          activeFiles={files}
          onRemoveFile={onRemoveFile}
          onClearFiles={onClearFiles}
        />
      )}

      {files.length === 0 && (
        <textarea
          id="pgp-input"
          aria-label="Message input"
          value={input}
          onChange={(e) => onInputChange(e.target.value)}
          className="border-border bg-background placeholder:text-muted-foreground focus:ring-ring min-h-20 w-full flex-1 resize-none rounded-md border p-3 text-sm focus:ring-2 focus:outline-none"
          // Visually mask armored private-key material. NOTE: this is
          // shoulder-surfing protection only; the string still lives in
          // V8's heap until GC. The privateKeyDetected flag elsewhere
          // also blocks draft-snapshotting this content.
          style={
            privateKeyDetected && !maskIgnored
              ? ({ WebkitTextSecurity: "disc" } as React.CSSProperties)
              : undefined
          }
          placeholder={
            mode === "decrypt"
              ? "Paste the encrypted message you received..."
              : mode === "verify"
                ? "Paste the signed message to check..."
                : "Type or paste your message..."
          }
        />
      )}

      {privateKeyDetected && (
        <div
          role="alert"
          className="border-destructive bg-destructive/10 text-destructive space-y-2 rounded-md border px-3 py-2 text-xs"
        >
          <div className="flex items-start justify-between gap-2">
            <p className="font-semibold">
              This looks like a private key. Don't paste private keys here.
            </p>
            {!maskIgnored && (
              <button
                onClick={() => setMaskIgnored(true)}
                className="border-destructive/40 hover:bg-destructive/20 shrink-0 rounded border px-2 py-0.5 text-[10px] font-medium tracking-wide uppercase"
                title="Show the pasted text in cleartext"
              >
                Ignore
              </button>
            )}
          </div>
          <p>
            The Encrypt/Decrypt box isn't a safe place for secret key material.
            Use the Import flow so the key is loaded into the secure store and
            kept out of any draft snapshots.
          </p>
          <div className="flex gap-2 pt-1">
            <button
              onClick={() => onNavigateToKeys?.(input)}
              className="border-destructive/40 hover:bg-destructive/20 rounded border px-2 py-1 font-medium"
            >
              Import this key safely
            </button>
            <button
              onClick={() => onInputChange("")}
              className="border-destructive/40 hover:bg-destructive/20 rounded border px-2 py-1 font-medium"
            >
              Clear input
            </button>
          </div>
        </div>
      )}

      {publicKeyDetected && (
        <div className="rounded-md bg-blue-500/10 px-3 py-2 text-xs text-blue-400">
          This looks like someone's public key.{" "}
          <button
            onClick={() => onNavigateToKeys?.(input)}
            className="underline"
          >
            Import it as a contact
          </button>
        </div>
      )}
    </div>
  );
}
