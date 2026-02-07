import { toast } from "sonner";

import { Button } from "@amibeingpwned/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@amibeingpwned/ui/select";

import { DropZone } from "./DropZone";

type Mode = "encrypt" | "decrypt" | "sign" | "verify";

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
  onNavigateToKeys?: () => void;
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
  onNavigateToKeys,
  operationDone,
  onReset,
  onResetOutput,
}: WorkspaceInputProps) {
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
          <SelectItem value="encrypt">Encrypt</SelectItem>
          <SelectItem value="decrypt">Decrypt</SelectItem>
          <SelectItem value="sign">Sign</SelectItem>
          <SelectItem value="verify">Verify</SelectItem>
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
          placeholder={
            mode === "decrypt"
              ? "Paste the encrypted message you received..."
              : mode === "verify"
                ? "Paste the signed message to check..."
                : "Type or paste your message..."
          }
        />
      )}

      {publicKeyDetected && (
        <div className="rounded-md bg-blue-500/10 px-3 py-2 text-xs text-blue-400">
          This looks like someone's public key.{" "}
          <button onClick={() => onNavigateToKeys?.()} className="underline">
            Go to Keys to import it as a contact
          </button>
        </div>
      )}
    </div>
  );
}
