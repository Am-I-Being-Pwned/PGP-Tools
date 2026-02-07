import { useCallback, useRef, useState } from "react";
import { FileIcon } from "lucide-react";

import { Button } from "@amibeingpwned/ui/button";

interface DropZoneProps {
  onTextDrop: (text: string) => void;
  onFileDrop: (files: File[]) => void;
  activeFiles: File[];
  onRemoveFile: (index: number) => void;
  onClearFiles: () => void;
}

export function DropZone({
  onTextDrop,
  onFileDrop,
  activeFiles,
  onRemoveFile,
  onClearFiles,
}: DropZoneProps) {
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback(() => {
    setDragOver(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);

      if (e.dataTransfer.files.length > 0) {
        onFileDrop(Array.from(e.dataTransfer.files));
        return;
      }

      const text = e.dataTransfer.getData("text/plain");
      if (text) {
        onTextDrop(text);
      }
    },
    [onTextDrop, onFileDrop],
  );

  const handleFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const selected = e.target.files;
      if (selected && selected.length > 0) onFileDrop(Array.from(selected));
      // Reset so the same file can be selected again
      e.target.value = "";
    },
    [onFileDrop],
  );

  return (
    <div
      className={`flex flex-col gap-2 ${activeFiles.length > 0 ? "min-h-0 flex-1" : ""}`}
    >
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`shrink-0 rounded-lg border-2 border-dashed p-5 text-center transition-colors ${
          dragOver
            ? "border-primary bg-primary/10"
            : "border-border hover:border-muted-foreground/50"
        }`}
      >
        <p className="text-muted-foreground mb-2 text-sm">
          Drop files or text here
        </p>
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          multiple
          onChange={handleFileSelect}
        />
        <Button
          variant="outline"
          size="sm"
          onClick={() => fileInputRef.current?.click()}
        >
          Browse files
        </Button>
      </div>

      {activeFiles.length > 0 && (
        <>
          <div className="min-h-0 flex-1 space-y-2 overflow-y-auto">
            {activeFiles.map((file, index) => (
              <div
                key={`${file.name}-${index}`}
                className="border-border bg-muted/30 flex items-center gap-3 rounded-lg border p-3"
              >
                <div className="bg-primary/10 text-primary flex h-9 w-9 shrink-0 items-center justify-center rounded-md">
                  <FileIcon size={18} />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium">{file.name}</p>
                  <p className="text-muted-foreground text-xs">
                    {formatFileSize(file.size)}
                  </p>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => onRemoveFile(index)}
                >
                  Remove
                </Button>
              </div>
            ))}
          </div>
          {activeFiles.length > 1 && (
            <Button
              variant="ghost"
              size="sm"
              className="w-full shrink-0"
              onClick={onClearFiles}
            >
              Clear all
            </Button>
          )}
        </>
      )}
    </div>
  );
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
