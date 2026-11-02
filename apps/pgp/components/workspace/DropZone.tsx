import { useCallback, useRef, useState } from "react";
import { FileIcon, PaperclipIcon } from "lucide-react";

import { Block, BlockStack, Button, cn } from "@amibeingpwned/ui";

import { MarkedText } from "~/components/shared/MarkedText";
import { t } from "~/lib/i18n";
import { displayFileName } from "~/lib/utils/file-name";
import { formatFileSize } from "~/lib/utils/formatting";

interface DropZoneProps {
  onTextDrop: (text: string) => void;
  onFileDrop: (files: File[]) => void;
  activeFiles: File[];
  onRemoveFile: (index: number) => void;
  onClearFiles: () => void;
  /** False once the message box has text: no drops, no Browse, no file list. */
  enabled: boolean;
  /** Off once the box has text: a text drop would clobber the written message. */
  acceptTextDrop?: boolean;
  children?: React.ReactNode;
  trailing?: React.ReactNode;
  leading?: React.ReactNode;
  /** To/From rows. Not a drop target: a drop on the recipient box is not a message. */
  header?: React.ReactNode;
  className?: string;
}

/**
 * The message card, which is also the drop target. Drops ON the textarea
 * are left to the browser (native caret placement + undo); file drags are
 * caught earlier by GlobalDropZone's overlay.
 */
export function DropZone({
  onTextDrop,
  onFileDrop,
  activeFiles,
  onRemoveFile,
  onClearFiles,
  enabled,
  acceptTextDrop = true,
  children,
  trailing,
  leading,
  header,
  className,
}: DropZoneProps) {
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    if (e.target instanceof HTMLTextAreaElement || inHeader(e.target)) return;
    e.preventDefault();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    // Crossing between children is not leaving (avoids highlight flicker).
    if (
      e.relatedTarget instanceof Node &&
      e.currentTarget.contains(e.relatedTarget)
    )
      return;
    setDragOver(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      setDragOver(false);
      if (e.target instanceof HTMLTextAreaElement || inHeader(e.target)) return;
      e.preventDefault();

      if (e.dataTransfer.files.length > 0) {
        onFileDrop(Array.from(e.dataTransfer.files));
        return;
      }

      const text = e.dataTransfer.getData("text/plain");
      if (text && acceptTextDrop) {
        onTextDrop(text);
      }
    },
    [onTextDrop, onFileDrop, acceptTextDrop],
  );

  const handleFileSelect = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const selected = e.target.files;
      if (selected && selected.length > 0) onFileDrop(Array.from(selected));
      e.target.value = "";
    },
    [onFileDrop],
  );

  const showFiles = enabled && activeFiles.length > 0;
  const filesBeside = children !== undefined && children !== false;

  return (
    <BlockStack
      // Focus target after a clear (`focusFlowStart` in WorkspaceView).
      data-workspace-card=""
      onDragOver={enabled ? handleDragOver : undefined}
      onDragLeave={enabled ? handleDragLeave : undefined}
      onDrop={enabled ? handleDrop : undefined}
      className={cn(
        "min-h-0 flex-1 transition-shadow",
        enabled && dragOver && "ring-primary/60 ring-2",
        className,
      )}
    >
      {header && (
        <div data-drop-pass="" className="flex shrink-0 flex-col gap-0.5">
          {header}
        </div>
      )}
      {children}

      {showFiles && (
        <Block
          // First anchor in the page wins (see ToastHost).
          data-toast-anchor={filesBeside ? "" : undefined}
          className={cn(
            "min-h-0 space-y-0.5 overflow-y-auto p-1.5",
            filesBeside ? "max-h-36 shrink-0" : "flex-1",
          )}
        >
          {activeFiles.map((file, index) => (
            <div
              key={`${file.name}-${index}`}
              className="flex items-center gap-3 rounded-md px-1.5 py-1.5"
            >
              <div className="bg-secondary text-muted-foreground flex h-8 w-8 shrink-0 items-center justify-center rounded-md">
                <FileIcon size={16} />
              </div>
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">
                  <MarkedText text={displayFileName(file.name)} />
                </p>
                <p className="text-muted-foreground text-xs">
                  {formatFileSize(file.size)}
                </p>
              </div>
              <Button
                variant="ghost"
                size="sm"
                className="text-muted-foreground"
                onClick={() => onRemoveFile(index)}
              >
                {t("common_remove")}
              </Button>
            </div>
          ))}
        </Block>
      )}

      <Block
        data-toast-anchor=""
        className="flex shrink-0 items-center gap-1 px-1.5 py-1"
      >
        {leading}
        {enabled && (
          <>
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              multiple
              onChange={handleFileSelect}
            />
            {leading ? (
              <button
                type="button"
                aria-label={t("workspace_browse_files")}
                title={t("workspace_browse_files")}
                onClick={() => fileInputRef.current?.click()}
                className="text-muted-foreground hover:text-foreground hover:bg-accent flex h-7 w-7 shrink-0 items-center justify-center rounded transition-colors"
              >
                <PaperclipIcon className="h-3.5 w-3.5" />
              </button>
            ) : (
              <>
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-muted-foreground hover:text-foreground h-7 px-2"
                  onClick={() => fileInputRef.current?.click()}
                >
                  {t("workspace_browse_files")}
                </Button>
                <p
                  className={cn(
                    "min-w-0 flex-1 truncate px-1 text-xs transition-colors",
                    dragOver ? "text-primary" : "text-muted-foreground",
                  )}
                >
                  {t("workspace_drop_files_or_text")}
                </p>
              </>
            )}
            {activeFiles.length > 1 && (
              <Button
                variant="ghost"
                size="sm"
                className="text-muted-foreground hover:text-foreground h-7 shrink-0 px-2"
                onClick={onClearFiles}
              >
                {t("workspace_clear_all_files")}
              </Button>
            )}
          </>
        )}
        {trailing && <div className="ml-auto flex shrink-0">{trailing}</div>}
      </Block>
    </BlockStack>
  );
}

function inHeader(target: EventTarget): boolean {
  return (
    target instanceof Element && target.closest("[data-drop-pass]") !== null
  );
}
