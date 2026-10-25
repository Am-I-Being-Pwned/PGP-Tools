import { useCallback, useRef, useState } from "react";
import { FileIcon } from "lucide-react";

import { cn } from "@amibeingpwned/ui";
import { Block, BlockStack } from "@amibeingpwned/ui/block";
import { Button } from "@amibeingpwned/ui/button";

import { t } from "../../lib/i18n";
import { formatFileSize } from "../../lib/utils/formatting";

interface DropZoneProps {
  onTextDrop: (text: string) => void;
  onFileDrop: (files: File[]) => void;
  activeFiles: File[];
  onRemoveFile: (index: number) => void;
  onClearFiles: () => void;
  /** False once the message box has text. The zone then takes no drops
   *  and offers neither Browse nor the file list -- exactly what it did
   *  when it was a separate box swapped out for "Clear text". */
  enabled: boolean;
  /** The message block(s), stacked above the file list and the strip. */
  children?: React.ReactNode;
  /** The right end of the bottom strip (the "Clear text" button). */
  trailing?: React.ReactNode;
  /** The card's top block (the To row). It is not part of the drop
   *  target -- a drop aimed at the recipient box is not a message -- and
   *  it comes AFTER the message in the DOM while drawing first, so Tab
   *  still goes message -> recipients, the order the keyboard flow was
   *  built around, ahead of the strip's Browse button. */
  header?: React.ReactNode;
  className?: string;
}

/**
 * The message card, which is also the drop target. It used to be a
 * dashed box above the message; now the card itself takes the drop, the
 * staged files sit in a block of their own above the bottom strip, and
 * Browse lives in that strip.
 *
 * A drop that lands ON the textarea is left to the browser, as it always
 * was: native insertion knows where the caret landed and how to undo.
 * (File drags never get here at all -- the app-wide overlay in
 * GlobalDropZone covers the panel while one is in progress.)
 */
export function DropZone({
  onTextDrop,
  onFileDrop,
  activeFiles,
  onRemoveFile,
  onClearFiles,
  enabled,
  children,
  trailing,
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
    // The card has children now; crossing from one to the next is not
    // leaving it, and dropping the highlight there makes it flicker.
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

  const showFiles = enabled && activeFiles.length > 0;

  return (
    <BlockStack
      onDragOver={enabled ? handleDragOver : undefined}
      onDragLeave={enabled ? handleDragLeave : undefined}
      onDrop={enabled ? handleDrop : undefined}
      className={cn(
        "min-h-0 flex-1 transition-shadow",
        enabled && dragOver && "ring-primary/60 ring-2",
        className,
      )}
    >
      {children}
      {header && (
        <Block
          data-drop-pass=""
          className="order-first shrink-0 focus-within:shadow-[inset_0_0_0_1px_rgb(79_193_133/0.35)]"
        >
          {header}
        </Block>
      )}

      {showFiles && (
        <Block className="min-h-0 flex-1 space-y-0.5 overflow-y-auto p-1.5">
          {activeFiles.map((file, index) => (
            <div
              key={`${file.name}-${index}`}
              className="flex items-center gap-3 rounded-md px-1.5 py-1.5"
            >
              <div className="bg-secondary text-muted-foreground flex h-8 w-8 shrink-0 items-center justify-center rounded-md">
                <FileIcon size={16} />
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
                className="text-muted-foreground"
                onClick={() => onRemoveFile(index)}
              >
                {t("common_remove")}
              </Button>
            </div>
          ))}
        </Block>
      )}

      <Block className="flex shrink-0 items-center gap-1 px-1.5 py-1">
        {enabled && (
          <>
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              multiple
              onChange={handleFileSelect}
            />
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

/** Inside the card's header block, which takes no drops of its own. */
function inHeader(target: EventTarget): boolean {
  return (
    target instanceof Element && target.closest("[data-drop-pass]") !== null
  );
}
