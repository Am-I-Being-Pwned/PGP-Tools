import { useEffect, useState } from "react";
import { CheckCheckIcon, DownloadIcon, Trash2Icon, XIcon } from "lucide-react";

import { cn } from "@amibeingpwned/ui";

/** Must match the `duration-300` on the pill below. */
const ANIM_MS = 300;

interface SelectionBarProps {
  /** Drives the enter/exit animation; the bar stays mounted until exit ends. */
  open: boolean;
  count: number;
  /** Whether every selectable card is currently selected. */
  allSelected: boolean;
  /** Select every card, or (when all are selected) clear the selection. */
  onToggleAll: () => void;
  onExport: () => void;
  onDelete: () => void;
  onExit: () => void;
}

/**
 * Floating "magic island" shown while bulk-selecting keys/contacts. Pinned via a
 * zero-height sticky wrapper so it follows the list as it scrolls yet floats
 * over the content without taking a layout slot. Animates both in and out:
 * `open` toggles the enter/exit transition and the bar stays mounted until the
 * exit finishes.
 */
export function SelectionBar({
  open,
  count,
  allSelected,
  onToggleAll,
  onExport,
  onDelete,
  onExit,
}: SelectionBarProps) {
  // `rendered` keeps the node mounted across the exit animation; `entered`
  // drives the transform/opacity.
  const [rendered, setRendered] = useState(open);
  const [entered, setEntered] = useState(false);
  // Hold the last count so it doesn't flash "0 selected" as it animates out
  // (exiting clears the selection at the same moment).
  const [shownCount, setShownCount] = useState(count);

  useEffect(() => {
    if (open) setShownCount(count);
  }, [open, count]);

  useEffect(() => {
    if (open) {
      setRendered(true);
      const raf = requestAnimationFrame(() => setEntered(true));
      return () => cancelAnimationFrame(raf);
    }
    setEntered(false);
    const t = setTimeout(() => setRendered(false), ANIM_MS);
    return () => clearTimeout(t);
  }, [open]);

  if (!rendered) return null;

  return (
    // Zero-height sticky wrapper: pins to the top of the scroll area (following
    // as the list scrolls) but consumes no vertical space, so the pill overlays
    // the content instead of pushing it down.
    <div className="pointer-events-none sticky top-2 z-40 flex h-0 items-start justify-center">
      <div
        role="toolbar"
        aria-label="Selection actions"
        className={cn(
          "bg-background/95 border-border pointer-events-auto flex items-center gap-1.5 rounded-full border px-2.5 py-2 shadow-xl backdrop-blur",
          // Dynamic-island feel, matching the reference's computed styles: the
          // content sharpens from a soft 2px blur + fade while springing down
          // out of the top edge, overshooting past size and settling (the iOS
          // island's signature) rather than just sliding in.
          "origin-top transition-all duration-300 ease-[cubic-bezier(0.34,1.56,0.64,1)]",
          entered
            ? "blur-0 translate-y-0 scale-100 opacity-100"
            : "-translate-y-2 scale-95 opacity-0 blur-[2px]",
        )}
      >
        <button
          type="button"
          onClick={onExit}
          aria-label="Cancel selection"
          className="text-muted-foreground hover:text-foreground hover:bg-muted/60 rounded-full p-2 transition-colors"
        >
          <XIcon className="h-4 w-4" />
        </button>
        <span className="px-1.5 text-sm font-medium whitespace-nowrap tabular-nums">
          {shownCount} selected
        </span>
        <button
          type="button"
          onClick={onToggleAll}
          aria-label={allSelected ? "Deselect all" : "Select all"}
          title={allSelected ? "Deselect all" : "Select all"}
          className={cn(
            "rounded-full p-2 transition-colors",
            allSelected
              ? "text-green-500 hover:bg-green-500/10"
              : "text-muted-foreground hover:text-foreground hover:bg-muted/60",
          )}
        >
          <CheckCheckIcon className="h-4 w-4" />
        </button>
        <button
          type="button"
          onClick={onExport}
          disabled={shownCount === 0}
          className="hover:bg-muted/60 flex items-center gap-1.5 rounded-full px-4 py-2 text-sm font-medium transition-colors disabled:opacity-50"
        >
          <DownloadIcon className="h-4 w-4" />
          Export
        </button>
        <button
          type="button"
          onClick={onDelete}
          disabled={shownCount === 0}
          className="text-destructive hover:bg-destructive/10 flex items-center gap-1.5 rounded-full px-4 py-2 text-sm font-medium transition-colors disabled:opacity-50"
        >
          <Trash2Icon className="h-4 w-4" />
          Delete
        </button>
      </div>
    </div>
  );
}
