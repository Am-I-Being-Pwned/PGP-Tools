import { useEffect, useState } from "react";
import { DownloadIcon, Trash2Icon, XIcon } from "lucide-react";

import { cn } from "@amibeingpwned/ui";

interface SelectionBarProps {
  count: number;
  onExport: () => void;
  onDelete: () => void;
  onExit: () => void;
}

/**
 * Floating "magic island" that appears while bulk-selecting keys/contacts.
 * Sticks to the top of the scrolling list and offers the two bulk actions
 * (Export, Delete) plus an exit. Rendered only while selection mode is active;
 * animates in on mount.
 */
export function SelectionBar({
  count,
  onExport,
  onDelete,
  onExit,
}: SelectionBarProps) {
  const [entered, setEntered] = useState(false);
  useEffect(() => {
    const raf = requestAnimationFrame(() => setEntered(true));
    return () => cancelAnimationFrame(raf);
  }, []);

  return (
    <div className="pointer-events-none sticky top-0 z-40 flex justify-center">
      <div
        role="toolbar"
        aria-label="Selection actions"
        className={cn(
          "bg-background/95 border-border pointer-events-auto flex items-center gap-1 rounded-full border px-1.5 py-1 shadow-lg backdrop-blur transition-all duration-200 ease-out",
          entered ? "translate-y-0 opacity-100" : "-translate-y-2 opacity-0",
        )}
      >
        <button
          type="button"
          onClick={onExit}
          aria-label="Cancel selection"
          className="text-muted-foreground hover:text-foreground hover:bg-muted/60 rounded-full p-1.5 transition-colors"
        >
          <XIcon className="h-4 w-4" />
        </button>
        <span className="px-1 text-xs font-medium whitespace-nowrap tabular-nums">
          {count} selected
        </span>
        <button
          type="button"
          onClick={onExport}
          disabled={count === 0}
          className="hover:bg-muted/60 flex items-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50"
        >
          <DownloadIcon className="h-3.5 w-3.5" />
          Export
        </button>
        <button
          type="button"
          onClick={onDelete}
          disabled={count === 0}
          className="text-destructive hover:bg-destructive/10 flex items-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50"
        >
          <Trash2Icon className="h-3.5 w-3.5" />
          Delete
        </button>
      </div>
    </div>
  );
}
