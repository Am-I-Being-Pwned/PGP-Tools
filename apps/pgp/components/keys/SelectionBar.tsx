import { useEffect, useState } from "react";
import { CheckCheckIcon, DownloadIcon, Trash2Icon, XIcon } from "lucide-react";

import { cn } from "@amibeingpwned/ui";

import { t, tn } from "../../lib/i18n";

/** Must match the `duration-300` on the pill below. */
const ANIM_MS = 300;

interface SelectionBarProps {
  open: boolean;
  count: number;
  allSelected: boolean;
  onToggleAll: () => void;
  onExport: () => void;
  onDelete: () => void;
  onExit: () => void;
}

/** Floating island while bulk-selecting; stays mounted until its exit ends. */
export function SelectionBar({
  open,
  count,
  allSelected,
  onToggleAll,
  onExport,
  onDelete,
  onExit,
}: SelectionBarProps) {
  const [rendered, setRendered] = useState(open);
  const [entered, setEntered] = useState(false);
  // Hold the last count so it doesn't flash "0 selected" on exit.
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
    // Zero-height sticky wrapper: follows the scroll, takes no layout slot.
    <div className="pointer-events-none sticky top-2 z-40 flex h-0 items-start justify-center">
      <div
        role="toolbar"
        aria-label={t("keys_selection_actions_aria")}
        className={cn(
          "surface-float pointer-events-auto flex items-center gap-1.5 rounded-full px-2.5 py-2",
          "origin-top transition-all duration-300 ease-[cubic-bezier(0.34,1.56,0.64,1)]",
          entered
            ? "blur-0 translate-y-0 scale-100 opacity-100"
            : "-translate-y-2 scale-95 opacity-0 blur-[2px]",
        )}
      >
        <button
          type="button"
          onClick={onExit}
          aria-label={t("keys_cancel_selection_aria")}
          className="text-muted-foreground hover:text-foreground hover:bg-accent rounded-full p-2 transition-colors"
        >
          <XIcon className="h-4 w-4" />
        </button>
        <span className="px-1.5 text-sm font-medium whitespace-nowrap tabular-nums">
          {tn("keys_selected_count", shownCount)}
        </span>
        <button
          type="button"
          onClick={onToggleAll}
          aria-label={
            allSelected ? t("keys_deselect_all") : t("keys_select_all")
          }
          title={allSelected ? t("keys_deselect_all") : t("keys_select_all")}
          className={cn(
            "rounded-full p-2 transition-colors",
            allSelected
              ? "text-good hover:bg-on"
              : "text-muted-foreground hover:text-foreground hover:bg-accent",
          )}
        >
          <CheckCheckIcon className="h-4 w-4" />
        </button>
        <button
          type="button"
          onClick={onExport}
          disabled={shownCount === 0}
          className="hover:bg-accent flex items-center gap-1.5 rounded-full px-4 py-2 text-sm font-medium transition-colors disabled:opacity-50"
        >
          <DownloadIcon className="h-4 w-4" />
          {t("keys_export")}
        </button>
        <button
          type="button"
          onClick={onDelete}
          disabled={shownCount === 0}
          className="text-bad hover:bg-destructive/12 flex items-center gap-1.5 rounded-full px-4 py-2 text-sm font-medium transition-colors disabled:opacity-50"
        >
          <Trash2Icon className="h-4 w-4" />
          {t("common_delete")}
        </button>
      </div>
    </div>
  );
}
