import type { MouseEvent as ReactMouseEvent, ReactNode } from "react";
import { ChevronRightIcon, EllipsisVerticalIcon } from "lucide-react";

import { cn } from "@amibeingpwned/ui";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@amibeingpwned/ui/dropdown-menu";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@amibeingpwned/ui/tooltip";

import { t } from "../../lib/i18n";
import { useJustImported } from "./useJustImported";
import { useLongPress } from "./useLongPress";

/** While selecting, the card is the target: its own controls go dim and
 *  click-through, and drop their hover (which fires off the CARD's hover,
 *  so pointer-events-none alone wouldn't stop it). */
export const DIMMED = "pointer-events-none opacity-40";

const PILL_TONE = {
  neutral: "bg-secondary text-muted-foreground",
  good: "bg-good/12 text-good",
  warn: "bg-warn/12 text-warn",
  bad: "bg-destructive/12 text-bad",
} as const;

/** The design language's status pill. */
export function Pill({
  tone = "neutral",
  icon,
  title,
  children,
}: {
  tone?: keyof typeof PILL_TONE;
  icon?: ReactNode;
  title?: string;
  children: ReactNode;
}) {
  return (
    <span
      title={title}
      className={cn(
        "shrink-0 items-center rounded px-1.5 py-px text-[10.5px] font-medium whitespace-nowrap",
        PILL_TONE[tone],
        icon && "inline-flex gap-1",
      )}
    >
      {icon}
      {children}
    </span>
  );
}

interface CardRowProps {
  selectionMode: boolean;
  selected: boolean;
  onToggleSelect?: (extend: boolean) => void;
  /** Long-press / menu entry into selection mode. */
  onStartSelect?: () => void;
  onShowDetails?: () => void;
  justImported?: boolean;
  /** Background and corner overrides (a tinted signer band, say). */
  className?: string;
  children: ReactNode;
}

/**
 * One compact row of a keys-list stack, shared by own keys and contacts
 * so the two read as one list: click opens details (or toggles while
 * selecting, shift extends), long-press starts selecting, and a fresh
 * import pulses it.
 */
export function CardRow({
  selectionMode,
  selected,
  onToggleSelect,
  onStartSelect,
  onShowDetails,
  justImported,
  className,
  children,
}: CardRowProps) {
  const [importedRef, importedClass] = useJustImported(justImported);
  const longPress = useLongPress(
    () => onStartSelect?.(),
    !selectionMode && !!onStartSelect,
  );

  const handleClick = (e: ReactMouseEvent) => {
    if (longPress.consumeClick()) return; // the click ending a long-press
    if (selectionMode) {
      onToggleSelect?.(e.shiftKey);
      return;
    }
    onShowDetails?.();
  };

  const clickable = selectionMode || !!onShowDetails;
  return (
    <div
      ref={importedRef}
      onClick={handleClick}
      {...longPress.handlers}
      className={cn(
        // select-none: a shift-click would otherwise drag a text range.
        "group bg-card relative rounded-[3px] py-2.5 pr-2 pl-3.5 transition-colors select-none",
        className,
        importedClass,
        // The pulse is an outward ring: lift it over the 2px gap.
        importedClass && "z-10",
        // Inset: selecting must not shift the row or spill into the gap.
        selected && "ring-primary/70 ring-2 ring-inset",
        clickable && "hover:bg-accent/50 cursor-pointer",
      )}
    >
      {children}
    </div>
  );
}

/** The last 16 hex digits of a fingerprint, as two stacked lines. */
export function LongIdColumn({ lines }: { lines: [string, string] }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="text-muted-foreground shrink-0 font-mono text-[11px] leading-tight whitespace-nowrap">
          <span className="block">{lines[0]}</span>
          <span className="block">{lines[1]}</span>
        </span>
      </TooltipTrigger>
      <TooltipContent>{t("keys_contact_long_id_title")}</TooltipContent>
    </Tooltip>
  );
}

/** The row's ⋮ menu. */
export function CardMenu({
  ariaLabel,
  selectionMode,
  children,
}: {
  ariaLabel: string;
  selectionMode: boolean;
  children: ReactNode;
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button
          onClick={(e) => e.stopPropagation()}
          onPointerDown={(e) => e.stopPropagation()}
          className={cn(
            "text-muted-foreground rounded p-1 transition-colors",
            selectionMode ? DIMMED : "hover:text-foreground",
          )}
          aria-label={ariaLabel}
        >
          <EllipsisVerticalIcon className="h-4 w-4" />
        </button>
      </DropdownMenuTrigger>
      {/* Portalled, but React events still bubble through the component
          tree: without this a menu click also fires the row's onClick. */}
      <DropdownMenuContent align="end" onClick={(e) => e.stopPropagation()}>
        {children}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** The row opens details too; this is the visible, keyboard-reachable
 *  target for the same action. */
export function DetailsChevron({
  onClick,
  selectionMode,
}: {
  onClick: () => void;
  selectionMode: boolean;
}) {
  return (
    <button
      type="button"
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      aria-label={t("keys_key_details")}
      className={cn(
        "text-muted-foreground -ml-1 shrink-0 rounded p-0.5 transition-colors",
        selectionMode ? DIMMED : "group-hover:text-foreground",
      )}
    >
      <ChevronRightIcon className="h-4 w-4" />
    </button>
  );
}
