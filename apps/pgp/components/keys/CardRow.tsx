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

/** Hover fires off the CARD's hover, so pointer-events-none alone
 *  wouldn't stop it. */
export const DIMMED = "pointer-events-none opacity-40";

const PILL_TONE = {
  neutral: "bg-secondary text-muted-foreground",
  good: "bg-good/12 text-good",
  warn: "bg-warn/12 text-warn",
  bad: "bg-destructive/12 text-bad",
} as const;

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
  onStartSelect?: () => void;
  onShowDetails?: () => void;
  justImported?: boolean;
  className?: string;
  children: ReactNode;
}

/** One keys-list row, shared by own keys and contacts. */
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
    if (longPress.consumeClick()) return;
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
        "group bg-card relative rounded-[3px] py-2.5 pr-2 pl-3.5 transition-colors select-none",
        className,
        importedClass,
        importedClass && "z-10",
        selected && "ring-primary/70 ring-2 ring-inset",
        clickable && "hover:bg-accent/50 cursor-pointer",
      )}
    >
      {children}
    </div>
  );
}

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
      {/* Portalled, but React events still bubble: stop the row's onClick. */}
      <DropdownMenuContent align="end" onClick={(e) => e.stopPropagation()}>
        {children}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

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
