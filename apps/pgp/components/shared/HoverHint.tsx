import { useState, type ReactElement } from "react";

import {
  Kbd,
  Popover,
  PopoverAnchor,
  PopoverContent,
  type ShortcutSpec,
} from "@amibeingpwned/ui";

/** A label and/or keyboard shortcut over its child on hover and focus
 *  (the kit has no tooltip; Popover is the house idiom). The child is the
 *  anchor; its own handlers are untouched. */
export function HoverHint({
  label,
  shortcut,
  align = "center",
  children,
}: {
  label?: string;
  shortcut?: ShortcutSpec;
  align?: "start" | "center" | "end";
  children: ReactElement;
}) {
  const [open, setOpen] = useState(false);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverAnchor
        asChild
        onPointerEnter={() => setOpen(true)}
        onPointerLeave={() => setOpen(false)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
      >
        {children}
      </PopoverAnchor>
      <PopoverContent
        side="top"
        align={align}
        className={
          label
            ? "pointer-events-none flex w-auto flex-col items-center gap-2 px-2 py-1.5 text-xs"
            : "pointer-events-none w-auto px-2 py-1.5"
        }
        onOpenAutoFocus={(e) => e.preventDefault()}
      >
        {label}
        {shortcut && (
          <Kbd
            shortcut={shortcut}
            className={label ? "text-muted-foreground" : undefined}
          />
        )}
      </PopoverContent>
    </Popover>
  );
}
