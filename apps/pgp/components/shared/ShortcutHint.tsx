import type { ReactElement } from "react";
import { useState } from "react";

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";
import { Kbd } from "@amibeingpwned/ui/kbd";
import {
  Popover,
  PopoverAnchor,
  PopoverContent,
} from "@amibeingpwned/ui/popover";

/** A button's keyboard shortcut as keycaps, on hover and focus. The child
 *  (one Button) is the anchor; its own onClick is untouched. */
export function ShortcutHint({
  shortcut,
  children,
}: {
  shortcut: ShortcutSpec;
  children: ReactElement;
}) {
  const [open, setOpen] = useState(false);
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverAnchor
        asChild
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        onFocus={() => setOpen(true)}
        onBlur={() => setOpen(false)}
      >
        {children}
      </PopoverAnchor>
      <PopoverContent
        side="top"
        className="pointer-events-none w-auto px-2 py-1.5"
        onOpenAutoFocus={(e) => e.preventDefault()}
      >
        <Kbd shortcut={shortcut} />
      </PopoverContent>
    </Popover>
  );
}
