import { useEffect, useRef, useState } from "react";

import {
  Command,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@amibeingpwned/ui/command";
import { Kbd } from "@amibeingpwned/ui/kbd";
import { isMacPlatform } from "@amibeingpwned/ui/kbd-helpers";

import type { ResolvedAction } from "../lib/actions/registry";
import type { ActionCtx } from "../lib/actions/types";
import { useShortcut } from "../hooks/useShortcut";
import { ACTIONS, PALETTE_SHORTCUT } from "../lib/actions/definitions";
import {
  filterActions,
  findByShortcut,
  groupActions,
  visibleActions,
} from "../lib/actions/registry";
import { isEditableTarget, matchesShortcut } from "../lib/shortcuts";
import { toast } from "../lib/toast";
import { hasOpenSlideOver, holdFocusTraps } from "./shared/SlideOver";

/** Below this many visible actions the search input is pointless noise
 *  -- show a plain list instead. */
const MIN_ACTIONS_FOR_SEARCH = 4;

/**
 * Dispatch registry shortcuts globally: an enabled action executes; a
 * disabled one toasts its reason ("<name> is disabled: <reason>")
 * instead of going silently dead. Suspended while
 * the palette is open (it owns the keyboard) or a slide-over is up.
 */
function useRegistryShortcuts(ctx: ActionCtx, suspended: boolean) {
  const ctxRef = useRef(ctx);
  const suspendedRef = useRef(suspended);
  useEffect(() => {
    ctxRef.current = ctx;
    suspendedRef.current = suspended;
  });

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (suspendedRef.current || hasOpenSlideOver()) return;
      const hit = findByShortcut(
        ACTIONS,
        event,
        ctxRef.current,
        isMacPlatform(),
      );
      if (!hit) return;
      // Same rule as useShortcut: plain-key shortcuts must not fire
      // from text fields; modifier combos may.
      if (!hit.action.shortcut?.mod && isEditableTarget(event.target)) return;
      event.preventDefault();
      if (hit.disabledReason) {
        // Stable id: holding the shortcut down must not stack a column
        // of identical "disabled" toasts.
        toast.message(`${hit.name} is disabled: ${hit.disabledReason}`, {
          id: "action-disabled",
        });
        return;
      }
      void hit.action.execute(ctxRef.current);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);
}

/**
 * The mod+K command palette. Mounted once behind the master-unlock
 * gate (so it cannot open while locked); also owns global dispatch of
 * the actions' registered shortcuts.
 */
export function CommandPalette({
  ctx,
  bindOpen,
}: {
  ctx: ActionCtx;
  /** Receives an imperative open() so other chrome (the footer's ⌘K
   *  hint) can pop the palette without owning its state. */
  bindOpen?: (open: () => void) => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  // A second step: the action whose options are being listed.
  const [picking, setPicking] = useState<ResolvedAction | null>(null);

  // While the palette is up, any slide-over focus trap must pause --
  // and it must pause BEFORE the palette mounts, or the trap would
  // yank focus straight back from the search input's autoFocus. Hence
  // a synchronous hold in the open handler, not an effect.
  const releaseTrapHold = useRef<(() => void) | null>(null);
  const releaseHold = () => {
    releaseTrapHold.current?.();
    releaseTrapHold.current = null;
  };
  useEffect(() => releaseHold, []);

  // Shared by the mod+K shortcut and the imperative `bindOpen` hook-up.
  const openPalette = () => {
    releaseTrapHold.current ??= holdFocusTraps();
    setQuery("");
    setPicking(null);
    setOpen(true);
  };

  useShortcut(PALETTE_SHORTCUT, openPalette, { allowInInput: true });

  const openPaletteRef = useRef(openPalette);
  useEffect(() => {
    openPaletteRef.current = openPalette;
  });
  useEffect(() => {
    bindOpen?.(() => openPaletteRef.current());
  }, [bindOpen]);

  useRegistryShortcuts(ctx, open);

  if (!open) return null;

  const close = () => {
    setOpen(false);
    setPicking(null);
    releaseHold();
  };
  const resolved = visibleActions(ACTIONS, ctx);
  const showSearch = resolved.length >= MIN_ACTIONS_FOR_SEARCH || !!picking;
  const matches = filterActions(resolved, showSearch ? query : "");
  const groups = groupActions(matches);
  // Group headers only earn their space when they separate something.
  const showHeadings = groups.length >= 2;

  // The picker step's options, filtered with the same token rule.
  const step = picking?.action.pick?.(ctx);
  const tokens = query.toLowerCase().split(/\s+/).filter(Boolean);
  const options = step
    ? step.options.filter((o) => {
        const hay = [o.label, ...(o.keywords ?? [])].join(" ").toLowerCase();
        return tokens.every((t) => hay.includes(t));
      })
    : [];
  const enterStep = (r: ResolvedAction) => {
    setPicking(r);
    setQuery("");
  };
  const leaveStep = () => {
    setPicking(null);
    setQuery("");
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/50 px-4 pt-14"
      onClick={close}
      onKeyDown={(e) => {
        // The palette owns the keyboard: nothing leaks to the global
        // shortcut listeners underneath. Escape closes the palette
        // only (never a slide-over below it); mod+K toggles it shut.
        if (
          e.key === "Escape" ||
          matchesShortcut(e.nativeEvent, PALETTE_SHORTCUT, isMacPlatform())
        ) {
          e.preventDefault();
          // Escape backs out of a picker step before it closes.
          if (picking && e.key === "Escape") leaveStep();
          else close();
        }
        // Backspace on an empty picker query backs out too.
        if (e.key === "Backspace" && picking && query === "") {
          e.preventDefault();
          leaveStep();
        }
        e.stopPropagation();
      }}
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
    >
      <div
        className="border-border w-full max-w-md overflow-hidden rounded-lg border shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        <Command shouldFilter={false} label="Command palette">
          {/* With very few actions the search box is noise -- but
              cmdk's keyboard handling
              lives on the focused input, so hide it visually instead
              of unmounting it. Typed text is ignored while hidden. */}
          <div className={showSearch ? undefined : "sr-only"}>
            <CommandInput
              // Remount on step change so cmdk's selection resets to
              // the first option of the new list.
              key={picking ? picking.action.id : "top"}
              value={query}
              onValueChange={setQuery}
              placeholder={step ? step.placeholder : "Type a command..."}
              autoFocus
            />
          </div>
          <CommandList>
            {step && picking && (
              <CommandGroup heading={step.title}>
                {options.length === 0 && (
                  <p className="text-muted-foreground py-6 text-center text-sm">
                    No match.
                  </p>
                )}
                {options.map((o) => (
                  <CommandItem
                    key={o.id}
                    value={o.id}
                    onSelect={() => {
                      const action = picking.action;
                      close();
                      void action.execute(ctx, o.id);
                    }}
                  >
                    <span className="truncate">{o.label}</span>
                  </CommandItem>
                ))}
              </CommandGroup>
            )}
            {!step && matches.length === 0 && (
              <p className="text-muted-foreground py-6 text-center text-sm">
                No matching commands.
              </p>
            )}
            {!step &&
              groups.map(({ group, items }) => (
                <CommandGroup
                  key={group || "other"}
                  heading={showHeadings ? group : undefined}
                >
                  {items.map(({ action, name, disabledReason }) => (
                    <CommandItem
                      key={action.id}
                      value={action.id}
                      disabled={disabledReason !== undefined}
                      onSelect={() => {
                        // An action with a second step stays open on
                        // it; otherwise close first, then run: the
                        // action may move focus or open a slide-over.
                        if (action.pick) {
                          enterStep({ action, name, disabledReason });
                          return;
                        }
                        close();
                        void action.execute(ctx);
                      }}
                    >
                      <span className="truncate">{name}</span>
                      <span className="ml-auto flex shrink-0 items-center pl-3">
                        {disabledReason !== undefined ? (
                          <span className="text-muted-foreground text-xs">
                            {disabledReason}
                          </span>
                        ) : (
                          action.shortcut && <Kbd shortcut={action.shortcut} />
                        )}
                      </span>
                    </CommandItem>
                  ))}
                </CommandGroup>
              ))}
          </CommandList>
        </Command>
      </div>
    </div>
  );
}
