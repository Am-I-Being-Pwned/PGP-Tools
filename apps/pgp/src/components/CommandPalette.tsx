import { useEffect, useRef, useState } from "react";

import {
  Command,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  isMacPlatform,
  Kbd,
} from "@amibeingpwned/ui";

import { useShortcut } from "~/hooks";
import {
  ACTIONS,
  groupLabel,
  PALETTE_SHORTCUT,
} from "~/lib/actions/definitions";
import {
  filterActions,
  findByShortcut,
  groupActions,
  visibleActions,
  type ResolvedAction,
} from "~/lib/actions/registry";
import type { ActionCtx } from "~/lib/actions/types";
import { t } from "~/lib/i18n";
import { isEditableTarget, matchesShortcut } from "~/lib/shortcuts";
import { toast } from "~/lib/toast";
import { hasOpenSlideOver, holdFocusTraps } from "./shared/SlideOver";

/** Below this many actions, a plain list instead of search. */
const MIN_ACTIONS_FOR_SEARCH = 4;

const ITEM_CLASS = "h-9 rounded-md px-2.5";

/** A disabled action's shortcut toasts its reason instead of going dead. */
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
      // Plain-key shortcuts never fire from text fields.
      if (!hit.action.shortcut?.mod && isEditableTarget(event.target)) return;
      event.preventDefault();
      if (hit.disabledReason) {
        // Stable id so key repeat doesn't stack toasts.
        toast.message(
          t("actions_disabled_toast", {
            name: hit.name,
            reason: hit.disabledReason,
          }),
          { id: "action-disabled" },
        );
        return;
      }
      void hit.action.execute(ctxRef.current);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);
}

/** Mounted behind the master-unlock gate, so it cannot open while locked. */
export function CommandPalette({
  ctx,
  bindOpen,
}: {
  ctx: ActionCtx;
  bindOpen?: (open: () => void) => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  // A second step: the action whose options are being listed.
  const [picking, setPicking] = useState<ResolvedAction | null>(null);

  // Traps must pause BEFORE the palette mounts or they yank its autofocus:
  // a synchronous hold in the open handler, not an effect.
  const releaseTrapHold = useRef<(() => void) | null>(null);
  const releaseHold = () => {
    releaseTrapHold.current?.();
    releaseTrapHold.current = null;
  };
  useEffect(() => releaseHold, []);

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
  const showHeadings = groups.length >= 2;

  const step = picking?.action.pick?.(ctx);
  const tokens = query.toLowerCase().split(/\s+/).filter(Boolean);
  const options = step
    ? step.options.filter((o) => {
        const hay = [o.label, ...(o.keywords ?? [])].join(" ").toLowerCase();
        return tokens.every((token) => hay.includes(token));
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
      className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 px-3 pt-14"
      onClick={close}
      onKeyDown={(e) => {
        // Nothing leaks to global shortcuts; Escape never reaches a
        // slide-over below.
        if (
          e.key === "Escape" ||
          matchesShortcut(e.nativeEvent, PALETTE_SHORTCUT, isMacPlatform())
        ) {
          e.preventDefault();
          // Escape backs out of a picker step before it closes.
          if (picking && e.key === "Escape") leaveStep();
          else close();
        }
        if (e.key === "Backspace" && picking && query === "") {
          e.preventDefault();
          leaveStep();
        }
        e.stopPropagation();
      }}
      role="dialog"
      aria-modal="true"
      aria-label={t("actions_palette_label")}
    >
      <div
        className="surface-float w-full max-w-md overflow-hidden rounded-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <Command
          shouldFilter={false}
          label={t("actions_palette_label")}
          className="bg-transparent"
        >
          {/* cmdk's keyboard handling lives on the input: hide, don't unmount. */}
          <div className={showSearch ? undefined : "sr-only"}>
            <CommandInput
              // Remount so cmdk's selection resets per step.
              key={picking ? picking.action.id : "top"}
              value={query}
              onValueChange={setQuery}
              placeholder={
                step ? step.placeholder : t("actions_palette_placeholder")
              }
              autoFocus
            />
          </div>
          <CommandList>
            {step && picking && (
              <CommandGroup heading={step.title}>
                {options.length === 0 && (
                  <p className="text-muted-foreground py-6 text-center text-sm">
                    {t("actions_palette_no_match")}
                  </p>
                )}
                {options.map((o) => (
                  <CommandItem
                    key={o.id}
                    value={o.id}
                    className={ITEM_CLASS}
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
                {t("actions_palette_no_commands")}
              </p>
            )}
            {!step &&
              groups.map(({ group, items }) => (
                <CommandGroup
                  key={group || "other"}
                  heading={showHeadings ? groupLabel(group) : undefined}
                >
                  {items.map(({ action, name, disabledReason }) => (
                    <CommandItem
                      key={action.id}
                      value={action.id}
                      className={ITEM_CLASS}
                      disabled={disabledReason !== undefined}
                      onSelect={() => {
                        // Close before running: the action may move focus.
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
