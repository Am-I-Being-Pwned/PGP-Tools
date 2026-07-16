import type { FocusTrap } from "focus-trap";
import { useCallback, useEffect, useRef, useState } from "react";
import { createFocusTrap } from "focus-trap";
import { ArrowLeftIcon } from "lucide-react";
import { tabbable } from "tabbable";

/** Must match the `duration-300` class on the panel. */
export const SLIDE_MS = 300;

// Slide-overs can stack (e.g. a delete confirmation on top of the key
// details page). Escape must only close the topmost one, so each open
// panel registers here and checks it is on top before reacting.
const openStack: symbol[] = [];

/** True while any slide-over is open. Global shortcuts (useShortcut)
 *  check this so workspace-level bindings don't fire underneath a
 *  subpage. */
export function hasOpenSlideOver(): boolean {
  return openStack.length > 0;
}

/**
 * Mount/unmount choreography for a right-to-left slide-over subpage.
 * `entered` drives the transform class; `close` slides out, then calls
 * `onClosed` (where the parent unmounts the panel). Escape closes the
 * topmost open slide-over only; `isTop` lets the panel gate its own
 * shortcuts the same way.
 */
export function useSlideOver(onClosed: () => void) {
  const [entered, setEntered] = useState(false);
  const id = useRef(Symbol("slide-over"));

  useEffect(() => {
    const raf = requestAnimationFrame(() => setEntered(true));
    const self = id.current;
    openStack.push(self);
    return () => {
      cancelAnimationFrame(raf);
      const i = openStack.indexOf(self);
      if (i !== -1) openStack.splice(i, 1);
    };
  }, []);

  const close = useCallback(() => {
    setEntered(false);
    setTimeout(onClosed, SLIDE_MS);
  }, [onClosed]);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (
        e.key === "Escape" &&
        openStack[openStack.length - 1] === id.current
      ) {
        close();
      }
    };
    document.addEventListener("keydown", handler);
    return () => document.removeEventListener("keydown", handler);
  }, [close]);

  const isTop = useCallback(
    () => openStack[openStack.length - 1] === id.current,
    [],
  );

  return { entered, close, isTop };
}

// ── focus management ─────────────────────────────────────────────────
//
// Each open panel traps Tab focus within itself while it is the topmost
// slide-over (focus-trap's shared trap stack auto-pauses a parent panel
// when a child activates, and unpauses it when the child deactivates).
// Two things outside the panel are allowed to own focus while a trap is
// nominally active, and pause it:
//
// - Radix portalled content (Select/Popover/DropdownMenu render into a
//   `[data-radix-popper-content-wrapper]` under <body>, outside every
//   panel). A body MutationObserver pauses the top trap while any such
//   wrapper exists, so Radix's own focus handling wins.
// - The command palette, via {@link holdFocusTraps} -- it must pause the
//   trap BEFORE its input mounts, or the trap would yank the autofocus.

/** Radix popper-positioned portal content lives in these wrappers,
 *  directly under <body>. */
const RADIX_POPPER_SELECTOR = "[data-radix-popper-content-wrapper]";

const activeTraps: FocusTrap[] = [];
let trapHolds = 0;
let popperObserver: MutationObserver | null = null;

function shouldPauseTraps(): boolean {
  return (
    trapHolds > 0 || document.querySelector(RADIX_POPPER_SELECTOR) !== null
  );
}

/** Pause or resume the topmost trap only: traps under it are already
 *  paused by focus-trap's own stack and must stay that way. */
function syncTopTrap(): void {
  const top = activeTraps.at(-1);
  if (!top) return;
  if (shouldPauseTraps()) top.pause();
  else top.unpause();
}

/**
 * Suspend slide-over focus traps while an overlay outside the panel
 * (the command palette) owns the keyboard. Call BEFORE mounting the
 * overlay so its autofocus isn't yanked back into the trap; call the
 * returned release exactly once when the overlay closes (extra calls
 * are no-ops). Safe to call when no slide-over is open.
 */
export function holdFocusTraps(): () => void {
  trapHolds++;
  syncTopTrap();
  let released = false;
  return () => {
    if (released) return;
    released = true;
    trapHolds--;
    syncTopTrap();
  };
}

function registerTrap(trap: FocusTrap): void {
  // Activation pushes onto the shared `activeTraps` stack (the trap's
  // `trapStack` option) and auto-pauses the panel below, if any.
  trap.activate();
  if (shouldPauseTraps()) trap.pause();
  // Popper wrappers are added/removed as direct children of <body>.
  popperObserver ??= new MutationObserver(syncTopTrap);
  if (activeTraps.length === 1) {
    popperObserver.observe(document.body, { childList: true });
  }
}

function unregisterTrap(trap: FocusTrap): void {
  // Deactivation pops the shared stack, returns focus (per
  // setReturnFocus), and unpauses the parent panel's trap if one exists.
  trap.deactivate();
  if (activeTraps.length === 0) popperObserver?.disconnect();
}

export function SlideOverPanel({
  entered,
  ariaLabel,
  children,
}: {
  entered: boolean;
  ariaLabel: string;
  children: React.ReactNode;
}) {
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const panel = panelRef.current;
    if (!panel) return;
    const trap = createFocusTrap(panel, {
      // The openStack keydown handler in useSlideOver owns Escape.
      escapeDeactivates: false,
      // Clicks on portalled content (popovers, toasts) must keep working.
      allowOutsideClick: true,
      // Initial focus: the first autofocus element if the page marked
      // one, else the first tabbable, else the panel itself.
      initialFocus: () =>
        panel.querySelector<HTMLElement>("[autofocus]") ??
        tabbable(panel).at(0) ??
        panel,
      fallbackFocus: panel,
      // Return-focus guard: if the element focused before the
      // panel opened is gone, or lives inside this (closing) panel,
      // leave focus alone instead of throwing.
      setReturnFocus: (previous) =>
        previous.isConnected && !panel.contains(previous) ? previous : false,
      // All panels share one stack so nested slide-overs pause their
      // parent's trap while open (only the topmost trap is ever live).
      trapStack: activeTraps,
    });
    registerTrap(trap);
    return () => unregisterTrap(trap);
  }, []);

  return (
    <div
      ref={panelRef}
      tabIndex={-1}
      className={`bg-background fixed inset-0 z-50 flex flex-col transition-transform duration-300 ease-out ${entered ? "translate-x-0" : "translate-x-full"}`}
      role="region"
      aria-label={ariaLabel}
    >
      {children}
    </div>
  );
}

export function SlideOverHeader({
  title,
  onBack,
  children,
}: {
  title: string;
  onBack: () => void;
  /** Optional action buttons, rendered right-aligned. */
  children?: React.ReactNode;
}) {
  return (
    <div className="border-border flex items-center gap-2 border-b px-3 py-2.5">
      <button
        type="button"
        onClick={onBack}
        aria-label="Back"
        className="text-muted-foreground hover:text-foreground rounded p-1 transition-colors"
      >
        <ArrowLeftIcon className="h-4 w-4" />
      </button>
      <h2 className="truncate text-sm font-semibold">{title}</h2>
      <span className="flex-1" />
      {children}
    </div>
  );
}
