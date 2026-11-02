import { useCallback, useEffect, useRef, useState } from "react";
import { createFocusTrap, type FocusTrap } from "focus-trap";
import { ChevronLeftIcon } from "lucide-react";
import { tabbable } from "tabbable";

import { t } from "~/lib/i18n";

/** Must match the `duration-300` class on the panel. */
export const SLIDE_MS = 300;

// Slide-overs stack; Escape closes only the topmost.
const openStack: symbol[] = [];

/** Global shortcuts check this so they don't fire underneath a subpage. */
export function hasOpenSlideOver(): boolean {
  return openStack.length > 0;
}

/** `close` slides out, then calls `onClosed` (where the parent unmounts). */
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

// The topmost panel traps focus, paused while Radix portal content (under
// <body>) or the command palette ({@link holdFocusTraps}) owns it.

const RADIX_POPPER_SELECTOR = "[data-radix-popper-content-wrapper]";

const activeTraps: FocusTrap[] = [];
let trapHolds = 0;
let popperObserver: MutationObserver | null = null;

function shouldPauseTraps(): boolean {
  return (
    trapHolds > 0 || document.querySelector(RADIX_POPPER_SELECTOR) !== null
  );
}

/** Topmost trap only: focus-trap's stack keeps the ones below paused. */
function syncTopTrap(): void {
  const top = activeTraps.at(-1);
  if (!top) return;
  if (shouldPauseTraps()) top.pause();
  else top.unpause();
}

/** Suspend focus traps for an outside overlay. Call BEFORE mounting it,
 *  or the trap yanks its autofocus back. */
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
  trap.activate();
  if (shouldPauseTraps()) trap.pause();
  popperObserver ??= new MutationObserver(syncTopTrap);
  if (activeTraps.length === 1) {
    popperObserver.observe(document.body, { childList: true });
  }
}

function unregisterTrap(trap: FocusTrap): void {
  trap.deactivate();
  if (activeTraps.length === 0) popperObserver?.disconnect();
}

export function SlideOverPanel({
  entered,
  ariaLabel,
  onDismiss,
  children,
}: {
  entered: boolean;
  ariaLabel: string;
  /** Backdrop click. Pass the hook's `close` so it slides out. */
  onDismiss?: () => void;
  children: React.ReactNode;
}) {
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const panel = panelRef.current;
    if (!panel) return;
    // Trap only while fully open, so a CLOSING panel never yanks focus
    // from whatever the user clicked into below.
    if (!entered) return;
    const trap = createFocusTrap(panel, {
      // useSlideOver's openStack handler owns Escape.
      escapeDeactivates: false,
      allowOutsideClick: true,
      // Live focus first: React's autoFocus calls .focus() and renders no
      // [autofocus] attribute, so without this the trap steals focus to
      // Back mid-typing.
      initialFocus: () => {
        const active = document.activeElement;
        if (active instanceof HTMLElement && panel.contains(active)) {
          return active;
        }
        return (
          panel.querySelector<HTMLElement>("[autofocus]") ??
          tabbable(panel).at(0) ??
          panel
        );
      },
      fallbackFocus: panel,
      // Don't return focus if the user has already moved on: it would
      // hijack their typing.
      setReturnFocus: (previous) => {
        const active = document.activeElement;
        const userMovedOn =
          active !== null &&
          active !== document.body &&
          !panel.contains(active);
        if (userMovedOn) return false;
        return previous.isConnected && !panel.contains(previous)
          ? previous
          : false;
      },
      trapStack: activeTraps,
    });
    registerTrap(trap);
    return () => unregisterTrap(trap);
  }, [entered]);

  // Nested panels stack as later siblings at the same width; each
  // backdrop darkens the exposed strip a step further (the depth cue).
  return (
    <div className="pointer-events-none fixed inset-0 z-50">
      {/* Click-through layer: it stays mounted for the slide-out, and an
          invisible click-swallower would dead-zone the view after close. */}
      <div
        aria-hidden="true"
        onClick={onDismiss}
        className={`absolute inset-0 bg-black/40 transition-opacity duration-300 ease-out ${entered ? "pointer-events-auto opacity-100" : "opacity-0"}`}
      />
      <div
        ref={panelRef}
        tabIndex={-1}
        className={`bg-background pointer-events-auto absolute inset-y-0 right-0 flex w-3/4 flex-col shadow-xl transition-transform duration-300 ease-out ${entered ? "translate-x-0" : "translate-x-full"}`}
        role="region"
        aria-label={ariaLabel}
      >
        {children}
      </div>
    </div>
  );
}

export function SlideOverHeader({
  title,
  hideTitle = false,
  onBack,
  children,
}: {
  title: string;
  /** Screen-reader-only title, for headers whose actions need the room. */
  hideTitle?: boolean;
  onBack: () => void;
  children?: React.ReactNode;
}) {
  return (
    // With actions, Back drops to its chevron to leave the title room.
    <div className="bg-chrome flex min-h-[46px] items-center gap-1.5 border-b border-white/[0.06] py-2 pr-2.5 pl-2">
      <button
        type="button"
        onClick={onBack}
        aria-label={t("common_back")}
        className={`text-muted-foreground hover:bg-accent hover:text-foreground flex h-[30px] shrink-0 items-center gap-1 rounded-lg text-sm font-medium transition-colors ${children ? "w-[30px] justify-center" : "pr-2.5 pl-1"}`}
      >
        <ChevronLeftIcon className="h-4 w-4" />
        {!children && t("common_back")}
      </button>
      <h2
        className={
          hideTitle ? "sr-only" : "ml-1 min-w-0 truncate text-sm font-semibold"
        }
      >
        {title}
      </h2>
      <span className="flex-1" />
      {children}
    </div>
  );
}
