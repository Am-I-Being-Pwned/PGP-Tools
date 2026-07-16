import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowLeftIcon } from "lucide-react";

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

export function SlideOverPanel({
  entered,
  ariaLabel,
  children,
}: {
  entered: boolean;
  ariaLabel: string;
  children: React.ReactNode;
}) {
  return (
    <div
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
