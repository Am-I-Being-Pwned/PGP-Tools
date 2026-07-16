import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";

/** The subset of KeyboardEvent the matcher reads (kept structural so
 *  the pure logic is testable without a DOM). */
export interface ShortcutKeyEvent {
  key: string;
  metaKey: boolean;
  ctrlKey: boolean;
  shiftKey: boolean;
  altKey: boolean;
  repeat: boolean;
}

/** Exact-match a keydown against a spec. `mod` means Cmd on macOS and
 *  Ctrl elsewhere; the *other* of the two must NOT be held, and shift/
 *  alt must match the spec exactly, so e.g. mod+shift+Enter does not
 *  trigger a mod+Enter shortcut. Held-key autorepeat never matches --
 *  these shortcuts fire actions, not scrolling. */
export function matchesShortcut(
  event: ShortcutKeyEvent,
  spec: ShortcutSpec,
  isMac: boolean,
): boolean {
  if (event.repeat) return false;
  const mod = isMac ? event.metaKey : event.ctrlKey;
  const otherMod = isMac ? event.ctrlKey : event.metaKey;
  if (mod !== !!spec.mod || otherMod) return false;
  if (event.shiftKey !== !!spec.shift) return false;
  if (event.altKey !== !!spec.alt) return false;
  return event.key.toLowerCase() === spec.key.toLowerCase();
}

/** True when the event target is somewhere the user types: an input,
 *  textarea, select, or contentEditable region. Plain-key shortcuts
 *  must not fire from these; modifier combos may. */
export function isEditableTarget(target: unknown): boolean {
  if (typeof target !== "object" || target === null) return false;
  const el = target as { tagName?: unknown; isContentEditable?: unknown };
  if (el.isContentEditable === true) return true;
  return (
    el.tagName === "INPUT" ||
    el.tagName === "TEXTAREA" ||
    el.tagName === "SELECT"
  );
}
