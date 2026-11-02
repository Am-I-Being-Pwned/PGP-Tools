import type { ShortcutSpec } from "@amibeingpwned/ui";

/** Structural so the matcher is testable without a DOM. */
export interface ShortcutKeyEvent {
  key: string;
  metaKey: boolean;
  ctrlKey: boolean;
  shiftKey: boolean;
  altKey: boolean;
  repeat: boolean;
}

/** Exact match: `mod` is Cmd on macOS, Ctrl elsewhere (the other must not
 *  be held); shift/alt must match; autorepeat never matches. */
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

/** Plain-key shortcuts must not fire from typing targets; modifier combos may. */
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
