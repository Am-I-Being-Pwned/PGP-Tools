// Pure, DOM-free helpers behind the Kbd component, kept out of kbd.tsx
// so app unit tests (and non-React code) can import them without a JSX
// transform.

/** A keyboard shortcut: `mod` is Cmd on macOS and Ctrl elsewhere.
 *  `key` is the KeyboardEvent.key value ("Enter", "c", ...). */
export interface ShortcutSpec {
  mod?: boolean;
  shift?: boolean;
  alt?: boolean;
  key: string;
}

/** True on macOS (and iPadOS/iOS, which share the Cmd convention). */
export function isMacPlatform(): boolean {
  if (typeof navigator === "undefined") return false;
  const nav = navigator as Navigator & {
    userAgentData?: { platform?: string };
  };
  const platform = nav.userAgentData?.platform ?? nav.platform;
  return /mac|iphone|ipad|ipod/i.test(platform);
}

/** Key names rendered as glyphs/abbreviations on both platforms. */
const KEY_LABELS: Record<string, string> = {
  enter: "⏎",
  escape: "Esc",
  " ": "Space",
  arrowup: "↑",
  arrowdown: "↓",
  arrowleft: "←",
  arrowright: "→",
};

function keyLabel(key: string): string {
  const mapped = KEY_LABELS[key.toLowerCase()];
  if (mapped) return mapped;
  return key.length === 1 ? key.toUpperCase() : key;
}

/** One label per keycap chip, in display order. Mac uses the glyph
 *  modifiers (⌥ ⇧ ⌘, Apple menu order); elsewhere they're spelled out
 *  (Ctrl Alt Shift). Enter is the ⏎ glyph on both platforms. */
export function formatShortcut(spec: ShortcutSpec, isMac: boolean): string[] {
  const parts: string[] = [];
  if (isMac) {
    if (spec.alt) parts.push("⌥");
    if (spec.shift) parts.push("⇧");
    if (spec.mod) parts.push("⌘");
  } else {
    if (spec.mod) parts.push("Ctrl");
    if (spec.alt) parts.push("Alt");
    if (spec.shift) parts.push("Shift");
  }
  parts.push(keyLabel(spec.key));
  return parts;
}

/** Human-readable single string, for tooltips: "⇧⌘C" / "Ctrl+Shift+C". */
export function formatShortcutTitle(spec: ShortcutSpec, isMac: boolean) {
  return formatShortcut(spec, isMac).join(isMac ? "" : "+");
}

/** Value for the `aria-keyshortcuts` attribute, e.g. "Meta+Shift+C". */
export function ariaKeyShortcuts(spec: ShortcutSpec, isMac: boolean): string {
  const parts: string[] = [];
  if (spec.mod) parts.push(isMac ? "Meta" : "Control");
  if (spec.alt) parts.push("Alt");
  if (spec.shift) parts.push("Shift");
  parts.push(spec.key.length === 1 ? spec.key.toUpperCase() : spec.key);
  return parts.join("+");
}
