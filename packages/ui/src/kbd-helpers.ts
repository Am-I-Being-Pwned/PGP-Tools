// DOM-free, so app unit tests can import without a JSX transform.

/** `mod` is Cmd on macOS, Ctrl elsewhere; `key` is KeyboardEvent.key. */
export interface ShortcutSpec {
  mod?: boolean;
  shift?: boolean;
  alt?: boolean;
  key: string;
}

/** Includes iPadOS/iOS, which share the Cmd convention. */
export function isMacPlatform(): boolean {
  if (typeof navigator === "undefined") return false;
  const nav = navigator as Navigator & {
    userAgentData?: { platform?: string };
  };
  const platform = nav.userAgentData?.platform ?? nav.platform;
  return /mac|iphone|ipad|ipod/i.test(platform);
}

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

/** One label per keycap chip; Mac modifiers in Apple menu order. */
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

export function formatShortcutTitle(spec: ShortcutSpec, isMac: boolean) {
  return formatShortcut(spec, isMac).join(isMac ? "" : "+");
}

export function ariaKeyShortcuts(spec: ShortcutSpec, isMac: boolean): string {
  const parts: string[] = [];
  if (spec.mod) parts.push(isMac ? "Meta" : "Control");
  if (spec.alt) parts.push("Alt");
  if (spec.shift) parts.push("Shift");
  parts.push(spec.key.length === 1 ? spec.key.toUpperCase() : spec.key);
  return parts.join("+");
}
