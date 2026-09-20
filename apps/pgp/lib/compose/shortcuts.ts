import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";

import type { InlineStyle } from "./text-format";

/** Keyboard shortcuts for the message box's editing tools. One source,
 *  read by the toolbar (hints), the key handlers and the Settings
 *  reference page. */
export const FIND_SHORTCUT: ShortcutSpec = { mod: true, key: "f" };

export const STYLE_SHORTCUTS: Record<InlineStyle, ShortcutSpec> = {
  bold: { mod: true, key: "b" },
  italic: { mod: true, key: "i" },
  strike: { mod: true, shift: true, key: "x" },
  code: { mod: true, key: "e" },
};

export const STYLE_LABELS: Record<InlineStyle, string> = {
  bold: "Bold",
  italic: "Italic",
  strike: "Strikethrough",
  code: "Code",
};
