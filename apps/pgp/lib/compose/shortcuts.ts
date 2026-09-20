import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";

import type { InlineStyle } from "./text-format";
import { t } from "../i18n";

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

/** Localised name of each style. Getters, not values: `t()` must run at
 *  use time (after the i18n shim is installed), and the consumers read
 *  this as a plain `Record<InlineStyle, string>`. */
export const STYLE_LABELS: Record<InlineStyle, string> = {
  get bold() {
    return t("workspace_style_bold");
  },
  get italic() {
    return t("workspace_style_italic");
  },
  get strike() {
    return t("workspace_style_strike");
  },
  get code() {
    return t("workspace_style_code");
  },
};
