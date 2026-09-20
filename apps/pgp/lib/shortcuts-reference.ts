// The data behind Settings -> Keyboard shortcuts: every shortcut the
// app answers to, in one greppable place. Anything with a live source
// of truth is DERIVED from it (mod+K from PALETTE_SHORTCUT, the mode
// switches from MODE_SHORTCUTS, copy/download from COPY_SHORTCUT/
// DOWNLOAD_SHORTCUT); the rest is static and drift-guarded
// by shortcuts-reference.test.ts where a source exists to compare.

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";

import type { PgpMode } from "./actions/types";
import type { InlineStyle } from "./compose/text-format";
import type { MessageKey } from "./i18n";
import {
  COPY_SHORTCUT,
  DOWNLOAD_SHORTCUT,
  MODE_SHORTCUTS,
  PALETTE_SHORTCUT,
} from "./actions/definitions";
import {
  FIND_SHORTCUT,
  STYLE_LABELS,
  STYLE_SHORTCUTS,
} from "./compose/shortcuts";
import { t } from "./i18n";

/** One row of the reference: a label plus how to render its keys. */
export interface ShortcutRefEntry {
  label: string;
  /** Platform-aware keycaps (mod renders as Cmd on macOS, Ctrl
   *  elsewhere). Omit together with `chips` for an unbound entry. */
  shortcut?: ShortcutSpec;
  /** Literal keycap chips for keys a ShortcutSpec can't express
   *  (a digit range, plain Backspace). */
  chips?: string[];
  /** Fine print under the label ("only while the search is empty"). */
  note?: string;
}

/** A titled group of reference rows. */
export interface ShortcutRefSection {
  /** Stable identifier, independent of the translated title. */
  id: "palette" | "workspace" | "message" | "modes" | "global";
  title: string;
  entries: ShortcutRefEntry[];
  /** Fine print under the whole section. */
  note?: string;
}

/** Where Chrome lets users rebind extension commands. Rendered as
 *  plain text (chrome:// links don't open from extension pages) and
 *  opened via chrome.tabs.create from the reference page's button. */
export const CHROME_SHORTCUTS_URL = "chrome://extensions/shortcuts";

const MODE_NAMES: Record<PgpMode, MessageKey> = {
  encrypt: "common_encrypt",
  decrypt: "common_decrypt",
  sign: "common_sign",
  verify: "common_verify",
};

/** Chrome's suggested bindings for the manifest `commands`; the Verify
 *  mode ships unbound (Chrome caps suggested keys at four). */
const GLOBAL_MODE_SHORTCUTS: Record<PgpMode, ShortcutSpec | undefined> = {
  encrypt: { alt: true, shift: true, key: "E" },
  decrypt: { alt: true, shift: true, key: "D" },
  sign: { alt: true, shift: true, key: "S" },
  verify: undefined,
};

/**
 * The full shortcut reference, in display order. A function rather than
 * a constant so every label is looked up in the UI language at render
 * time, never at module load.
 */
export function shortcutReference(): readonly ShortcutRefSection[] {
  return [
    {
      id: "palette",
      title: t("settings_shortcuts_group_palette"),
      entries: [
        {
          label: t("settings_shortcuts_open_palette"),
          shortcut: PALETTE_SHORTCUT,
          note: t("settings_shortcuts_open_palette_note"),
        },
      ],
    },
    {
      id: "workspace",
      title: t("settings_shortcuts_group_workspace"),
      entries: [
        {
          label: t("settings_shortcuts_run_mode"),
          shortcut: { mod: true, key: "Enter" },
        },
        {
          label: t("settings_shortcuts_copy_output"),
          shortcut: COPY_SHORTCUT,
        },
        {
          label: t("settings_shortcuts_download_output"),
          shortcut: DOWNLOAD_SHORTCUT,
        },
        {
          label: t("settings_shortcuts_pick_recipient"),
          chips: ["1-9"],
          note: t("settings_shortcuts_pick_recipient_note"),
        },
        {
          label: t("settings_shortcuts_remove_recipient"),
          chips: ["Backspace"],
          note: t("settings_shortcuts_remove_recipient_note"),
        },
      ],
    },
    {
      id: "message",
      title: t("settings_shortcuts_group_message"),
      entries: [
        {
          label: t("settings_shortcuts_find_replace"),
          shortcut: FIND_SHORTCUT,
        },
        ...(Object.keys(STYLE_SHORTCUTS) as InlineStyle[]).map((style) => ({
          label: STYLE_LABELS[style],
          shortcut: STYLE_SHORTCUTS[style],
          note: t("settings_shortcuts_style_note"),
        })),
      ],
    },
    {
      id: "modes",
      title: t("settings_shortcuts_group_modes"),
      // Derived, never hand-listed: MODE_SHORTCUTS is the single source
      // shared with the registry's mode actions and the mode dropdown.
      entries: (
        Object.entries(MODE_SHORTCUTS) as [PgpMode, ShortcutSpec][]
      ).map(([mode, shortcut]) => ({
        label: t("settings_shortcuts_switch_mode", {
          mode: t(MODE_NAMES[mode]),
        }),
        shortcut,
      })),
    },
    {
      id: "global",
      title: t("settings_shortcuts_group_global"),
      entries: [
        {
          label: t("settings_shortcuts_open_app"),
          shortcut: { alt: true, shift: true, key: "G" },
        },
        ...(Object.keys(GLOBAL_MODE_SHORTCUTS) as PgpMode[]).map((mode) => {
          const shortcut = GLOBAL_MODE_SHORTCUTS[mode];
          const label = t("settings_shortcuts_open_in_mode", {
            mode: t(MODE_NAMES[mode]),
          });
          return shortcut
            ? { label, shortcut }
            : { label, note: t("settings_shortcuts_unbound_note") };
        }),
      ],
      note: t("settings_shortcuts_global_note", { url: CHROME_SHORTCUTS_URL }),
    },
  ];
}
