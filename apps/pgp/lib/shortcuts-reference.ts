// Settings -> Keyboard shortcuts data. Entries with a live source of truth
// are derived from it; the rest are drift-guarded by the test.

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";

import type { PgpMode } from "./actions/types";
import type { InlineStyle } from "./compose/text-format";
import type { MessageKey } from "./i18n";
import {
  COPY_SHORTCUT,
  DOWNLOAD_SHORTCUT,
  MODE_SHORTCUTS,
  PALETTE_SHORTCUT,
  REPLY_SHORTCUT,
} from "./actions/definitions";
import {
  FIND_SHORTCUT,
  STYLE_LABELS,
  STYLE_SHORTCUTS,
} from "./compose/shortcuts";
import { t } from "./i18n";

export interface ShortcutRefEntry {
  label: string;
  /** Omit together with `chips` for an unbound entry. */
  shortcut?: ShortcutSpec;
  /** For keys a ShortcutSpec can't express (a digit range, Backspace). */
  chips?: string[];
  note?: string;
}

export interface ShortcutRefSection {
  id: "palette" | "workspace" | "message" | "modes" | "global";
  title: string;
  entries: ShortcutRefEntry[];
  note?: string;
}

/** Plain text: chrome:// links don't open from extension pages. */
export const CHROME_SHORTCUTS_URL = "chrome://extensions/shortcuts";

const MODE_NAMES: Record<PgpMode, MessageKey> = {
  encrypt: "common_encrypt",
  decrypt: "common_decrypt",
  sign: "common_sign",
  verify: "common_verify",
};

/** Manifest `commands` defaults; Verify is unbound (Chrome caps at four). */
const GLOBAL_MODE_SHORTCUTS: Record<PgpMode, ShortcutSpec | undefined> = {
  encrypt: { alt: true, shift: true, key: "E" },
  decrypt: { alt: true, shift: true, key: "D" },
  sign: { alt: true, shift: true, key: "S" },
  verify: undefined,
};

/** A function so labels are translated at render time, not module load. */
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
          label: t("settings_shortcuts_reply"),
          shortcut: REPLY_SHORTCUT,
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
