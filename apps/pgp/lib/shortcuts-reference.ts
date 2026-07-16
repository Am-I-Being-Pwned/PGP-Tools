// The data behind Settings -> Keyboard shortcuts: every shortcut the
// app answers to, in one greppable place. Anything with a live source
// of truth is DERIVED from it (mod+K from PALETTE_SHORTCUT, the mode
// switches from MODE_SHORTCUTS); the rest is static and drift-guarded
// by shortcuts-reference.test.ts where a source exists to compare.

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";

import type { PgpMode } from "./actions/types";
import { MODE_SHORTCUTS, PALETTE_SHORTCUT } from "./actions/definitions";

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
  title: string;
  entries: ShortcutRefEntry[];
  /** Fine print under the whole section. */
  note?: string;
}

/** Where Chrome lets users rebind extension commands. Rendered as
 *  plain text (chrome:// links don't open from extension pages) and
 *  opened via chrome.tabs.create from the reference page's button. */
export const CHROME_SHORTCUTS_URL = "chrome://extensions/shortcuts";

const MODE_NAMES: Record<PgpMode, string> = {
  encrypt: "Encrypt",
  decrypt: "Decrypt",
  sign: "Sign",
  verify: "Verify",
};

/** The full shortcut reference, in display order. */
export const SHORTCUT_REFERENCE: readonly ShortcutRefSection[] = [
  {
    title: "Command palette",
    entries: [
      {
        label: "Open the command palette",
        shortcut: PALETTE_SHORTCUT,
        note: "Every action below is also searchable there.",
      },
    ],
  },
  {
    title: "Workspace",
    entries: [
      {
        label: "Run the current mode",
        shortcut: { mod: true, key: "Enter" },
      },
      {
        label: "Copy the output",
        shortcut: { mod: true, shift: true, key: "c" },
      },
      {
        label: "Pick the nth recipient",
        chips: ["1-9"],
        note: "In the recipient dropdown, while its search box is empty.",
      },
      {
        label: "Remove the last recipient",
        chips: ["Backspace"],
        note: "In the recipient dropdown's empty search box.",
      },
    ],
  },
  {
    title: "Modes",
    // Derived, never hand-listed: MODE_SHORTCUTS is the single source
    // shared with the registry's mode actions and the mode dropdown.
    entries: (
      Object.entries(MODE_SHORTCUTS) as [PgpMode, ShortcutSpec][]
    ).map(([mode, shortcut]) => ({
      label: `Switch to ${MODE_NAMES[mode]}`,
      shortcut,
    })),
  },
  {
    title: "Global browser shortcuts",
    entries: [
      {
        label: "Open PGP Tools",
        shortcut: { alt: true, shift: true, key: "G" },
      },
      {
        label: "Open in Encrypt mode",
        shortcut: { alt: true, shift: true, key: "E" },
      },
      {
        label: "Open in Decrypt mode",
        shortcut: { alt: true, shift: true, key: "D" },
      },
      {
        label: "Open in Sign mode",
        shortcut: { alt: true, shift: true, key: "S" },
      },
      {
        label: "Open in Verify mode",
        note: "Unbound by default (Chrome caps suggested keys at four).",
      },
    ],
    note: `These work anywhere in the browser. Rebind any of them at ${CHROME_SHORTCUTS_URL}.`,
  },
];
