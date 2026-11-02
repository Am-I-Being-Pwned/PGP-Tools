/** TEST-ONLY keydown builder. Imported exclusively from `*.test.ts`. */

import type { ShortcutKeyEvent } from "~/lib/shortcuts";

export function keydown(
  overrides: Partial<ShortcutKeyEvent>,
): ShortcutKeyEvent {
  return {
    key: "",
    metaKey: false,
    ctrlKey: false,
    shiftKey: false,
    altKey: false,
    repeat: false,
    ...overrides,
  };
}
