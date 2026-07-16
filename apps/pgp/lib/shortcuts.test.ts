import { describe, expect, it } from "vitest";

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";
import {
  ariaKeyShortcuts,
  formatShortcut,
  formatShortcutTitle,
} from "@amibeingpwned/ui/kbd-helpers";

import type { ShortcutKeyEvent } from "./shortcuts";
import { isEditableTarget, matchesShortcut } from "./shortcuts";

const MOD_ENTER: ShortcutSpec = { mod: true, key: "Enter" };
const MOD_SHIFT_C: ShortcutSpec = { mod: true, shift: true, key: "c" };

function keydown(overrides: Partial<ShortcutKeyEvent>): ShortcutKeyEvent {
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

describe("formatShortcut", () => {
  it("renders mod as ⌘ on macOS", () => {
    expect(formatShortcut(MOD_ENTER, true)).toEqual(["⌘", "⏎"]);
  });

  it("renders mod as Ctrl elsewhere", () => {
    expect(formatShortcut(MOD_ENTER, false)).toEqual(["Ctrl", "⏎"]);
  });

  it("uses glyph modifiers in Apple order on macOS", () => {
    expect(
      formatShortcut({ mod: true, shift: true, alt: true, key: "k" }, true),
    ).toEqual(["⌥", "⇧", "⌘", "K"]);
  });

  it("spells modifiers out on other platforms", () => {
    expect(
      formatShortcut({ mod: true, shift: true, alt: true, key: "k" }, false),
    ).toEqual(["Ctrl", "Alt", "Shift", "K"]);
  });

  it("uppercases single-character keys", () => {
    expect(formatShortcut(MOD_SHIFT_C, true)).toEqual(["⇧", "⌘", "C"]);
  });

  it("abbreviates Escape", () => {
    expect(formatShortcut({ key: "Escape" }, true)).toEqual(["Esc"]);
    expect(formatShortcut({ key: "Escape" }, false)).toEqual(["Esc"]);
  });

  it("renders a bare key without modifiers", () => {
    expect(formatShortcut({ key: "c" }, false)).toEqual(["C"]);
  });
});

describe("formatShortcutTitle", () => {
  it("joins without separator on macOS", () => {
    expect(formatShortcutTitle(MOD_SHIFT_C, true)).toBe("⇧⌘C");
  });

  it("joins with + elsewhere", () => {
    expect(formatShortcutTitle(MOD_SHIFT_C, false)).toBe("Ctrl+Shift+C");
  });
});

describe("ariaKeyShortcuts", () => {
  it("uses Meta on macOS and Control elsewhere", () => {
    expect(ariaKeyShortcuts(MOD_ENTER, true)).toBe("Meta+Enter");
    expect(ariaKeyShortcuts(MOD_ENTER, false)).toBe("Control+Enter");
  });

  it("lists all modifiers with an uppercased letter key", () => {
    expect(
      ariaKeyShortcuts({ mod: true, shift: true, alt: true, key: "c" }, false),
    ).toBe("Control+Alt+Shift+C");
  });
});

describe("matchesShortcut", () => {
  it("matches mod+Enter via metaKey on macOS", () => {
    expect(
      matchesShortcut(
        keydown({ key: "Enter", metaKey: true }),
        MOD_ENTER,
        true,
      ),
    ).toBe(true);
  });

  it("matches mod+Enter via ctrlKey on other platforms", () => {
    expect(
      matchesShortcut(
        keydown({ key: "Enter", ctrlKey: true }),
        MOD_ENTER,
        false,
      ),
    ).toBe(true);
  });

  it("does not treat Ctrl as mod on macOS", () => {
    expect(
      matchesShortcut(
        keydown({ key: "Enter", ctrlKey: true }),
        MOD_ENTER,
        true,
      ),
    ).toBe(false);
  });

  it("rejects when the wrong modifier of the pair is also held", () => {
    expect(
      matchesShortcut(
        keydown({ key: "Enter", metaKey: true, ctrlKey: true }),
        MOD_ENTER,
        true,
      ),
    ).toBe(false);
  });

  it("rejects plain Enter for a mod+Enter spec", () => {
    expect(matchesShortcut(keydown({ key: "Enter" }), MOD_ENTER, true)).toBe(
      false,
    );
  });

  it("requires shift exactly", () => {
    const event = keydown({ key: "c", metaKey: true, shiftKey: true });
    expect(matchesShortcut(event, MOD_SHIFT_C, true)).toBe(true);
    // Extra shift must not trigger the shift-less shortcut...
    expect(matchesShortcut(event, { mod: true, key: "c" }, true)).toBe(false);
    // ...and a missing shift must not trigger the shifted one.
    expect(
      matchesShortcut(keydown({ key: "c", metaKey: true }), MOD_SHIFT_C, true),
    ).toBe(false);
  });

  it("requires alt exactly", () => {
    const spec: ShortcutSpec = { mod: true, alt: true, key: "n" };
    expect(
      matchesShortcut(
        keydown({ key: "n", metaKey: true, altKey: true }),
        spec,
        true,
      ),
    ).toBe(true);
    expect(
      matchesShortcut(keydown({ key: "n", metaKey: true }), spec, true),
    ).toBe(false);
  });

  it("compares keys case-insensitively (shift reports 'C')", () => {
    expect(
      matchesShortcut(
        keydown({ key: "C", metaKey: true, shiftKey: true }),
        MOD_SHIFT_C,
        true,
      ),
    ).toBe(true);
  });

  it("matches plain-key specs with no modifiers held", () => {
    expect(matchesShortcut(keydown({ key: "c" }), { key: "c" }, true)).toBe(
      true,
    );
    expect(
      matchesShortcut(keydown({ key: "c", metaKey: true }), { key: "c" }, true),
    ).toBe(false);
  });

  it("ignores autorepeat", () => {
    expect(
      matchesShortcut(
        keydown({ key: "Enter", metaKey: true, repeat: true }),
        MOD_ENTER,
        true,
      ),
    ).toBe(false);
  });
});

describe("isEditableTarget", () => {
  it("flags inputs, textareas and selects", () => {
    expect(isEditableTarget({ tagName: "INPUT" })).toBe(true);
    expect(isEditableTarget({ tagName: "TEXTAREA" })).toBe(true);
    expect(isEditableTarget({ tagName: "SELECT" })).toBe(true);
  });

  it("flags contentEditable regions", () => {
    expect(isEditableTarget({ tagName: "DIV", isContentEditable: true })).toBe(
      true,
    );
  });

  it("ignores ordinary elements and non-elements", () => {
    expect(
      isEditableTarget({ tagName: "BUTTON", isContentEditable: false }),
    ).toBe(false);
    expect(isEditableTarget({ tagName: "DIV" })).toBe(false);
    expect(isEditableTarget(null)).toBe(false);
    expect(isEditableTarget(undefined)).toBe(false);
  });
});
