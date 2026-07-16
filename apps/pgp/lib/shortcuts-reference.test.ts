import { describe, expect, it } from "vitest";

import { MODE_SHORTCUTS, PALETTE_SHORTCUT } from "./actions/definitions";
import { SHORTCUT_REFERENCE } from "./shortcuts-reference";

function section(title: string) {
  const hit = SHORTCUT_REFERENCE.find((s) => s.title === title);
  if (!hit) throw new Error(`no "${title}" section in the reference`);
  return hit;
}

// Drift guards: the reference page must never show stale bindings for
// shortcuts that have a live source of truth elsewhere.
describe("shortcut reference", () => {
  it("modes section matches MODE_SHORTCUTS exactly", () => {
    const modes = Object.entries(MODE_SHORTCUTS);
    const entries = section("Modes").entries;
    expect(entries).toHaveLength(modes.length);
    for (const [mode, spec] of modes) {
      const entry = entries.find((e) =>
        e.label.toLowerCase().includes(mode),
      );
      expect(entry, `no modes entry mentions "${mode}"`).toBeDefined();
      expect(entry?.shortcut).toEqual(spec);
    }
  });

  it("palette section shows the real palette shortcut", () => {
    expect(section("Command palette").entries[0]?.shortcut).toEqual(
      PALETTE_SHORTCUT,
    );
  });

  it("every entry has keycaps or an explanatory note", () => {
    for (const s of SHORTCUT_REFERENCE) {
      for (const e of s.entries) {
        expect(
          e.shortcut !== undefined ||
            e.chips !== undefined ||
            e.note !== undefined,
          `"${e.label}" renders neither keys nor a note`,
        ).toBe(true);
      }
    }
  });
});
