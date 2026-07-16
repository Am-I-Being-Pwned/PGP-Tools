import { describe, expect, it, vi } from "vitest";

import type { ShortcutKeyEvent } from "../shortcuts";
import type { ActionCtx, PgpMode } from "./types";
import { ACTIONS } from "./definitions";
import { findByShortcut, visibleActions } from "./registry";

function fakeCtx(overrides: Partial<ActionCtx> = {}): ActionCtx {
  const noop = () => undefined;
  return {
    tab: "workspace",
    mode: "encrypt",
    hasInput: false,
    hasOutput: false,
    masterUnlocked: true,
    historyEnabled: false,
    counts: { ownKeys: 0, contacts: 0 },
    navigation: {
      setTab: noop,
      openHistory: noop,
      openGenerate: noop,
      openImport: noop,
      setMode: noop,
    },
    ops: {
      execute: noop,
      clearInput: noop,
      copyOutput: noop,
      lockNow: noop,
    },
    ...overrides,
  };
}

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

function byId(ctx: ActionCtx, id: string) {
  return visibleActions(ACTIONS, ctx).find((r) => r.action.id === id);
}

describe("action ids", () => {
  // Ids are stable identities (see PgpAction.id): this test guards
  // against accidental duplicates, mirroring Linear's rootActions test.
  it("are unique", () => {
    const ids = ACTIONS.map((a) => a.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("are non-empty dot-namespaced strings", () => {
    for (const a of ACTIONS) {
      expect(a.id).toMatch(/^[a-z][a-z-]*(\.[a-z][a-z-]*)+$/);
    }
  });
});

describe("workspace.run", () => {
  it("names itself after the current mode", () => {
    expect(byId(fakeCtx({ mode: "encrypt" }), "workspace.run")?.name).toBe(
      "Run Encrypt",
    );
    expect(byId(fakeCtx({ mode: "verify" }), "workspace.run")?.name).toBe(
      "Run Verify",
    );
  });

  it("explains itself per mode when there is no input", () => {
    const reason = (mode: PgpMode) =>
      byId(fakeCtx({ mode }), "workspace.run")?.disabledReason;
    expect(reason("encrypt")).toBe(
      "Nothing to encrypt - add text or drop a file",
    );
    expect(reason("decrypt")).toContain("Nothing to decrypt");
    expect(reason("sign")).toContain("Nothing to sign");
    expect(reason("verify")).toContain("Nothing to verify");
  });

  it("is enabled with input and runs ops.execute", () => {
    const execute = vi.fn();
    const ctx = fakeCtx({ hasInput: true });
    ctx.ops.execute = execute;
    const run = byId(ctx, "workspace.run");
    expect(run?.disabledReason).toBeUndefined();
    void run?.action.execute(ctx);
    expect(execute).toHaveBeenCalledOnce();
  });

  it("only applies on the workspace tab", () => {
    expect(byId(fakeCtx({ tab: "keys" }), "workspace.run")).toBeUndefined();
  });
});

describe("disabled reasons", () => {
  it("copy-output requires output", () => {
    expect(byId(fakeCtx(), "workspace.copy-output")?.disabledReason).toBe(
      "No output to copy yet",
    );
    expect(
      byId(fakeCtx({ hasOutput: true }), "workspace.copy-output")
        ?.disabledReason,
    ).toBeUndefined();
  });

  it("clear requires something to clear", () => {
    expect(byId(fakeCtx(), "workspace.clear")?.disabledReason).toBe(
      "Nothing to clear",
    );
    expect(
      byId(fakeCtx({ hasInput: true }), "workspace.clear")?.disabledReason,
    ).toBeUndefined();
    expect(
      byId(fakeCtx({ hasOutput: true }), "workspace.clear")?.disabledReason,
    ).toBeUndefined();
  });

  it("history explains how to turn itself on", () => {
    expect(byId(fakeCtx(), "history.open")?.disabledReason).toBe(
      "History is off - enable it next to Sign",
    );
    expect(
      byId(fakeCtx({ historyEnabled: true }), "history.open")?.disabledReason,
    ).toBeUndefined();
  });
});

describe("navigation actions", () => {
  it("hide the tab you are already on", () => {
    const onKeys = visibleActions(ACTIONS, fakeCtx({ tab: "keys" })).map(
      (r) => r.action.id,
    );
    expect(onKeys).not.toContain("nav.keys");
    expect(onKeys).toContain("nav.workspace");
    expect(onKeys).toContain("nav.settings");
  });
});

describe("mode shortcuts", () => {
  it("mod+1..4 map to the four modes via the registry", () => {
    const modes: [string, string][] = [
      ["1", "mode.encrypt"],
      ["2", "mode.decrypt"],
      ["3", "mode.sign"],
      ["4", "mode.verify"],
    ];
    for (const [digit, id] of modes) {
      const hit = findByShortcut(
        ACTIONS,
        keydown({ key: digit, metaKey: true }),
        fakeCtx({ tab: "settings" }),
        true,
      );
      expect(hit?.action.id).toBe(id);
      expect(hit?.disabledReason).toBeUndefined();
    }
  });

  it("switching mode jumps to the workspace tab", () => {
    const setTab = vi.fn();
    const setMode = vi.fn();
    const ctx = fakeCtx({ tab: "keys" });
    ctx.navigation.setTab = setTab;
    ctx.navigation.setMode = setMode;
    const sign = ACTIONS.find((a) => a.id === "mode.sign");
    void sign?.execute(ctx);
    expect(setTab).toHaveBeenCalledWith("workspace");
    expect(setMode).toHaveBeenCalledWith("sign");
  });
});

describe("shortcut dispatch through the registry", () => {
  it("returns run's reason when mod+Enter fires with no input", () => {
    const hit = findByShortcut(
      ACTIONS,
      keydown({ key: "Enter", metaKey: true }),
      fakeCtx(),
      true,
    );
    expect(hit?.action.id).toBe("workspace.run");
    expect(hit?.name).toBe("Run Encrypt");
    expect(hit?.disabledReason).toBe(
      "Nothing to encrypt - add text or drop a file",
    );
  });

  it("does not match workspace shortcuts on other tabs", () => {
    const hit = findByShortcut(
      ACTIONS,
      keydown({ key: "Enter", metaKey: true }),
      fakeCtx({ tab: "settings" }),
      true,
    );
    expect(hit).toBeNull();
  });

  it("no two applicable actions claim the same shortcut", () => {
    const tabs = ["workspace", "keys", "settings"] as const;
    for (const tab of tabs) {
      const ctx = fakeCtx({ tab });
      const seen = new Set<string>();
      for (const r of visibleActions(ACTIONS, ctx)) {
        const spec = r.action.shortcut;
        if (!spec) continue;
        const sig = `${spec.mod ? "mod+" : ""}${spec.shift ? "shift+" : ""}${spec.alt ? "alt+" : ""}${spec.key.toLowerCase()}`;
        expect(seen.has(sig), `duplicate shortcut ${sig} on ${tab}`).toBe(
          false,
        );
        seen.add(sig);
      }
    }
  });
});
