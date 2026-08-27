import { describe, expect, it, vi } from "vitest";

import type { ShortcutKeyEvent } from "../shortcuts";
import type { ActionCtx, PgpMode } from "./types";
import { ACTIONS, MODE_SHORTCUTS } from "./definitions";
import { findByShortcut, visibleActions } from "./registry";

function fakeCtx(overrides: Partial<ActionCtx> = {}): ActionCtx {
  const noop = () => undefined;
  return {
    tab: "workspace",
    mode: "encrypt",
    hasInput: false,
    canEncrypt: true,
    encryptEngine: "pgp",
    hasOutput: false,
    hasDownload: false,
    masterUnlocked: true,
    historyEnabled: false,
    encryptToSelf: false,
    alsoSign: false,
    neverCacheKeys: false,
    counts: { ownKeys: 0, contacts: 0 },
    navigation: {
      setTab: noop,
      openHistory: noop,
      openGenerate: noop,
      openImport: noop,
      setMode: noop,
      openSecurityPresets: noop,
    },
    ops: {
      execute: noop,
      clearInput: noop,
      copyOutput: noop,
      downloadOutput: noop,
      lockNow: noop,
      toggleEncryptToSelf: noop,
      toggleAlsoSign: noop,
      toggleSaveToHistory: noop,
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
  // against accidental duplicates.
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

  it("requires someone who can open the result, in encrypt mode only", () => {
    const reason = (mode: PgpMode) =>
      byId(
        fakeCtx({ mode, hasInput: true, canEncrypt: false }),
        "workspace.run",
      )?.disabledReason;
    expect(reason("encrypt")).toBe(
      "Select at least one recipient, or set a password",
    );
    expect(reason("decrypt")).toBeUndefined();
    expect(reason("sign")).toBeUndefined();
    expect(reason("verify")).toBeUndefined();
  });

  it("runs a password-only encrypt, with no recipients at all", () => {
    // REGRESSION. `canEncrypt` was `hasRecipients`, and symmetric
    // encryption added a second way to satisfy the gate without this
    // context field learning about it. The BUTTON was updated and this
    // was not, so the palette and the mod+Enter shortcut refused a
    // message the button beside them would happily encrypt -- reported
    // from the running app, as a toast reading "Run Encrypt is disabled:
    // Select at least one recipient" over an armed Password badge.
    const action = byId(
      fakeCtx({ mode: "encrypt", hasInput: true, canEncrypt: true }),
      "workspace.run",
    );
    expect(action?.disabledReason).toBeUndefined();
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

  it("stays visible on other tabs with a tab-switch reason", () => {
    // hasInput is irrelevant off-tab: the tab reason wins.
    const run = byId(fakeCtx({ tab: "keys", hasInput: true }), "workspace.run");
    expect(run?.disabledReason).toBe("Switch to Workspace first");
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

  it("download requires something downloadable", () => {
    expect(byId(fakeCtx(), "workspace.download")?.disabledReason).toBe(
      "Nothing to download yet",
    );
    expect(
      byId(fakeCtx({ hasDownload: true }), "workspace.download")
        ?.disabledReason,
    ).toBeUndefined();
  });

  it("copy-output, download and clear explain the tab switch on other tabs", () => {
    const ids = [
      "workspace.copy-output",
      "workspace.download",
      "workspace.clear",
    ];
    for (const id of ids) {
      expect(
        byId(
          fakeCtx({ tab: "settings", hasOutput: true, hasDownload: true }),
          id,
        )?.disabledReason,
      ).toBe("Switch to Workspace first");
    }
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

describe("preference toggles", () => {
  it("name the resulting state, not the current one", () => {
    expect(
      byId(fakeCtx({ encryptToSelf: true }), "workspace.toggle-encrypt-to-self")
        ?.name,
    ).toBe("Turn off: Also encrypt to me");
    expect(byId(fakeCtx(), "workspace.toggle-encrypt-to-self")?.name).toBe(
      "Turn on: Also encrypt to me",
    );
    expect(
      byId(fakeCtx({ alsoSign: true }), "workspace.toggle-sign")?.name,
    ).toBe("Turn off: Sign when encrypting");
    expect(
      byId(fakeCtx({ historyEnabled: true }), "workspace.toggle-history")?.name,
    ).toBe("Turn off: Save to history");
  });

  it("encrypt toggles need an own key", () => {
    for (const id of [
      "workspace.toggle-encrypt-to-self",
      "workspace.toggle-sign",
    ]) {
      expect(byId(fakeCtx(), id)?.disabledReason).toBe(
        "Add one of your own keys first",
      );
      expect(
        byId(fakeCtx({ counts: { ownKeys: 1, contacts: 0 } }), id)
          ?.disabledReason,
      ).toBeUndefined();
    }
  });

  it("sign toggle explains the FORMAT before the key count for age", () => {
    // With SSH recipients selected there is no key of any kind that
    // would make the message signable, so "add one of your own keys
    // first" would send the user off to do something pointless.
    const age = { encryptEngine: "ssh" as const };
    expect(byId(fakeCtx(age), "workspace.toggle-sign")?.disabledReason).toBe(
      "age messages can't be signed",
    );
    expect(
      byId(
        fakeCtx({ ...age, counts: { ownKeys: 3, contacts: 0 } }),
        "workspace.toggle-sign",
      )?.disabledReason,
    ).toBe("age messages can't be signed");
    // Encrypt-to-self is untouched: the user's own SSH key CAN ride
    // along on an age message.
    expect(
      byId(
        fakeCtx({ ...age, counts: { ownKeys: 1, contacts: 0 } }),
        "workspace.toggle-encrypt-to-self",
      )?.disabledReason,
    ).toBeUndefined();
  });

  it("history toggle is unavailable under never-cache", () => {
    expect(
      byId(fakeCtx({ neverCacheKeys: true }), "workspace.toggle-history")
        ?.disabledReason,
    ).toBe("History is off while keys never cache");
    expect(
      byId(fakeCtx(), "workspace.toggle-history")?.disabledReason,
    ).toBeUndefined();
  });

  it("run the ops bridge callbacks", () => {
    const ctx = fakeCtx({ counts: { ownKeys: 1, contacts: 0 } });
    const spies = {
      toggleEncryptToSelf: vi.fn(),
      toggleAlsoSign: vi.fn(),
      toggleSaveToHistory: vi.fn(),
    };
    Object.assign(ctx.ops, spies);
    void byId(ctx, "workspace.toggle-encrypt-to-self")?.action.execute(ctx);
    void byId(ctx, "workspace.toggle-sign")?.action.execute(ctx);
    void byId(ctx, "workspace.toggle-history")?.action.execute(ctx);
    for (const spy of Object.values(spies)) expect(spy).toHaveBeenCalledOnce();
  });
});

describe("history.open reasons", () => {
  it("distinguishes never-cache from the plain off state", () => {
    expect(
      byId(fakeCtx({ neverCacheKeys: true }), "history.open")?.disabledReason,
    ).toBe("History is off while keys never cache");
    expect(byId(fakeCtx(), "history.open")?.disabledReason).toBe(
      "History is off - enable it next to Sign",
    );
  });
});

describe("settings.security-presets", () => {
  it("opens the presets subpage via navigation", () => {
    const openSecurityPresets = vi.fn();
    const ctx = fakeCtx();
    ctx.navigation.openSecurityPresets = openSecurityPresets;
    void byId(ctx, "settings.security-presets")?.action.execute(ctx);
    expect(openSecurityPresets).toHaveBeenCalledOnce();
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

  // Drift guard: the mode dropdown renders its Kbd hints from
  // MODE_SHORTCUTS, while keydown dispatch goes through each action's
  // `shortcut`. Both must stay the same object per mode.
  it("MODE_SHORTCUTS matches the registry's mode actions", () => {
    for (const mode of ["encrypt", "decrypt", "sign", "verify"] as const) {
      const action = ACTIONS.find((a) => a.id === `mode.${mode}`);
      expect(action?.shortcut).toEqual(MODE_SHORTCUTS[mode]);
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

  it("matches workspace shortcuts on other tabs, disabled with the tab reason", () => {
    const hit = findByShortcut(
      ACTIONS,
      keydown({ key: "Enter", metaKey: true }),
      fakeCtx({ tab: "settings", hasInput: true }),
      true,
    );
    expect(hit?.action.id).toBe("workspace.run");
    expect(hit?.disabledReason).toBe("Switch to Workspace first");
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
