import { describe, expect, it } from "vitest";

import type { ShortcutKeyEvent } from "../shortcuts";
import type { ActionCtx, PgpAction } from "./types";
import {
  filterActions,
  findByShortcut,
  groupActions,
  visibleActions,
} from "./registry";
import { actionName } from "./types";

/** A ctx where nothing is loaded and nothing is possible. */
function fakeCtx(overrides: Partial<ActionCtx> = {}): ActionCtx {
  const noop = () => undefined;
  return {
    tab: "workspace",
    mode: "encrypt",
    hasInput: false,
    hasRecipients: true,
    hasOutput: false,
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

const ALWAYS: PgpAction = {
  id: "test.always",
  name: "Always",
  group: "A",
  execute: () => undefined,
};

const WORKSPACE_ONLY: PgpAction = {
  id: "test.workspace-only",
  name: "Workspace only",
  group: "B",
  applicable: (ctx) => ctx.tab === "workspace",
  execute: () => undefined,
};

const NEEDS_INPUT: PgpAction = {
  id: "test.needs-input",
  name: (ctx) => `Run ${ctx.mode}`,
  group: "B",
  shortcut: { mod: true, key: "Enter" },
  disabledReason: (ctx) => (ctx.hasInput ? undefined : "Nothing to run"),
  execute: () => undefined,
};

const FAKE_ACTIONS = [ALWAYS, WORKSPACE_ONLY, NEEDS_INPUT];

describe("visibleActions", () => {
  it("includes actions without an applicable predicate", () => {
    const ids = visibleActions(FAKE_ACTIONS, fakeCtx()).map((r) => r.action.id);
    expect(ids).toContain("test.always");
  });

  it("filters out inapplicable actions", () => {
    const ids = visibleActions(FAKE_ACTIONS, fakeCtx({ tab: "keys" })).map(
      (r) => r.action.id,
    );
    expect(ids).not.toContain("test.workspace-only");
    expect(ids).toContain("test.always");
  });

  it("keeps disabled actions visible WITH their reason", () => {
    const resolved = visibleActions(FAKE_ACTIONS, fakeCtx());
    const needsInput = resolved.find((r) => r.action.id === "test.needs-input");
    expect(needsInput?.disabledReason).toBe("Nothing to run");
  });

  it("reports no reason once the action becomes runnable", () => {
    const resolved = visibleActions(FAKE_ACTIONS, fakeCtx({ hasInput: true }));
    const needsInput = resolved.find((r) => r.action.id === "test.needs-input");
    expect(needsInput?.disabledReason).toBeUndefined();
  });

  it("resolves dynamic names against the ctx", () => {
    const resolved = visibleActions(FAKE_ACTIONS, fakeCtx({ mode: "sign" }));
    const needsInput = resolved.find((r) => r.action.id === "test.needs-input");
    expect(needsInput?.name).toBe("Run sign");
  });
});

describe("findByShortcut", () => {
  const modEnter = keydown({ key: "Enter", metaKey: true });

  it("matches an enabled action's shortcut", () => {
    const hit = findByShortcut(
      FAKE_ACTIONS,
      modEnter,
      fakeCtx({ hasInput: true }),
      true,
    );
    expect(hit?.action.id).toBe("test.needs-input");
    expect(hit?.disabledReason).toBeUndefined();
  });

  it("returns a disabled action together with its reason", () => {
    const hit = findByShortcut(FAKE_ACTIONS, modEnter, fakeCtx(), true);
    expect(hit?.action.id).toBe("test.needs-input");
    expect(hit?.disabledReason).toBe("Nothing to run");
  });

  it("does not match inapplicable actions", () => {
    const gated: PgpAction = {
      ...NEEDS_INPUT,
      applicable: () => false,
    };
    expect(findByShortcut([gated], modEnter, fakeCtx(), true)).toBeNull();
  });

  it("returns null when nothing matches", () => {
    const hit = findByShortcut(
      FAKE_ACTIONS,
      keydown({ key: "k", metaKey: true }),
      fakeCtx(),
      true,
    );
    expect(hit).toBeNull();
  });

  it("respects the mod key per platform", () => {
    const ctrlEnter = keydown({ key: "Enter", ctrlKey: true });
    expect(findByShortcut(FAKE_ACTIONS, ctrlEnter, fakeCtx(), true)).toBeNull();
    expect(
      findByShortcut(FAKE_ACTIONS, ctrlEnter, fakeCtx(), false)?.action.id,
    ).toBe("test.needs-input");
  });
});

describe("filterActions", () => {
  const resolved = visibleActions(FAKE_ACTIONS, fakeCtx());

  it("returns everything for an empty query", () => {
    expect(filterActions(resolved, "")).toHaveLength(resolved.length);
    expect(filterActions(resolved, "   ")).toHaveLength(resolved.length);
  });

  it("matches case-insensitively on the resolved name", () => {
    const hits = filterActions(resolved, "ALWAYS");
    expect(hits.map((r) => r.action.id)).toEqual(["test.always"]);
  });

  it("matches on keywords", () => {
    const withKeywords = visibleActions(
      [{ ...ALWAYS, keywords: ["palette", "menu"] }],
      fakeCtx(),
    );
    expect(filterActions(withKeywords, "menu")).toHaveLength(1);
    expect(filterActions(withKeywords, "nope")).toHaveLength(0);
  });

  it("requires every token to match", () => {
    expect(filterActions(resolved, "run encrypt")).toHaveLength(1);
    expect(filterActions(resolved, "run banana")).toHaveLength(0);
  });
});

describe("groupActions", () => {
  it("groups in first-seen order", () => {
    const grouped = groupActions(visibleActions(FAKE_ACTIONS, fakeCtx()));
    expect(grouped.map((g) => g.group)).toEqual(["A", "B"]);
    expect(grouped[1].items).toHaveLength(2);
  });
});

describe("actionName", () => {
  it("passes static names through", () => {
    expect(actionName(ALWAYS, fakeCtx())).toBe("Always");
  });

  it("invokes dynamic names with the ctx", () => {
    expect(actionName(NEEDS_INPUT, fakeCtx({ mode: "verify" }))).toBe(
      "Run verify",
    );
  });
});
