// The action list behind the command palette and global shortcuts.
//
// Ids are stable forever (see PgpAction.id). Destructive/irreversible
// operations -- key deletion, contact deletion, history clearing -- are
// deliberately NOT palette actions in v1: they keep their dedicated
// confirmation pages, out of reach of a stray Enter in a fuzzy matcher.

import type { ActionCtx, PgpAction, PgpMode } from "./types";

/** What "no input" means per mode, for Run's disabled reason. */
const NO_INPUT_REASON: Record<PgpMode, string> = {
  encrypt: "Nothing to encrypt - add text or drop a file",
  decrypt: "Nothing to decrypt - paste a PGP message or drop a file",
  sign: "Nothing to sign - add text or drop a file",
  verify: "Nothing to verify - paste a signed message or drop a file",
};

const MODES: { mode: PgpMode; name: string; digit: string }[] = [
  { mode: "encrypt", name: "Encrypt", digit: "1" },
  { mode: "decrypt", name: "Decrypt", digit: "2" },
  { mode: "sign", name: "Sign", digit: "3" },
  { mode: "verify", name: "Verify", digit: "4" },
];

/** Switch the workspace to a mode (jumping to the tab if needed). */
const modeActions: PgpAction[] = MODES.map(({ mode, name, digit }) => ({
  id: `mode.${mode}`,
  name,
  group: "Mode",
  keywords: ["mode", "switch"],
  shortcut: { mod: true, key: digit },
  execute: (ctx: ActionCtx) => {
    ctx.navigation.setTab("workspace");
    ctx.navigation.setMode(mode);
  },
}));

export const ACTIONS: readonly PgpAction[] = [
  ...modeActions,

  {
    id: "workspace.run",
    name: (ctx) =>
      `Run ${MODES.find((m) => m.mode === ctx.mode)?.name ?? ctx.mode}`,
    group: "Workspace",
    keywords: ["go", "execute", "submit"],
    shortcut: { mod: true, key: "Enter" },
    applicable: (ctx) => ctx.tab === "workspace",
    disabledReason: (ctx) => {
      if (!ctx.hasInput) return NO_INPUT_REASON[ctx.mode];
      if (ctx.mode === "encrypt" && !ctx.hasRecipients)
        return "Select at least one recipient";
      return undefined;
    },
    execute: (ctx) => ctx.ops.execute(),
  },
  {
    id: "workspace.copy-output",
    name: "Copy output",
    group: "Workspace",
    keywords: ["clipboard", "result"],
    shortcut: { mod: true, shift: true, key: "c" },
    applicable: (ctx) => ctx.tab === "workspace",
    disabledReason: (ctx) =>
      ctx.hasOutput ? undefined : "No output to copy yet",
    execute: (ctx) => ctx.ops.copyOutput(),
  },
  {
    id: "workspace.clear",
    name: "Clear input",
    group: "Workspace",
    keywords: ["reset", "empty"],
    applicable: (ctx) => ctx.tab === "workspace",
    disabledReason: (ctx) =>
      ctx.hasInput || ctx.hasOutput ? undefined : "Nothing to clear",
    execute: (ctx) => ctx.ops.clearInput(),
  },
  {
    id: "history.open",
    name: "Open history",
    group: "Workspace",
    keywords: ["log", "past", "operations"],
    disabledReason: (ctx) =>
      ctx.historyEnabled
        ? undefined
        : "History is off - enable it next to Sign",
    execute: (ctx) => ctx.navigation.openHistory(),
  },

  {
    id: "keys.generate",
    name: "Generate key",
    group: "Keys",
    keywords: ["new", "create", "keypair"],
    execute: (ctx) => ctx.navigation.openGenerate(),
  },
  {
    id: "keys.import",
    name: "Import key",
    group: "Keys",
    keywords: ["add", "paste", "armored"],
    execute: (ctx) => ctx.navigation.openImport(),
  },

  {
    id: "nav.workspace",
    name: "Go to Workspace",
    group: "Navigation",
    keywords: ["tab", "main"],
    applicable: (ctx) => ctx.tab !== "workspace",
    execute: (ctx) => ctx.navigation.setTab("workspace"),
  },
  {
    id: "nav.keys",
    name: "Go to Keys",
    group: "Navigation",
    keywords: ["tab", "contacts"],
    applicable: (ctx) => ctx.tab !== "keys",
    execute: (ctx) => ctx.navigation.setTab("keys"),
  },
  {
    id: "nav.settings",
    name: "Go to Settings",
    group: "Navigation",
    keywords: ["tab", "preferences"],
    applicable: (ctx) => ctx.tab !== "settings",
    execute: (ctx) => ctx.navigation.setTab("settings"),
  },

  {
    id: "session.lock",
    name: "Lock now",
    group: "Session",
    keywords: ["logout", "secure", "close"],
    execute: (ctx) => ctx.ops.lockNow(),
  },
];
