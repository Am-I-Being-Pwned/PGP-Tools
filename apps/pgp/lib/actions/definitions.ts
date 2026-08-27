// The action list behind the command palette and global shortcuts.
//
// Ids are stable forever (see PgpAction.id). Destructive/irreversible
// operations -- key deletion, contact deletion, history clearing -- are
// deliberately NOT palette actions in v1: they keep their dedicated
// confirmation pages, out of reach of a stray Enter in a fuzzy matcher.
//
// "Set default key" is also deliberately excluded: picking WHICH key
// needs a second-step key list, and the palette has no submenu surface
// (one flat list, one Enter). Executing it with an implicit "current"
// key would silently retarget "encrypt to me". It stays on the key
// cards in the Keys tab until the palette grows a picker step.

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";

import type { ActionCtx, PgpAction, PgpMode } from "./types";

/** What "no input" means per mode, for Run's disabled reason. */
const NO_INPUT_REASON: Record<PgpMode, string> = {
  encrypt: "Nothing to encrypt - add text or drop a file",
  decrypt: "Nothing to decrypt - paste an encrypted message or drop a file",
  sign: "Nothing to sign - add text or drop a file",
  verify: "Nothing to verify - paste a signed message or drop a file",
};

const MODES: { mode: PgpMode; name: string }[] = [
  { mode: "encrypt", name: "Encrypt" },
  { mode: "decrypt", name: "Decrypt" },
  { mode: "sign", name: "Sign" },
  { mode: "verify", name: "Verify" },
];

/** mod+K opens the command palette. Lives here (not in the palette
 *  component) so the footer hint and the shortcuts reference can render
 *  it without importing UI code; the palette itself binds it. */
export const PALETTE_SHORTCUT: ShortcutSpec = { mod: true, key: "k" };

/** mod+shift+C copies completed text output. Exported so the copy
 *  button's Kbd chip and the shortcuts reference share this exact
 *  spec with the registry action below. */
export const COPY_SHORTCUT: ShortcutSpec = { mod: true, shift: true, key: "c" };

/** mod+shift+D downloads the completed output. In Chrome this combo is
 *  "bookmark all tabs" -- acceptable to intercept: it only fires while
 *  the extension panel itself has focus, where bookmarking is never
 *  the intent. Exported for the same no-drift reason as COPY_SHORTCUT. */
export const DOWNLOAD_SHORTCUT: ShortcutSpec = {
  mod: true,
  shift: true,
  key: "d",
};

/** The mod+digit shortcut for each workspace mode. Single source of
 *  truth shared by the registry's mode actions (below) and the mode
 *  dropdown's Kbd hints, so the two can never drift. */
export const MODE_SHORTCUTS: Record<PgpMode, ShortcutSpec> = {
  encrypt: { mod: true, key: "1" },
  decrypt: { mod: true, key: "2" },
  sign: { mod: true, key: "3" },
  verify: { mod: true, key: "4" },
};

/** Switch the workspace to a mode (jumping to the tab if needed). */
const modeActions: PgpAction[] = MODES.map(({ mode, name }) => ({
  id: `mode.${mode}`,
  name,
  group: "Mode",
  keywords: ["mode", "switch"],
  shortcut: MODE_SHORTCUTS[mode],
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
    // Workspace actions stay visible on other tabs with a reason (not
    // hidden via `applicable`): a dimmed "Switch to Workspace first" is
    // discoverable; a vanished action looks like it doesn't exist.
    disabledReason: (ctx) => {
      if (ctx.tab !== "workspace") return "Switch to Workspace first";
      if (!ctx.hasInput) return NO_INPUT_REASON[ctx.mode];
      if (ctx.mode === "encrypt" && !ctx.canEncrypt)
        return "Select at least one recipient, or set a password";
      return undefined;
    },
    execute: (ctx) => ctx.ops.execute(),
  },
  {
    id: "workspace.copy-output",
    name: "Copy output",
    group: "Workspace",
    keywords: ["clipboard", "result"],
    shortcut: COPY_SHORTCUT,
    disabledReason: (ctx) => {
      if (ctx.tab !== "workspace") return "Switch to Workspace first";
      return ctx.hasOutput ? undefined : "No output to copy yet";
    },
    execute: (ctx) => ctx.ops.copyOutput(),
  },
  {
    id: "workspace.download",
    name: "Download output",
    group: "Workspace",
    keywords: ["save", "file", "export"],
    shortcut: DOWNLOAD_SHORTCUT,
    disabledReason: (ctx) => {
      if (ctx.tab !== "workspace") return "Switch to Workspace first";
      return ctx.hasDownload ? undefined : "Nothing to download yet";
    },
    execute: (ctx) => ctx.ops.downloadOutput(),
  },
  {
    id: "workspace.clear",
    name: "Clear input",
    group: "Workspace",
    keywords: ["reset", "empty"],
    disabledReason: (ctx) => {
      if (ctx.tab !== "workspace") return "Switch to Workspace first";
      return ctx.hasInput || ctx.hasOutput ? undefined : "Nothing to clear";
    },
    execute: (ctx) => ctx.ops.clearInput(),
  },
  {
    id: "history.open",
    name: "Open history",
    group: "Workspace",
    keywords: ["log", "past", "operations"],
    disabledReason: (ctx) => {
      if (ctx.historyEnabled) return undefined;
      // Under never-cache the checkbox itself is unavailable, so
      // "enable it next to Sign" would point at nothing.
      return ctx.neverCacheKeys
        ? "History is off while keys never cache"
        : "History is off - enable it next to Sign";
    },
    execute: (ctx) => ctx.navigation.openHistory(),
  },

  // ── Preference toggles ─────────────────────────────────────────────
  // Names show the RESULTING state ("Turn off: ..."), so the palette
  // doubles as a readout of where the toggle currently sits. All three
  // reuse the workspace checkboxes' exact handlers (persistence +
  // stale-output reset included) via ctx.ops.
  {
    id: "workspace.toggle-encrypt-to-self",
    name: (ctx) =>
      `${ctx.encryptToSelf ? "Turn off" : "Turn on"}: Also encrypt to me`,
    group: "Workspace",
    keywords: ["toggle", "self", "own key", "preference"],
    disabledReason: (ctx) =>
      ctx.counts.ownKeys === 0 ? "Add one of your own keys first" : undefined,
    execute: (ctx) => ctx.ops.toggleEncryptToSelf(),
  },
  {
    id: "workspace.toggle-sign",
    name: (ctx) =>
      `${ctx.alsoSign ? "Turn off" : "Turn on"}: Sign when encrypting`,
    group: "Workspace",
    keywords: ["toggle", "signature", "preference"],
    disabledReason: (ctx) => {
      // Checked BEFORE the own-keys count: with SSH recipients selected,
      // "add one of your own keys first" would be the wrong advice --
      // no key of any kind makes an age message signable.
      if (ctx.encryptEngine === "ssh") {
        return "age messages can't be signed";
      }
      return ctx.counts.ownKeys === 0
        ? "Add one of your own keys first"
        : undefined;
    },
    execute: (ctx) => ctx.ops.toggleAlsoSign(),
  },
  {
    id: "workspace.toggle-history",
    name: (ctx) =>
      `${ctx.historyEnabled ? "Turn off" : "Turn on"}: Save to history`,
    group: "Workspace",
    keywords: ["toggle", "log", "preference"],
    disabledReason: (ctx) =>
      ctx.neverCacheKeys ? "History is off while keys never cache" : undefined,
    execute: (ctx) => ctx.ops.toggleSaveToHistory(),
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
    id: "settings.security-presets",
    name: "Open security presets",
    group: "Settings",
    keywords: ["preset", "paranoid", "convenient", "balanced", "security"],
    execute: (ctx) => ctx.navigation.openSecurityPresets(),
  },

  {
    id: "session.lock",
    name: "Lock now",
    group: "Session",
    keywords: ["logout", "secure", "close"],
    execute: (ctx) => ctx.ops.lockNow(),
  },
];
