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

import type { InlineStyle } from "../compose/text-format";
import type { MessageKey } from "../i18n";
import type { ActionCtx, PgpAction, PgpMode } from "./types";
import { languageLabel, translationLanguages } from "../ai/languages";
import { FIND_SHORTCUT, STYLE_SHORTCUTS } from "../compose/shortcuts";
import { t } from "../i18n";

/** What "no input" means per mode, for Run's disabled reason. (A
 *  switch, not a key table: the i18n checker counts only literal keys.) */
function noInputReason(mode: PgpMode): string {
  switch (mode) {
    case "encrypt":
      return t("actions_no_input_encrypt");
    case "decrypt":
      return t("actions_no_input_decrypt");
    case "sign":
      return t("actions_no_input_sign");
    case "verify":
      return t("actions_no_input_verify");
  }
}

const MODE_NAME: Record<PgpMode, MessageKey> = {
  encrypt: "common_encrypt",
  decrypt: "common_decrypt",
  sign: "common_sign",
  verify: "common_verify",
};

const MODES: PgpMode[] = ["encrypt", "decrypt", "sign", "verify"];

/** Palette group headings. `PgpAction.group` is a stable English id
 *  (it doubles as the grouping key and a search term); this is the
 *  label the palette shows for it. Unknown groups render as-is. */
export function groupLabel(group: string): string {
  switch (group) {
    case "Mode":
      return t("actions_group_mode");
    case "Workspace":
      return t("actions_group_workspace");
    case "Keys":
      return t("actions_group_keys");
    case "Navigation":
      return t("actions_group_navigation");
    case "Settings":
      return t("actions_group_settings");
    case "Session":
      return t("actions_group_session");
    case "Message":
      return t("actions_group_message");
    case "Result":
      return t("actions_group_result");
    default:
      return group;
  }
}

/** Palette names of the inline style actions. */
function styleActionName(style: InlineStyle): string {
  switch (style) {
    case "bold":
      return t("actions_style_bold");
    case "italic":
      return t("actions_style_italic");
    case "strike":
      return t("actions_style_strike");
    case "code":
      return t("actions_style_code");
  }
}

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
const modeActions: PgpAction[] = MODES.map((mode) => ({
  id: `mode.${mode}`,
  name: () => t(MODE_NAME[mode]),
  group: "Mode",
  keywords: ["mode", "switch"],
  shortcut: MODE_SHORTCUTS[mode],
  execute: (ctx: ActionCtx) => {
    ctx.navigation.setTab("workspace");
    ctx.navigation.setMode(mode);
  },
}));

/** The message-box tools exist only while prose is being written:
 *  workspace tab, Encrypt or Sign, text box mounted. Elsewhere they are
 *  absent rather than dimmed -- "Bold selection" on the Keys tab is not
 *  a thing the user might want next. */
function composing(ctx: ActionCtx): boolean {
  return ctx.tab === "workspace" && ctx.compose.canEdit;
}

/** Bold / italic / strikethrough / code on the message selection. The
 *  shortcuts are dispatched from here (the registry), so the toolbar
 *  binds none of its own. */
const styleActions: PgpAction[] = (
  Object.keys(STYLE_SHORTCUTS) as InlineStyle[]
).map((style) => ({
  id: `compose.${style}`,
  name: () => styleActionName(style),
  group: "Message",
  keywords: ["format", "style", "text", style],
  shortcut: STYLE_SHORTCUTS[style],
  applicable: composing,
  execute: (ctx) => ctx.ops.applyStyle(style),
}));

export const ACTIONS: readonly PgpAction[] = [
  ...modeActions,

  {
    id: "workspace.run",
    name: (ctx) => t("actions_run_mode", { mode: t(MODE_NAME[ctx.mode]) }),
    group: "Workspace",
    keywords: ["go", "execute", "submit"],
    shortcut: { mod: true, key: "Enter" },
    // Workspace actions stay visible on other tabs with a reason (not
    // hidden via `applicable`): a dimmed "Switch to Workspace first" is
    // discoverable; a vanished action looks like it doesn't exist.
    disabledReason: (ctx) => {
      if (ctx.tab !== "workspace")
        return t("actions_switch_to_workspace_first");
      if (!ctx.hasInput) return noInputReason(ctx.mode);
      if (ctx.mode === "encrypt" && !ctx.canEncrypt)
        return t("actions_need_recipient_or_password");
      return undefined;
    },
    execute: (ctx) => ctx.ops.execute(),
  },
  {
    id: "workspace.copy-output",
    name: () => t("actions_copy_output"),
    group: "Workspace",
    keywords: ["clipboard", "result"],
    shortcut: COPY_SHORTCUT,
    disabledReason: (ctx) => {
      if (ctx.tab !== "workspace")
        return t("actions_switch_to_workspace_first");
      return ctx.hasOutput ? undefined : t("actions_no_output_to_copy");
    },
    execute: (ctx) => ctx.ops.copyOutput(),
  },
  {
    id: "workspace.download",
    name: () => t("actions_download_output"),
    group: "Workspace",
    keywords: ["save", "file", "export"],
    shortcut: DOWNLOAD_SHORTCUT,
    disabledReason: (ctx) => {
      if (ctx.tab !== "workspace")
        return t("actions_switch_to_workspace_first");
      return ctx.hasDownload ? undefined : t("actions_nothing_to_download");
    },
    execute: (ctx) => ctx.ops.downloadOutput(),
  },
  {
    id: "workspace.clear",
    name: () => t("actions_clear_input"),
    group: "Workspace",
    keywords: ["reset", "empty"],
    disabledReason: (ctx) => {
      if (ctx.tab !== "workspace")
        return t("actions_switch_to_workspace_first");
      return ctx.hasInput || ctx.hasOutput
        ? undefined
        : t("actions_nothing_to_clear");
    },
    execute: (ctx) => ctx.ops.clearInput(),
  },
  {
    id: "history.open",
    name: () => t("actions_open_history"),
    group: "Workspace",
    keywords: ["log", "past", "operations"],
    disabledReason: (ctx) => {
      if (ctx.historyEnabled) return undefined;
      // Under never-cache the checkbox itself is unavailable, so
      // "enable it next to Sign" would point at nothing.
      return ctx.neverCacheKeys
        ? t("actions_history_off_never_cache")
        : t("actions_history_off_reason");
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
      ctx.encryptToSelf
        ? t("actions_encrypt_to_self_off")
        : t("actions_encrypt_to_self_on"),
    group: "Workspace",
    keywords: ["toggle", "self", "own key", "preference"],
    disabledReason: (ctx) =>
      ctx.counts.ownKeys === 0 ? t("actions_add_own_key_first") : undefined,
    execute: (ctx) => ctx.ops.toggleEncryptToSelf(),
  },
  {
    id: "workspace.toggle-sign",
    name: (ctx) =>
      ctx.alsoSign
        ? t("actions_sign_when_encrypting_off")
        : t("actions_sign_when_encrypting_on"),
    group: "Workspace",
    keywords: ["toggle", "signature", "preference"],
    disabledReason: (ctx) => {
      // Checked BEFORE the own-keys count: with SSH recipients selected,
      // "add one of your own keys first" would be the wrong advice --
      // no key of any kind makes an age message signable.
      if (ctx.encryptEngine === "ssh") {
        return t("actions_age_cannot_sign");
      }
      return ctx.counts.ownKeys === 0
        ? t("actions_add_own_key_first")
        : undefined;
    },
    execute: (ctx) => ctx.ops.toggleAlsoSign(),
  },
  {
    id: "workspace.toggle-history",
    name: (ctx) =>
      ctx.historyEnabled
        ? t("actions_save_to_history_off")
        : t("actions_save_to_history_on"),
    group: "Workspace",
    keywords: ["toggle", "log", "preference"],
    disabledReason: (ctx) =>
      ctx.neverCacheKeys ? t("actions_history_off_never_cache") : undefined,
    execute: (ctx) => ctx.ops.toggleSaveToHistory(),
  },

  {
    id: "keys.generate",
    name: () => t("actions_generate_key"),
    group: "Keys",
    keywords: ["new", "create", "keypair"],
    execute: (ctx) => ctx.navigation.openGenerate(),
  },
  {
    id: "keys.import",
    name: () => t("actions_import_key"),
    group: "Keys",
    keywords: ["add", "paste", "armored"],
    execute: (ctx) => ctx.navigation.openImport(),
  },

  {
    id: "nav.workspace",
    name: () => t("actions_go_to_workspace"),
    group: "Navigation",
    keywords: ["tab", "main"],
    applicable: (ctx) => ctx.tab !== "workspace",
    execute: (ctx) => ctx.navigation.setTab("workspace"),
  },
  {
    id: "nav.keys",
    name: () => t("actions_go_to_keys"),
    group: "Navigation",
    keywords: ["tab", "contacts"],
    applicable: (ctx) => ctx.tab !== "keys",
    execute: (ctx) => ctx.navigation.setTab("keys"),
  },
  {
    id: "nav.settings",
    name: () => t("actions_go_to_settings"),
    group: "Navigation",
    keywords: ["tab", "preferences"],
    applicable: (ctx) => ctx.tab !== "settings",
    execute: (ctx) => ctx.navigation.setTab("settings"),
  },

  {
    id: "settings.security-presets",
    name: () => t("actions_open_security_presets"),
    group: "Settings",
    keywords: ["preset", "paranoid", "convenient", "balanced", "security"],
    execute: (ctx) => ctx.navigation.openSecurityPresets(),
  },

  {
    id: "session.lock",
    name: () => t("actions_lock_now"),
    group: "Session",
    keywords: ["logout", "secure", "close"],
    execute: (ctx) => ctx.ops.lockNow(),
  },

  ...styleActions,
  {
    id: "compose.find",
    name: () => t("actions_find_replace"),
    group: "Message",
    keywords: ["search", "replace", "find"],
    shortcut: FIND_SHORTCUT,
    applicable: composing,
    execute: (ctx) => ctx.ops.openFind(),
  },
  {
    // Two steps: pick the action, then the language. The last-picked
    // language is listed first so a repeat is Enter, Enter.
    id: "compose.translate",
    name: () => t("actions_translate_message"),
    group: "Message",
    keywords: ["translate", "translation", "language"],
    applicable: composing,
    disabledReason: (ctx) => {
      if (!ctx.compose.translateEnabled) return t("actions_translation_off");
      if (!ctx.hasInput) return t("actions_nothing_to_translate");
      return undefined;
    },
    pick: (ctx) => {
      const last = ctx.compose.translateTarget;
      const options = translationLanguages().map((l) => ({
        id: l.code,
        label:
          l.code === last
            ? t("actions_language_last_used", { label: l.label })
            : l.label,
        keywords: [l.code],
      }));
      return {
        title: t("actions_translate_to_title"),
        placeholder: t("actions_pick_language_placeholder"),
        options: last
          ? [
              ...options.filter((o) => o.id === last),
              ...options.filter((o) => o.id !== last),
            ]
          : options,
      };
    },
    execute: (ctx, picked) => {
      if (picked) ctx.ops.translateTo(picked);
    },
  },
  {
    // The result side has one direction only -- into the language the
    // user reads -- so it is one entry, no picker, present only while a
    // decrypted or verified message is on screen.
    id: "result.translate",
    name: (ctx) =>
      t("actions_translate_result_to", {
        language: languageLabel(ctx.result.readingLanguage),
      }),
    group: "Result",
    keywords: ["translate", "translation", "language", "decrypted"],
    applicable: (ctx) => ctx.tab === "workspace" && ctx.result.canTranslate,
    execute: (ctx) => ctx.ops.translateOutput(),
  },
];
