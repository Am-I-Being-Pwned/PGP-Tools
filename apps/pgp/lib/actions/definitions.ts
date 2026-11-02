// Command palette + global shortcut actions. Ids are stable forever.
// Destructive ops (key/contact deletion, history clearing) are deliberately
// NOT actions: they keep confirmation pages, out of reach of a stray Enter.
// "Set default key" is excluded too: an implicit "current" key would
// silently retarget "encrypt to me".

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";

import type { InlineStyle } from "../compose/text-format";
import type { MessageKey } from "../i18n";
import type { ActionCtx, PgpAction, PgpMode } from "./types";
import { languageLabel, translationLanguages } from "../ai/languages";
import { FIND_SHORTCUT, STYLE_SHORTCUTS } from "../compose/shortcuts";
import { t } from "../i18n";

/** A switch, not a key table: the i18n checker counts only literal keys. */
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

/** Display label for a stable English `PgpAction.group` id. */
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

// Shortcut specs are exported so Kbd hints and the shortcuts reference
// share the exact spec with the registry and can't drift.
export const PALETTE_SHORTCUT: ShortcutSpec = { mod: true, key: "k" };

export const COPY_SHORTCUT: ShortcutSpec = { mod: true, shift: true, key: "c" };

/** Chrome's "bookmark all tabs"; intercepted only while the panel has focus. */
export const DOWNLOAD_SHORTCUT: ShortcutSpec = {
  mod: true,
  shift: true,
  key: "d",
};

/** Chrome's hard reload; intercepted only while the panel has focus. */
export const REPLY_SHORTCUT: ShortcutSpec = {
  mod: true,
  shift: true,
  key: "r",
};

export const MODE_SHORTCUTS: Record<PgpMode, ShortcutSpec> = {
  encrypt: { mod: true, key: "1" },
  decrypt: { mod: true, key: "2" },
  sign: { mod: true, key: "3" },
  verify: { mod: true, key: "4" },
};

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

/** Message-box tools are absent (not dimmed) unless prose is being written. */
function composing(ctx: ActionCtx): boolean {
  return ctx.tab === "workspace" && ctx.compose.canEdit;
}

/** The registry dispatches these shortcuts; the toolbar binds none. */
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
    // Dimmed with a reason on other tabs, not hidden, so it stays discoverable.
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
      return ctx.neverCacheKeys
        ? t("actions_history_off_never_cache")
        : t("actions_history_off_reason");
    },
    execute: (ctx) => ctx.navigation.openHistory(),
  },

  // Preference toggles: names show the RESULTING state; handlers are the
  // checkboxes' own (persistence + stale-output reset).
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
      // Before the own-keys check: no key makes an age message signable.
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
    // Last-picked language first, so a repeat is Enter, Enter.
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
    // One direction only (into the reading language), so no picker.
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
  {
    id: "result.reply",
    name: () => t("actions_reply_to_signer"),
    group: "Result",
    keywords: ["reply", "respond", "answer", "write back"],
    shortcut: REPLY_SHORTCUT,
    applicable: (ctx) => ctx.tab === "workspace" && ctx.result.canReply,
    execute: (ctx) => ctx.ops.reply(),
  },
];
