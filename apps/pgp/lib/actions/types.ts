// Framework-free action model: an action is data (id,
// name, grouping, shortcut) plus pure predicates over an ActionCtx the
// app assembles. Nothing in lib/actions imports React -- the UI layer
// (CommandPalette) renders whatever the registry reports.

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";

import type { InlineStyle } from "../compose/text-format";
import type { StoredKeyKind } from "../storage/key-kind";

/** The workspace operation modes (mirrors WorkspaceAction). */
export type PgpMode = "encrypt" | "decrypt" | "sign" | "verify";

/** Top-level tabs of the side panel. */
export type AppTab = "workspace" | "keys" | "settings";

/**
 * Everything an action may read or invoke, assembled by the app in one
 * place (useActionContext). A plain typed bag of data + callbacks so
 * actions stay pure and trivially testable with a fake ctx.
 */
export interface ActionCtx {
  tab: AppTab;
  /** Current workspace mode. */
  mode: PgpMode;
  /** Workspace has text input or dropped files. */
  hasInput: boolean;
  /** Encrypt has SOMEONE who could open the result: at least one
   *  selected recipient, or an armed message password. Only consulted in
   *  encrypt mode; other modes ignore it.
   *
   *  Named for the question rather than for one of its answers. It was
   *  `hasRecipients`, and when password encryption shipped that name
   *  quietly became a lie -- the palette and the mod+Enter shortcut went
   *  on refusing to run a password-only encrypt that the button next to
   *  them was happy to perform. */
  canEncrypt: boolean;
  /** Which engine the current recipient selection encrypts with:
   *  `"pgp"` (OpenPGP), `"ssh"` (age), or null while nothing is
   *  selected. age has no signing operation, so actions about signing
   *  have to know. */
  encryptEngine: StoredKeyKind | null;
  /** A completed operation produced copyable text output. */
  hasOutput: boolean;
  /** A completed operation produced something downloadable (text,
   *  binary, or per-file results) -- broader than hasOutput, which is
   *  text-only. */
  hasDownload: boolean;
  masterUnlocked: boolean;
  /** The "Save to history" preference is on. */
  historyEnabled: boolean;
  /** The "Also encrypt to me" preference is on. */
  encryptToSelf: boolean;
  /** The "Sign when encrypting" preference is on. */
  alsoSign: boolean;
  /** The "Never auto-cache keys" setting is on (history is unavailable
   *  while it is: nothing may persist beyond an operation). */
  neverCacheKeys: boolean;
  counts: {
    ownKeys: number;
    contacts: number;
  };
  /** The result box (a decrypted or verified message on screen). */
  result: {
    /** A readable decrypted/verified message is showing and translation
     *  is on and usable for it. */
    canTranslate: boolean;
    /** BCP 47 tag of the language the user reads (Settings). */
    readingLanguage: string;
  };
  /** The message box's editing tools. */
  compose: {
    /** Prose is being written: workspace tab, encrypt or sign mode, the
     *  text box mounted (no files staged) and no private key pasted. */
    canEdit: boolean;
    /** Translation is on in Settings and this device can do it. */
    translateEnabled: boolean;
    /** The language the user last translated a message into, or null. */
    translateTarget: string | null;
  };
  navigation: {
    setTab: (tab: AppTab) => void;
    openHistory: () => void;
    openGenerate: () => void;
    openImport: () => void;
    setMode: (mode: PgpMode) => void;
    /** Jump to Settings with the security-presets subpage open. */
    openSecurityPresets: () => void;
  };
  ops: {
    /** Run the current workspace mode on the current input. */
    execute: () => void;
    /** Clear workspace input and output. */
    clearInput: () => void;
    /** Copy the completed text output to the clipboard. */
    copyOutput: () => void;
    /** Download the completed output (file results, binary, or text). */
    downloadOutput: () => void;
    /** Master-lock the extension immediately. */
    lockNow: () => void;
    /** Flip "Also encrypt to me" (same handler as the checkbox:
     *  persists the preference and resets stale output). */
    toggleEncryptToSelf: () => void;
    /** Flip "Sign when encrypting" (same handler as the checkbox). */
    toggleAlsoSign: () => void;
    /** Flip "Save to history" (same handler as the checkbox). */
    toggleSaveToHistory: () => void;
    /** Toggle an inline style on the message box's selection. */
    applyStyle: (style: InlineStyle) => void;
    /** Open the message box's find bar. */
    openFind: () => void;
    /** Translate the message into `language` (BCP 47), replacing it. */
    translateTo: (language: string) => void;
    /** Translate the result into the reading language (or show the
     *  translation already made). */
    translateOutput: () => void;
  };
}

/**
 * A palette/shortcut action.
 *
 * `id` is a stable string identity: it must NEVER change once shipped
 * -- ids may end up in user keybinding
 * or telemetry data, so renaming an action means changing `name`, not
 * `id`. Removing an action retires its id forever.
 */
export interface PgpAction {
  id: string;
  /** Display label; a function for names derived from ctx ("Run encrypt"). */
  name: string | ((ctx: ActionCtx) => string);
  /** Extra search terms beyond the name. */
  keywords?: string[];
  /** Palette group heading. */
  group?: string;
  /** Global shortcut, dispatched through the registry. */
  shortcut?: ShortcutSpec;
  /** Whether the action appears at all. Defaults to always. */
  applicable?: (ctx: ActionCtx) => boolean;
  /**
   * When the action applies but cannot run right now, return a short
   * human reason ("No output to copy yet"). Shown dimmed in the
   * palette, and toasted when the action's shortcut fires.
   */
  disabledReason?: (ctx: ActionCtx) => string | undefined;
  /**
   * A second step: selecting the action shows these options (searchable,
   * like the top level) and `execute` runs with the picked option's id.
   * The palette's one way to ask "which one?" -- used by translate, where
   * "which language" is the whole question.
   */
  pick?: (ctx: ActionCtx) => {
    title: string;
    placeholder: string;
    options: { id: string; label: string; keywords?: string[] }[];
  };
  execute: (ctx: ActionCtx, picked?: string) => void | Promise<void>;
}

/** Resolve an action's display name against a ctx. */
export function actionName(action: PgpAction, ctx: ActionCtx): string {
  return typeof action.name === "function" ? action.name(ctx) : action.name;
}
