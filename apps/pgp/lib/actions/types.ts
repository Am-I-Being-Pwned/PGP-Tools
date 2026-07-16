// Framework-free action model: an action is data (id,
// name, grouping, shortcut) plus pure predicates over an ActionCtx the
// app assembles. Nothing in lib/actions imports React -- the UI layer
// (CommandPalette) renders whatever the registry reports.

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";

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
  /** Encrypt has at least one selected recipient. Only consulted in
   *  encrypt mode; other modes ignore it. */
  hasRecipients: boolean;
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
  execute: (ctx: ActionCtx) => void | Promise<void>;
}

/** Resolve an action's display name against a ctx. */
export function actionName(action: PgpAction, ctx: ActionCtx): string {
  return typeof action.name === "function" ? action.name(ctx) : action.name;
}
