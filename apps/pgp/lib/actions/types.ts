// Framework-free action model: nothing in lib/actions imports React.

import type { ShortcutSpec } from "@amibeingpwned/ui/kbd-helpers";

import type { InlineStyle } from "../compose/text-format";
import type { StoredKeyKind } from "../storage/key-kind";

export type PgpMode = "encrypt" | "decrypt" | "sign" | "verify";

export type AppTab = "workspace" | "keys" | "settings";

/** Everything an action may read or invoke, assembled in useActionContext. */
export interface ActionCtx {
  tab: AppTab;
  mode: PgpMode;
  /** Workspace has text input or dropped files. */
  hasInput: boolean;
  /** Encrypt has someone who could open the result: a selected recipient
   *  or an armed message password. Encrypt mode only. */
  canEncrypt: boolean;
  /** Engine of the current recipient selection; null when none. age has
   *  no signing, so signing actions need to know. */
  encryptEngine: StoredKeyKind | null;
  /** Copyable text output exists. */
  hasOutput: boolean;
  /** Anything downloadable exists (text, binary, or per-file results). */
  hasDownload: boolean;
  masterUnlocked: boolean;
  historyEnabled: boolean;
  encryptToSelf: boolean;
  alsoSign: boolean;
  /** History is unavailable while this is on. */
  neverCacheKeys: boolean;
  counts: {
    ownKeys: number;
    contacts: number;
  };
  result: {
    canTranslate: boolean;
    /** BCP 47 tag. */
    readingLanguage: string;
    /** A decrypted message from a verified signer is on screen. */
    canReply: boolean;
  };
  compose: {
    /** Workspace tab, encrypt/sign mode, text box mounted, no private key pasted. */
    canEdit: boolean;
    translateEnabled: boolean;
    translateTarget: string | null;
  };
  navigation: {
    setTab: (tab: AppTab) => void;
    openHistory: () => void;
    openGenerate: () => void;
    openImport: () => void;
    setMode: (mode: PgpMode) => void;
    openSecurityPresets: () => void;
  };
  ops: {
    execute: () => void;
    clearInput: () => void;
    copyOutput: () => void;
    downloadOutput: () => void;
    lockNow: () => void;
    /** Same handler as the checkbox (persists and resets stale output). */
    toggleEncryptToSelf: () => void;
    toggleAlsoSign: () => void;
    toggleSaveToHistory: () => void;
    applyStyle: (style: InlineStyle) => void;
    openFind: () => void;
    translateTo: (language: string) => void;
    translateOutput: () => void;
    reply: () => void;
  };
}

/**
 * A palette/shortcut action. `id` must NEVER change once shipped (it may
 * live in keybindings/telemetry); rename via `name`, retire ids forever.
 */
export interface PgpAction {
  id: string;
  name: string | ((ctx: ActionCtx) => string);
  keywords?: string[];
  group?: string;
  shortcut?: ShortcutSpec;
  applicable?: (ctx: ActionCtx) => boolean;
  /** Short reason the action can't run now; shown dimmed and toasted on shortcut. */
  disabledReason?: (ctx: ActionCtx) => string | undefined;
  /** Second-step options; `execute` receives the picked option's id. */
  pick?: (ctx: ActionCtx) => {
    title: string;
    placeholder: string;
    options: { id: string; label: string; keywords?: string[] }[];
  };
  execute: (ctx: ActionCtx, picked?: string) => void | Promise<void>;
}

export function actionName(action: PgpAction, ctx: ActionCtx): string {
  return typeof action.name === "function" ? action.name(ctx) : action.name;
}
