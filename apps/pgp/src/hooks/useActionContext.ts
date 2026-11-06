import {
  createContext,
  use,
  useMemo,
  useState,
  useSyncExternalStore,
} from "react";

import type { ActionCtx, AppTab, PgpMode } from "~/lib/actions/types";
import type { InlineStyle } from "~/lib/compose/text-format";
import type { StoredKeyKind } from "~/lib/storage/key-kind";
import type { Nav } from "./useNav";
import { usePreferences } from "./usePreferences";

/** Plain values only: no plaintext, nothing a lock needs to wipe. */
export interface WorkspaceSnapshot {
  mode: PgpMode;
  hasInput: boolean;
  canEncrypt: boolean;
  encryptEngine: StoredKeyKind | null;
  hasOutput: boolean;
  hasDownload: boolean;
  resultCanTranslate: boolean;
  resultCanReply: boolean;
  composeCanEdit: boolean;
  translateEnabled: boolean;
  translateTarget: string | null;
}

export interface WorkspaceCommands {
  setMode: (mode: PgpMode) => void;
  execute: () => void;
  clearInput: () => void;
  copyOutput: () => void;
  downloadOutput: () => void;
  toggleEncryptToSelf: () => void;
  toggleAlsoSign: () => void;
  toggleSaveToHistory: () => void;
  translateOutput: () => void;
  reply: () => void;
  applyStyle: (style: InlineStyle) => void;
  openFind: () => void;
  translateTo: (language: string) => void;
}

/**
 * External store so a workspace change re-renders the palette, not the App.
 * Commands are replaced silently each commit and looked up at call time.
 */
export interface WorkspaceBridge {
  publish: (
    snapshot: WorkspaceSnapshot | null,
    commands: WorkspaceCommands | null,
  ) => void;
  snapshot: () => WorkspaceSnapshot | null;
  commands: () => WorkspaceCommands | null;
  subscribe: (listener: () => void) => () => void;
}

function sameSnapshot(
  a: WorkspaceSnapshot | null,
  b: WorkspaceSnapshot | null,
): boolean {
  if (a === null || b === null) return a === b;
  return (Object.keys(a) as (keyof WorkspaceSnapshot)[]).every(
    (k) => a[k] === b[k],
  );
}

function createWorkspaceBridge(): WorkspaceBridge {
  let snapshot: WorkspaceSnapshot | null = null;
  let commands: WorkspaceCommands | null = null;
  const listeners = new Set<() => void>();
  return {
    publish(next, nextCommands) {
      commands = nextCommands;
      if (sameSnapshot(snapshot, next)) return;
      snapshot = next;
      for (const l of listeners) l();
    },
    snapshot: () => snapshot,
    commands: () => commands,
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
  };
}

export const WorkspaceBridgeContext = createContext<WorkspaceBridge | null>(
  null,
);

export function useWorkspaceBridgeStore(): WorkspaceBridge {
  return useState(createWorkspaceBridge)[0];
}

interface UseActionContextArgs {
  tab: AppTab;
  counts: { ownKeys: number; contacts: number };
  neverCacheKeys: boolean;
  nav: Pick<Nav, "showTab" | "openHistory" | "openKeysRoute" | "openPresets">;
  lockNow: () => void;
}

const noop = () => undefined;

/** Only used behind the master-unlock gate, so `masterUnlocked` is always true. */
export function useActionContext({
  tab,
  counts: { ownKeys, contacts },
  neverCacheKeys,
  nav: { showTab, openHistory, openKeysRoute, openPresets },
  lockNow,
}: UseActionContextArgs): ActionCtx {
  const bridge = use(WorkspaceBridgeContext);
  const ws = useSyncExternalStore(
    bridge?.subscribe ?? subscribeNever,
    bridge?.snapshot ?? nullSnapshot,
  );
  const {
    historyEnabled,
    encryptToSelf,
    signWhenEncrypting: alsoSign,
    translationTargetLanguage: readingLanguage,
  } = usePreferences();

  return useMemo(() => {
    const cmd = () => bridge?.commands() ?? null;
    return {
      tab,
      mode: ws?.mode ?? "encrypt",
      hasInput: ws?.hasInput ?? false,
      canEncrypt: ws?.canEncrypt ?? false,
      encryptEngine: ws?.encryptEngine ?? null,
      hasOutput: ws?.hasOutput ?? false,
      hasDownload: ws?.hasDownload ?? false,
      masterUnlocked: true,
      historyEnabled,
      encryptToSelf,
      alsoSign,
      neverCacheKeys,
      counts: { ownKeys, contacts },
      result: {
        canTranslate: ws?.resultCanTranslate ?? false,
        readingLanguage,
        canReply: ws?.resultCanReply ?? false,
      },
      compose: {
        canEdit: ws?.composeCanEdit ?? false,
        translateEnabled: ws?.translateEnabled ?? false,
        translateTarget: ws?.translateTarget ?? null,
      },
      navigation: {
        setTab: showTab,
        openHistory,
        openGenerate: () => openKeysRoute("generate"),
        openImport: () => openKeysRoute("import"),
        setMode: (m) => cmd()?.setMode(m),
        openSecurityPresets: openPresets,
      },
      ops: {
        execute: () => cmd()?.execute(),
        clearInput: () => cmd()?.clearInput(),
        copyOutput: () => cmd()?.copyOutput(),
        downloadOutput: () => cmd()?.downloadOutput(),
        lockNow,
        toggleEncryptToSelf: () => cmd()?.toggleEncryptToSelf(),
        toggleAlsoSign: () => cmd()?.toggleAlsoSign(),
        toggleSaveToHistory: () => cmd()?.toggleSaveToHistory(),
        applyStyle: (style) => cmd()?.applyStyle(style),
        openFind: () => cmd()?.openFind(),
        translateTo: (language) => cmd()?.translateTo(language),
        translateOutput: () => cmd()?.translateOutput(),
        reply: () => cmd()?.reply(),
      },
    };
  }, [
    bridge,
    ws,
    tab,
    historyEnabled,
    encryptToSelf,
    alsoSign,
    neverCacheKeys,
    ownKeys,
    contacts,
    readingLanguage,
    showTab,
    openHistory,
    openKeysRoute,
    openPresets,
    lockNow,
  ]);
}

const subscribeNever = () => noop;
const nullSnapshot = () => null;
