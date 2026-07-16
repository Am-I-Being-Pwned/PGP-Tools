import { useEffect, useMemo, useRef } from "react";

import type { ActionCtx, AppTab, PgpMode } from "../lib/actions/types";

/**
 * The slice of workspace state + operations the action system needs,
 * pushed up by WorkspaceView on change. Null until the workspace has
 * mounted (it stays mounted-but-hidden across tabs, so in practice
 * this is only null for a frame).
 */
export interface WorkspaceOpsBridge {
  mode: PgpMode;
  hasInput: boolean;
  /** Encrypt has at least one selected recipient. */
  hasRecipients: boolean;
  hasOutput: boolean;
  historyEnabled: boolean;
  setMode: (mode: PgpMode) => void;
  execute: () => void;
  clearInput: () => void;
  copyOutput: () => void;
}

interface UseActionContextArgs {
  tab: AppTab;
  setTab: (tab: AppTab) => void;
  workspace: WorkspaceOpsBridge | null;
  counts: { ownKeys: number; contacts: number };
  openHistory: () => void;
  openGenerate: () => void;
  openImport: () => void;
  lockNow: () => void;
}

const noop = () => undefined;

/**
 * Assemble the ActionCtx the action registry evaluates against. Only
 * used behind the master-unlock gate, so `masterUnlocked` is always
 * true here. Memoized on the data fields; callbacks route through a
 * ref so the ctx identity only changes when something an action can
 * *read* changes.
 */
export function useActionContext(args: UseActionContextArgs): ActionCtx {
  const argsRef = useRef(args);
  useEffect(() => {
    argsRef.current = args;
  });

  const { tab, workspace, counts } = args;
  const mode = workspace?.mode ?? "encrypt";
  const hasInput = workspace?.hasInput ?? false;
  const hasRecipients = workspace?.hasRecipients ?? false;
  const hasOutput = workspace?.hasOutput ?? false;
  const historyEnabled = workspace?.historyEnabled ?? false;
  const { ownKeys, contacts } = counts;

  return useMemo(
    () => ({
      tab,
      mode,
      hasInput,
      hasRecipients,
      hasOutput,
      masterUnlocked: true,
      historyEnabled,
      counts: { ownKeys, contacts },
      navigation: {
        setTab: (t) => argsRef.current.setTab(t),
        openHistory: () => argsRef.current.openHistory(),
        openGenerate: () => argsRef.current.openGenerate(),
        openImport: () => argsRef.current.openImport(),
        setMode: (m) => (argsRef.current.workspace?.setMode ?? noop)(m),
      },
      ops: {
        execute: () => (argsRef.current.workspace?.execute ?? noop)(),
        clearInput: () => (argsRef.current.workspace?.clearInput ?? noop)(),
        copyOutput: () => (argsRef.current.workspace?.copyOutput ?? noop)(),
        lockNow: () => argsRef.current.lockNow(),
      },
    }),
    [
      tab,
      mode,
      hasInput,
      hasRecipients,
      hasOutput,
      historyEnabled,
      ownKeys,
      contacts,
    ],
  );
}
