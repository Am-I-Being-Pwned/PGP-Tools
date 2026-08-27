import { useEffect, useMemo, useRef } from "react";

import type { ActionCtx, AppTab, PgpMode } from "../lib/actions/types";
import type { StoredKeyKind } from "../lib/storage/key-kind";

/**
 * The slice of workspace state + operations the action system needs,
 * pushed up by WorkspaceView on change. Null until the workspace has
 * mounted (it stays mounted-but-hidden across tabs, so in practice
 * this is only null for a frame).
 */
export interface WorkspaceOpsBridge {
  mode: PgpMode;
  hasInput: boolean;
  /** Encrypt has someone who could open the result: a selected
   *  recipient, or an armed message password. See ActionCtx.canEncrypt
   *  for why this is not named after recipients. */
  canEncrypt: boolean;
  /** Which engine those recipients encrypt with (null when none are
   *  selected). See ActionCtx.encryptEngine. */
  encryptEngine: StoredKeyKind | null;
  hasOutput: boolean;
  /** A completed operation produced anything downloadable. */
  hasDownload: boolean;
  historyEnabled: boolean;
  /** The "Also encrypt to me" preference is on. */
  encryptToSelf: boolean;
  /** The "Sign when encrypting" preference is on. */
  alsoSign: boolean;
  setMode: (mode: PgpMode) => void;
  execute: () => void;
  clearInput: () => void;
  copyOutput: () => void;
  downloadOutput: () => void;
  /** The workspace checkboxes' exact toggle handlers (persistence and
   *  stale-output reset included), exposed for the palette toggles. */
  toggleEncryptToSelf: () => void;
  toggleAlsoSign: () => void;
  toggleSaveToHistory: () => void;
}

interface UseActionContextArgs {
  tab: AppTab;
  setTab: (tab: AppTab) => void;
  workspace: WorkspaceOpsBridge | null;
  counts: { ownKeys: number; contacts: number };
  /** The "Never auto-cache keys" setting (gates history availability). */
  neverCacheKeys: boolean;
  openHistory: () => void;
  openGenerate: () => void;
  openImport: () => void;
  openSecurityPresets: () => void;
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

  const { tab, workspace, counts, neverCacheKeys } = args;
  const mode = workspace?.mode ?? "encrypt";
  const hasInput = workspace?.hasInput ?? false;
  const canEncrypt = workspace?.canEncrypt ?? false;
  const encryptEngine = workspace?.encryptEngine ?? null;
  const hasOutput = workspace?.hasOutput ?? false;
  const hasDownload = workspace?.hasDownload ?? false;
  const historyEnabled = workspace?.historyEnabled ?? false;
  const encryptToSelf = workspace?.encryptToSelf ?? false;
  const alsoSign = workspace?.alsoSign ?? false;
  const { ownKeys, contacts } = counts;

  return useMemo(
    () => ({
      tab,
      mode,
      hasInput,
      canEncrypt,
      encryptEngine,
      hasOutput,
      hasDownload,
      masterUnlocked: true,
      historyEnabled,
      encryptToSelf,
      alsoSign,
      neverCacheKeys,
      counts: { ownKeys, contacts },
      navigation: {
        setTab: (t) => argsRef.current.setTab(t),
        openHistory: () => argsRef.current.openHistory(),
        openGenerate: () => argsRef.current.openGenerate(),
        openImport: () => argsRef.current.openImport(),
        setMode: (m) => (argsRef.current.workspace?.setMode ?? noop)(m),
        openSecurityPresets: () => argsRef.current.openSecurityPresets(),
      },
      ops: {
        execute: () => (argsRef.current.workspace?.execute ?? noop)(),
        clearInput: () => (argsRef.current.workspace?.clearInput ?? noop)(),
        copyOutput: () => (argsRef.current.workspace?.copyOutput ?? noop)(),
        downloadOutput: () =>
          (argsRef.current.workspace?.downloadOutput ?? noop)(),
        lockNow: () => argsRef.current.lockNow(),
        toggleEncryptToSelf: () =>
          (argsRef.current.workspace?.toggleEncryptToSelf ?? noop)(),
        toggleAlsoSign: () =>
          (argsRef.current.workspace?.toggleAlsoSign ?? noop)(),
        toggleSaveToHistory: () =>
          (argsRef.current.workspace?.toggleSaveToHistory ?? noop)(),
      },
    }),
    [
      tab,
      mode,
      hasInput,
      canEncrypt,
      encryptEngine,
      hasOutput,
      hasDownload,
      historyEnabled,
      encryptToSelf,
      alsoSign,
      neverCacheKeys,
      ownKeys,
      contacts,
    ],
  );
}
