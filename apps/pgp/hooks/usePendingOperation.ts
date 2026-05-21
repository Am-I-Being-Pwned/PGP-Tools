import { useCallback, useEffect, useState } from "react";

import { SESSION_PENDING_OP } from "../lib/constants";
import type { OperationAction, PendingOperation } from "../lib/messages";

const VALID_ACTIONS = new Set<OperationAction>([
  "encrypt",
  "decrypt",
  "sign",
  "verify",
  "import-public",
  "import-private",
]);

/** Drop ops older than this. Catches the case where the user
 *  triggered the context menu, closed the side panel without
 *  unlocking, and only opens it much later for some unrelated
 *  reason -- we don't want the stale selection to surface. */
const PENDING_OP_TTL_MS = 60_000;

function isPendingOperation(msg: unknown): msg is PendingOperation {
  if (typeof msg !== "object" || msg === null) return false;
  const obj = msg as Record<string, unknown>;
  return (
    obj.type === "PENDING_OPERATION" &&
    typeof obj.id === "string" &&
    typeof obj.action === "string" &&
    VALID_ACTIONS.has(obj.action as OperationAction) &&
    typeof obj.text === "string" &&
    typeof obj.sourceTabId === "number" &&
    typeof obj.createdAt === "number"
  );
}

function isFresh(op: PendingOperation): boolean {
  return Date.now() - op.createdAt < PENDING_OP_TTL_MS;
}

/**
 * Source of truth: `chrome.storage.session` under `SESSION_PENDING_OP`.
 * The background writes there on context-menu click; we read on mount
 * and subscribe to changes, removing the entry as soon as we consume
 * it so re-renders don't re-apply the same op.
 *
 * This replaces the older runtime.sendMessage handshake -- that path
 * was racy against service-worker recycling and slow master-unlock,
 * causing the side panel to miss the selection text. Session storage
 * is in-memory but persists across SW restarts and is read at any
 * time by the App once the user has finished unlocking.
 */
export function usePendingOperation() {
  const [pending, setPending] = useState<PendingOperation | null>(null);

  useEffect(() => {
    // AbortController gives us a properly-typed mutable `aborted`
    // boolean for cross-async cancellation. (A plain `let` or ref
    // gets narrowed to the literal `false` by typescript-eslint.)
    const ac = new AbortController();

    const consume = async (): Promise<boolean> => {
      const result = await chrome.storage.session.get(SESSION_PENDING_OP);
      const op = result[SESSION_PENDING_OP];
      if (!isPendingOperation(op)) return false;
      // Always remove first, regardless of freshness -- a stale op
      // shouldn't keep sitting in storage even if we don't apply it.
      await chrome.storage.session.remove(SESSION_PENDING_OP);
      if (!isFresh(op)) return false;
      if (ac.signal.aborted) return true;
      setPending(op);
      return true;
    };

    // First read on mount. If empty, the background may still be
    // committing storage.set (close+locked case: the SW write races
    // against the side panel mount). Re-poll once after 400ms as a
    // safety net so we don't depend solely on the onChanged listener
    // racing with set().
    void (async () => {
      const got = await consume();
      if (got || ac.signal.aborted) return;
      // Defensive retry: covers the case where the background's
      // storage.set commits after we mounted but the onChanged event
      // somehow slipped past our listener registration.
      await new Promise((r) => setTimeout(r, 400));
      // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition -- mutated by cleanup on unmount, rule can't see it
      if (!ac.signal.aborted) void consume();
    })();

    const onChange = (
      changes: Record<string, chrome.storage.StorageChange>,
      area: chrome.storage.AreaName,
    ) => {
      if (area !== "session") return;
      if (!(SESSION_PENDING_OP in changes)) return;
      const change = changes[SESSION_PENDING_OP];
      if (change.newValue && isPendingOperation(change.newValue)) {
        void consume();
      }
    };

    chrome.storage.onChanged.addListener(onChange);
    return () => {
      ac.abort();
      chrome.storage.onChanged.removeListener(onChange);
    };
  }, []);

  // Stable identity so consumer effects with clearPending in deps
  // don't re-fire on every render.
  const clearPending = useCallback(() => setPending(null), []);

  return { pending, clearPending };
}
