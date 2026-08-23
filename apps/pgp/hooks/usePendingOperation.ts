import { useCallback, useEffect, useState } from "react";

import type { PendingOperation } from "../lib/messages";
import { SESSION_PENDING_OP } from "../lib/constants";
import { isPendingOperation, isPendingOpFresh } from "../lib/pending-op";

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
 *
 * `ready` GATES THE CONSUME, and it is a security control rather than a
 * convenience. Consuming means moving the payload -- the user's raw
 * selection, i.e. the plaintext they are about to encrypt -- out of
 * session storage and into React state, where `App` holds it until
 * something routes it. Nothing can route it while the panel is showing
 * onboarding or the master-unlock screen (`WorkspaceView` is not mounted
 * then), so consuming early bought nothing and left the plaintext
 * retained on the fiber for the whole locked window: measured as one
 * live retainer, `property[lastRenderedState] -> property[text]`, i.e.
 * this hook's own update queue. That is T-OUTPUT-HEAP-RESIDUE's class
 * applied to the pending op, and it is why the payload now waits where
 * `T-PENDING-OP-AT-REST` already accounts for it -- in session storage,
 * bounded by `PENDING_OP_TTL_MS` and `sweepStalePendingOp` -- until the
 * App can actually act on it.
 *
 * Consequence, stated rather than hidden: an unlock that takes longer
 * than `PENDING_OP_TTL_MS` now drops the selection instead of applying
 * it, because freshness is judged when we consume and no longer when the
 * panel merely mounted. That is what the TTL is for.
 */
export function usePendingOperation(ready: boolean) {
  const [pending, setPending] = useState<PendingOperation | null>(null);

  useEffect(() => {
    // Leave it in storage until the App is in a state that can route it.
    if (!ready) return;

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
      if (!isPendingOpFresh(op)) return false;
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
  }, [ready]);

  // Stable identity so consumer effects with clearPending in deps
  // don't re-fire on every render.
  const clearPending = useCallback(() => setPending(null), []);

  return { pending, clearPending };
}
