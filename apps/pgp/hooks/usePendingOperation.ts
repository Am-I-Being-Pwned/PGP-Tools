import { useCallback, useEffect, useState } from "react";

import type { PendingOperation } from "../lib/messages";
import { SESSION_PENDING_OP } from "../lib/constants";
import {
  isPendingOperation,
  isPendingOpForWindow,
  isPendingOpFresh,
} from "../lib/pending-op";

/**
 * Reads the pending op the background writes to `chrome.storage.session`
 * (`SESSION_PENDING_OP`), removing it as soon as it is consumed.
 *
 * `ready` GATES THE CONSUME as a security control: consuming moves the raw
 * selection into React state, and nothing can route it while onboarding or
 * the master-unlock screen is up. Until then it waits in session storage
 * where T-PENDING-OP-AT-REST bounds it (TTL + sweep), not on the fiber
 * (T-OUTPUT-HEAP-RESIDUE). Consequence: an unlock slower than
 * `PENDING_OP_TTL_MS` drops the selection.
 */
export function usePendingOperation(ready: boolean) {
  const [pending, setPending] = useState<PendingOperation | null>(null);
  // False until the first read after `ready`, so the panel can hold the
  // workspace back instead of painting an empty form first.
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    if (!ready) {
      setChecked(false);
      return;
    }

    // AbortController, not a `let`: typescript-eslint narrows a plain flag
    // to the literal `false`.
    const ac = new AbortController();

    const consume = async (): Promise<boolean> => {
      const result = await chrome.storage.session.get(SESSION_PENDING_OP);
      const op = result[SESSION_PENDING_OP];
      if (!isPendingOperation(op)) {
        if (!ac.signal.aborted) setChecked(true);
        return false;
      }
      // Another window's selection: leave it for that window's panel.
      const here = await chrome.windows.getCurrent();
      if (!isPendingOpForWindow(op, here.id)) {
        if (!ac.signal.aborted) setChecked(true);
        return false;
      }
      // Remove even if stale.
      await chrome.storage.session.remove(SESSION_PENDING_OP);
      if (ac.signal.aborted) return true;
      setChecked(true);
      if (!isPendingOpFresh(op)) return false;
      setPending(op);
      return true;
    };

    // The SW's set() can race the panel mount; re-poll once after 400ms in
    // case onChanged slipped past the listener registration.
    void (async () => {
      const got = await consume();
      if (got || ac.signal.aborted) return;
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

  const clearPending = useCallback(() => setPending(null), []);

  return { pending, clearPending, checked };
}
