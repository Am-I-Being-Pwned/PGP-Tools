import { useEffect, useEffectEvent } from "react";

import { useVault } from "~/hooks/useVault";
import type { Workspace } from "./useWorkspace";

/** How long an armed decrypt waits for the scan to land on its key. */
const KEY_PICK_GRACE_MS = 2_000;

/**
 * A message opened from the context menu runs by itself: verify always,
 * decrypt only when the key it is addressed to is ALREADY unlocked. It
 * never starts a ceremony or a prompt (SECURITY.md §15); anything else
 * falls back to the button. Waits for the vault to settle so a verdict
 * isn't reached against contacts still loading.
 *
 * Returns whether the idle form should stay invisible: it would only
 * flash up between the selection landing and the result replacing it.
 */
export function useAutoRun(
  ws: Workspace,
  o: {
    vaultSettling: boolean;
    /** The op is in this render's props but not yet armed, or the first
     *  look for one hasn't answered. */
    arriving: boolean;
    canRun: boolean;
  },
): boolean {
  const { session } = useVault();
  const { state: s, dispatch } = ws;
  const armed = s.autoRun;
  const loading = s.run.kind === "running";

  const attempt = useEffectEvent(
    async (run: { cancelled: boolean; timer?: number }) => {
      const give = () => dispatch({ type: "auto-run-dropped" });
      if (s.mode !== armed || s.run.kind === "done") return give();
      if (armed === "decrypt") {
        const match = await ws.matchDecryptionKey().catch(() => null);
        if (run.cancelled) return;
        if (!match || session.getKeyHandle(match) === null) return give();
        // The scan is about to land on it; this re-runs when it does.
        // Bounded, so a hand-picked key can't leave the run armed.
        if (ws.selectedKeyId !== match) {
          run.timer = window.setTimeout(give, KEY_PICK_GRACE_MS);
          return;
        }
      }
      give();
      if (o.canRun) void ws.executeUnattended();
    },
  );

  useEffect(() => {
    if (!armed || o.vaultSettling || loading) return;
    const run: { cancelled: boolean; timer?: number } = { cancelled: false };
    void attempt(run);
    return () => {
      run.cancelled = true;
      clearTimeout(run.timer);
    };
    // `input.version` stands in for the text.
  }, [
    armed,
    o.vaultSettling,
    loading,
    s.mode,
    s.run.kind,
    s.input.version,
    ws.selectedKeyId,
    ws.myKeys,
  ]);

  return (
    o.arriving || armed !== null || (s.run.kind === "running" && s.run.autoRun)
  );
}
