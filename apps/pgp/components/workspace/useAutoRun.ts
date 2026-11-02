import { useEffect, useEffectEvent } from "react";

import { useVault } from "~/hooks/useVault";
import type { Workspace } from "./useWorkspace";

const KEY_PICK_GRACE_MS = 2_000;

/**
 * Context-menu auto-run: verify always, decrypt only when the addressed key
 * is ALREADY unlocked; never a ceremony or prompt (SECURITY.md §15). Waits
 * for the vault to settle. Returns whether to hide the idle form.
 */
export function useAutoRun(
  ws: Workspace,
  o: {
    vaultSettling: boolean;
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
