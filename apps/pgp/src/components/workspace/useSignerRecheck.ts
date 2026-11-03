import { useEffect, useEffectEvent, useRef } from "react";

import { useNav, usePreferences, useVault } from "~/hooks";
import type { Workspace } from "./useWorkspace";
import type { WorkspaceFlags } from "./workspace-view";

/** Look up an unknown signer, and re-verify once the import lands. */
export function useSignerRecheck(ws: Workspace, v: WorkspaceFlags) {
  const { state: s, contacts } = ws;
  const { verdict } = s.result;
  const { session } = useVault();
  const { openImport } = useNav();
  const { keyDiscoveryEnabled } = usePreferences();
  // Re-verify a looked-up unknown signer once contacts change; never prompts.
  const lookedUp = useRef<{ keyId: string; contacts: unknown } | null>(null);
  const lookupSigner = keyDiscoveryEnabled
    ? (keyId: string) => {
        lookedUp.current = { keyId, contacts };
        openImport({ lookup: keyId });
      }
    : undefined;
  const recheckSigner = useEffectEvent(() => {
    const pending = lookedUp.current;
    if (!pending || pending.contacts === contacts) return;
    lookedUp.current = null;
    if (v.loading || verdict?.tone !== "warning") return;
    if (verdict.signer.keyId !== pending.keyId) return;
    if (s.mode === "verify") {
      void ws.execute();
    } else if (
      s.mode === "decrypt" &&
      (v.unencryptedMessage ||
        (!v.passwordOnlyMessage &&
          ws.selectedKeyId !== null &&
          session.getKeyHandle(ws.selectedKeyId) !== null))
    ) {
      void ws.executeWithoutPrompts();
    }
  });
  useEffect(() => {
    recheckSigner();
  }, [contacts]);

  return lookupSigner;
}
