import { useCallback, useRef, useState } from "react";

import {
  initialVaultLifecycle,
  vaultReducer,
  type VaultEvent,
  type VaultLifecycle,
} from "~/lib/vault-phase";

/** `useReducer` whose dispatch applies at once and returns the new state:
 *  an unlock needs its own generation, and a lock must take effect in the
 *  same synchronous run that wipes the workspace (see `doMasterLock`). */
export function useVaultLifecycle() {
  const ref = useRef(initialVaultLifecycle);
  const [state, setState] = useState(initialVaultLifecycle);
  const dispatch = useCallback((event: VaultEvent): VaultLifecycle => {
    ref.current = vaultReducer(ref.current, event);
    setState(ref.current);
    return ref.current;
  }, []);
  return [state, dispatch] as const;
}
