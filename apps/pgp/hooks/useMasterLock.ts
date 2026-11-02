import { useCallback, useRef, useState } from "react";

import type { VaultEvent, VaultLifecycle } from "../lib/vault-phase";
import type { WorkspaceDraftSource } from "../lib/workspace-draft";
import type { useKeySession } from "./useKeySession";
import { SESSION_PENDING_OP } from "../lib/constants";
import * as wasmApi from "../lib/pgp/wasm";
import { draftHasContent, encryptWorkspaceDraft } from "../lib/workspace-draft";

interface MasterLockDeps {
  session: ReturnType<typeof useKeySession>;
  dispatchVault: (event: VaultEvent) => VaultLifecycle;
  /** Drop the React-state copy of an unrouted context-menu op. */
  clearPending: () => void;
  /** Clear Reply's reader tabs. */
  lockReaders: () => void;
}

/**
 * Locking the vault, and the workspace draft that survives it as
 * ciphertext (SECURITY.md s.8.11, T-DRAFT-HEAP-RESIDUE). The workspace
 * registers a pull-model draft source; on lock it is asked for a
 * snapshot once, the snapshot is sealed under the in-WASM draft key, and
 * the workspace is told to wipe its plaintext.
 */
export function useMasterLock({
  session,
  dispatchVault,
  clearPending,
  lockReaders,
}: MasterLockDeps) {
  const draftSourceRef = useRef<WorkspaceDraftSource | null>(null);
  const [draftCiphertext, setDraftCiphertext] = useState<Uint8Array | null>(
    null,
  );

  const registerDraftSource = useCallback(
    (src: WorkspaceDraftSource | null) => {
      draftSourceRef.current = src;
    },
    [],
  );
  const discardDraft = useCallback(() => setDraftCiphertext(null), []);

  const lock = useCallback(
    async (auto = false) => {
      // Readers first, synchronously: nothing awaited below may let one
      // keep (or be sent) the message.
      lockReaders();
      // Seal the draft before the state flip unmounts the workspace. On
      // error, lock anyway: a lost draft beats a failed lock.
      const source = draftSourceRef.current;
      let draft = source?.getDraft() ?? null;
      if (draft && draftHasContent(draft)) {
        try {
          await wasmApi.initDraftSessionIfUnset();
          setDraftCiphertext(await encryptWorkspaceDraft(draft));
        } catch {
          /* lock anyway */
        }
      }
      // Releases this frame's reference to the plaintext (T-OUTPUT-HEAP-RESIDUE).
      // eslint-disable-next-line no-useless-assignment
      draft = null;
      // Unmounting alone keeps the plaintext reachable via the fiber's
      // `alternate`; only clearing the refs and DOM value drops it.
      source?.wipe();

      // An unrouted context-menu op lives in BOTH session storage and
      // React state; drop both so it cannot surface on the next unlock.
      clearPending();
      void chrome.storage.session.remove(SESSION_PENDING_OP);

      // FIRE-AND-FORGET: everything above and the state flip below must
      // land in ONE synchronous run, or the draft fails to rehydrate and
      // its plaintext stays reachable (e2e/draft-memory.spec.ts). Store
      // mutations re-check the session inside their own locks instead.
      void wasmApi.dropContactsSession();
      dispatchVault({ type: "locked", auto });
      // UNCONDITIONAL (no `size > 0` guard like the auto-lock handlers):
      // it also bumps the lock generation, so an unlock already in flight
      // cannot insert a live key after this lock.
      session.lockAll();
    },
    [session, clearPending, lockReaders, dispatchVault],
  );

  return {
    lock,
    draftCiphertext,
    discardDraft,
    registerDraftSource,
  };
}
