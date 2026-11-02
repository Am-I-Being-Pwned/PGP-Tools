import { useCallback, useRef, useState } from "react";

import { SESSION_PENDING_OP } from "~/lib/constants";
import * as wasmApi from "~/lib/pgp/wasm";
import type { VaultEvent, VaultLifecycle } from "~/lib/vault-phase";
import {
  draftHasContent,
  encryptWorkspaceDraft,
  type WorkspaceDraftSource,
} from "~/lib/workspace-draft";
import type { useKeySession } from "./useKeySession";

interface MasterLockDeps {
  session: ReturnType<typeof useKeySession>;
  dispatchVault: (event: VaultEvent) => VaultLifecycle;
  clearPending: () => void;
  lockReaders: () => void;
}

/**
 * Master lock. The workspace draft survives it only as ciphertext under
 * the in-WASM draft key, then the workspace wipes its plaintext
 * (SECURITY.md s.8.11, T-DRAFT-HEAP-RESIDUE).
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
      // Readers first, synchronously, before any await.
      lockReaders();
      // Seal before the state flip unmounts the workspace. A lost draft beats a failed lock.
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
      // Unmounting alone leaves plaintext reachable via the fiber's `alternate`.
      source?.wipe();

      // A pending context-menu op lives in session storage AND React state.
      clearPending();
      void chrome.storage.session.remove(SESSION_PENDING_OP);

      // FIRE-AND-FORGET: this and the state flip must land in ONE synchronous
      // run, or the draft fails to rehydrate (tests/e2e/draft-memory.spec.ts).
      void wasmApi.dropContactsSession();
      dispatchVault({ type: "locked", auto });
      // UNCONDITIONAL: also bumps the lock generation so an in-flight unlock
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
