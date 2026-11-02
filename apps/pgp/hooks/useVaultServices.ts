import { useCallback, useMemo } from "react";

import { fromBase64 } from "~/lib/encoding";
import { masterPasskeyOf } from "~/lib/protection/vault-unlock";
import {
  addKey,
  removeKey,
  replaceKeyProtection,
  type ProtectedKeyBlob,
} from "~/lib/storage/keyring";
import type { MasterProtection } from "~/lib/storage/master-protection";
import { keyringList } from "~/lib/storage/vault-lists";
import { useKeySession } from "./useKeySession";
import { savePreference, usePreferences } from "./usePreferences";
import type { VaultServices } from "./useVault";

/** The key session and the key-level actions every view shares. */
export function useVaultServices(
  masterProtection: MasterProtection | null,
): VaultServices {
  const {
    autoLockEnabled,
    autoLockMinutes,
    neverCacheKeys,
    unlockKeysOnOpen,
    defaultKeyId,
  } = usePreferences();

  const masterPasskey = useMemo(
    () => masterPasskeyOf(masterProtection),
    [masterProtection],
  );
  // A per-key passkey unlock re-seals the key under the master salt.
  const masterReseal = useMemo(
    () =>
      unlockKeysOnOpen && masterPasskey
        ? { master: masterPasskey, replaceProtection: replaceKeyProtection }
        : null,
    [unlockKeysOnOpen, masterPasskey],
  );
  const session = useKeySession({
    autoLockEnabled,
    autoLockMinutes,
    neverCacheKeys,
    masterReseal,
  });

  const masterSealSalt = useMemo(
    () =>
      unlockKeysOnOpen && masterPasskey
        ? fromBase64(masterPasskey.prfSalt).buffer
        : undefined,
    [unlockKeysOnOpen, masterPasskey],
  );

  const setDefaultKey = useCallback((keyId: string | null) => {
    void savePreference({ defaultKeyId: keyId });
  }, []);

  // Explicit default, so a second key never silently retargets "encrypt to me".
  const addOwnKey = useCallback(
    async (blob: ProtectedKeyBlob) => {
      const isFirstKey = keyringList.get().items.length === 0;
      await addKey(blob);
      if (isFirstKey && defaultKeyId === null) setDefaultKey(blob.keyId);
    },
    [defaultKeyId, setDefaultKey],
  );

  // The default never points at a deleted key.
  const deleteKey = useCallback(
    async (keyId: string) => {
      await removeKey(keyId);
      if (defaultKeyId === keyId) setDefaultKey(null);
    },
    [defaultKeyId, setDefaultKey],
  );

  return useMemo(
    () => ({
      session,
      masterPasskey,
      masterPasskeyCredentialId:
        masterProtection?.method === "passkey"
          ? masterProtection.credentialId
          : undefined,
      masterSealSalt,
      cacheKeys: !neverCacheKeys,
      onKeyCached: (keyId, handle) =>
        void session.cacheKeyHandle(keyId, handle),
      addKey: addOwnKey,
      deleteKey,
      setDefaultKey,
    }),
    [
      session,
      masterPasskey,
      masterProtection,
      masterSealSalt,
      neverCacheKeys,
      addOwnKey,
      deleteKey,
      setDefaultKey,
    ],
  );
}
