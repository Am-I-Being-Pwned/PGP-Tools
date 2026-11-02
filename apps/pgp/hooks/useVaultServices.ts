import { useCallback, useMemo } from "react";

import type { ProtectedKeyBlob } from "../lib/storage/keyring";
import type { MasterProtection } from "../lib/storage/master-protection";
import type { VaultServices } from "./useVault";
import { fromBase64 } from "../lib/encoding";
import { masterPasskeyOf } from "../lib/protection/vault-unlock";
import {
  addKey,
  removeKey,
  replaceKeyProtection,
} from "../lib/storage/keyring";
import { keyringList } from "../lib/storage/vault-lists";
import { useKeySession } from "./useKeySession";
import { savePreference, usePreferences } from "./usePreferences";

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
  // "Unlock keys with the vault": a per-key passkey unlock re-seals the
  // key under the master salt off its own ceremony.
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

  // New keys share the master SALT only while that option is on: that is
  // what lets the vault ceremony open them.
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

  // The first key becomes the explicit default, so adding a second one
  // later never silently changes which key "encrypt to me" targets.
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
