import { useCallback, useEffect, useState } from "react";

import type { ProtectedKeyBlob } from "../lib/storage/keyring";
import {
  addKey,
  getKeyring,
  removeKey,
  updateAlias,
  updateRevocationCertificate,
} from "../lib/storage/keyring";

/**
 * Read the keyring, distinguishing "empty" from "unreadable".
 *
 * Pure and exported for tests (the same split as `createDelayedFlag`):
 * `vitest` runs in a node environment here, so the logic worth testing
 * lives outside the hook rather than behind a renderer.
 *
 * `getKeyring` THROWS when the vault's session key can't open its blob
 * (a failed AEAD tag) rather than returning []. Unhandled, that left the
 * hook's `keys` at [] and `loading` stuck true forever, so the panel
 * showed "no keys" -- indistinguishable from having lost them. The
 * passkey unlock path can reach this state: it installs its session key
 * without verifying it (`MasterPasskeyProtection` carries no canary,
 * unlike the password variant), so a PRF output that isn't the one the
 * vault was sealed under dismisses the lock screen and fails here.
 */
export async function readKeyring(): Promise<{
  keys: ProtectedKeyBlob[];
  error: Error | null;
}> {
  try {
    return { keys: await getKeyring(), error: null };
  } catch (e) {
    return { keys: [], error: e instanceof Error ? e : new Error(String(e)) };
  }
}

export function useKeyring() {
  const [keys, setKeys] = useState<ProtectedKeyBlob[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  /** `error` is what tells the UI the difference between "you have no
   *  keys" and "your keys could not be read" -- see {@link readKeyring}. */
  const refresh = useCallback(async () => {
    const { keys: loaded, error: failure } = await readKeyring();
    setKeys(loaded);
    setError(failure);
    setLoading(false);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const add = useCallback(
    async (blob: ProtectedKeyBlob) => {
      await addKey(blob);
      await refresh();
    },
    [refresh],
  );

  const remove = useCallback(
    async (keyId: string) => {
      await removeKey(keyId);
      await refresh();
    },
    [refresh],
  );

  const rename = useCallback(
    async (keyId: string, alias: string) => {
      await updateAlias(keyId, alias);
      await refresh();
    },
    [refresh],
  );

  const setRevocationCertificate = useCallback(
    async (keyId: string, armored: string) => {
      await updateRevocationCertificate(keyId, armored);
      await refresh();
    },
    [refresh],
  );

  return {
    keys,
    loading,
    error,
    refresh,
    add,
    remove,
    rename,
    setRevocationCertificate,
  };
}
