import { useCallback, useEffect, useState } from "react";

import type { ProtectedKeyBlob } from "../lib/storage/keyring";
import {
  addKey,
  getKeyring,
  removeKey,
  updateAlias,
  updateRevocationCertificate,
} from "../lib/storage/keyring";

export function useKeyring() {
  const [keys, setKeys] = useState<ProtectedKeyBlob[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    const keyring = await getKeyring();
    setKeys(keyring);
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
    refresh,
    add,
    remove,
    rename,
    setRevocationCertificate,
  };
}
