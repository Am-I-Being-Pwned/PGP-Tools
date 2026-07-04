import { useCallback, useEffect, useState } from "react";

import { addCrxKey, getCrxKeys, removeCrxKey } from "../lib/crx/storage";
import type { CrxSigningKeyBlob } from "../lib/crx/types";

export function useCrxKeys() {
  const [keys, setKeys] = useState<CrxSigningKeyBlob[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    const crxKeys = await getCrxKeys();
    setKeys(crxKeys);
    setLoading(false);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const add = useCallback(
    async (blob: CrxSigningKeyBlob) => {
      await addCrxKey(blob);
      await refresh();
    },
    [refresh],
  );

  const remove = useCallback(
    async (extensionId: string) => {
      await removeCrxKey(extensionId);
      await refresh();
    },
    [refresh],
  );

  return { keys, loading, refresh, add, remove };
}
