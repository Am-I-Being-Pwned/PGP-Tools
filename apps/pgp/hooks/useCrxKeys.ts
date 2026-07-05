import { useCallback, useEffect, useState } from "react";

import type { CrxSigningKeyBlob } from "../lib/crx/types";
import {
  addCrxKey,
  getCrxKeys,
  removeCrxKey,
  updateCrxLabel,
} from "../lib/crx/storage";

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

  const rename = useCallback(
    async (extensionId: string, label: string) => {
      await updateCrxLabel(extensionId, label);
      await refresh();
    },
    [refresh],
  );

  return { keys, loading, refresh, add, remove, rename };
}
