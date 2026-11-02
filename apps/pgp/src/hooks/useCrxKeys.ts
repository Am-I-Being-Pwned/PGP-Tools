import { useSyncExternalStore } from "react";

import { addCrxKey, removeCrxKey, updateCrxLabel } from "~/lib/crx/storage";
import { crxKeysList } from "~/lib/storage/vault-lists";

export function useCrxKeys() {
  const { items, loading, error } = useSyncExternalStore(
    crxKeysList.subscribe,
    crxKeysList.get,
  );
  return {
    keys: items,
    loading,
    error,
    add: addCrxKey,
    remove: removeCrxKey,
    rename: updateCrxLabel,
  };
}
