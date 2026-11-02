import { useSyncExternalStore } from "react";

import {
  addKey,
  removeKey,
  replaceKeyProtection,
  updateAlias,
  updateRevocationCertificate,
} from "~/lib/storage/keyring";
import { keyringList } from "~/lib/storage/vault-lists";

/** The keyring as stored. `error` is set when the blob would not open --
 *  never shown as an empty keyring. Writes reach `keys` on their own. */
export function useKeyring() {
  const { items, loading, error } = useSyncExternalStore(
    keyringList.subscribe,
    keyringList.get,
  );
  return {
    keys: items,
    loading,
    error,
    add: addKey,
    remove: removeKey,
    rename: updateAlias,
    replaceProtection: replaceKeyProtection,
    setRevocationCertificate: updateRevocationCertificate,
  };
}
