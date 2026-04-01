import { useCallback, useEffect, useRef, useState } from "react";

import type { PublicContactKey } from "../lib/storage/contacts";
import {
  deleteContactsBlob,
  loadContacts,
  saveContacts,
} from "../lib/storage/contacts";

export function useContacts() {
  const [contacts, setContacts] = useState<PublicContactKey[]>([]);
  const [loading, setLoading] = useState(true);

  // Mutex to serialize mutations.
  const mutexRef = useRef<Promise<void>>(Promise.resolve());

  const refresh = useCallback(async () => {
    const all = await loadContacts();
    setContacts(all);
    setLoading(false);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const add = useCallback(async (contact: PublicContactKey) => {
    const op = mutexRef.current.then(async () => {
      let updated: PublicContactKey[] = [];
      let existing: PublicContactKey | undefined;
      setContacts((prev) => {
        existing = prev.find((c) => c.keyId === contact.keyId);
        updated = [...prev.filter((c) => c.keyId !== contact.keyId), contact];
        return updated;
      });

      try {
        await saveContacts(updated);
      } catch (e) {
        setContacts((prev) => {
          const without = prev.filter((c) => c.keyId !== contact.keyId);
          return existing ? [...without, existing] : without;
        });
        throw e;
      }
    });
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    mutexRef.current = op.catch(() => {});
    return op;
  }, []);

  const remove = useCallback(async (keyId: string) => {
    const op = mutexRef.current.then(async () => {
      let removed: PublicContactKey | undefined;
      let updated: PublicContactKey[] = [];
      setContacts((prev) => {
        removed = prev.find((c) => c.keyId === keyId);
        updated = prev.filter((c) => c.keyId !== keyId);
        return updated;
      });

      try {
        if (updated.length === 0) {
          await deleteContactsBlob();
        } else {
          await saveContacts(updated);
        }
      } catch (e) {
        const rollback = removed;
        if (rollback) {
          setContacts((prev) => [...prev, rollback]);
        }
        throw e;
      }
    });
    // eslint-disable-next-line @typescript-eslint/no-empty-function
    mutexRef.current = op.catch(() => {});
    return op;
  }, []);

  return { contacts, loading, refresh, add, remove };
}
