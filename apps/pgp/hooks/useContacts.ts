import { useCallback, useEffect, useRef, useState } from "react";

import type { PublicContactKey } from "../lib/storage/contacts";
import {
  loadContacts,
  removeContact,
  saveContact,
} from "../lib/storage/contacts";

export function useContacts() {
  const [contacts, setContacts] = useState<PublicContactKey[]>([]);
  const [loading, setLoading] = useState(true);

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
      let existing: PublicContactKey | undefined;
      setContacts((prev) => {
        existing = prev.find((c) => c.keyId === contact.keyId);
        return [...prev.filter((c) => c.keyId !== contact.keyId), contact];
      });

      try {
        await saveContact(contact);
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
      setContacts((prev) => {
        removed = prev.find((c) => c.keyId === keyId);
        return prev.filter((c) => c.keyId !== keyId);
      });

      try {
        await removeContact(keyId);
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
