import { useCallback, useEffect, useState } from "react";

import type { PublicContactKey } from "../lib/storage/contacts";
import {
  addContact,
  getContacts,
  removeContact,
} from "../lib/storage/contacts";

export function useContacts() {
  const [contacts, setContacts] = useState<PublicContactKey[]>([]);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    const all = await getContacts();
    setContacts(all);
    setLoading(false);
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const add = useCallback(
    async (contact: PublicContactKey) => {
      await addContact(contact);
      await refresh();
    },
    [refresh],
  );

  const remove = useCallback(
    async (keyId: string) => {
      await removeContact(keyId);
      await refresh();
    },
    [refresh],
  );

  return { contacts, loading, refresh, add, remove };
}
