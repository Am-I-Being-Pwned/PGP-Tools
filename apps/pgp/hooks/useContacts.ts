import { useCallback, useEffect, useState } from "react";

import type { PublicContactKey } from "../lib/storage/contacts";
import {
  addContactEncrypted,
  hasEncryptedContacts,
  hasLegacyContacts,
  loadAndDecryptContacts,
  migrateLegacyContacts,
  removeContactEncrypted,
} from "../lib/storage/contacts";

export function useContacts(masterUnlocked: boolean) {
  const [contacts, setContacts] = useState<PublicContactKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [locked, setLocked] = useState(false);

  const refresh = useCallback(async () => {
    if (!masterUnlocked) {
      const hasEncrypted = await hasEncryptedContacts();
      const hasLegacy = await hasLegacyContacts();
      setLocked(hasEncrypted || hasLegacy);
      setContacts([]);
      setLoading(false);
      return;
    }

    // Migrate legacy plaintext contacts on first unlock.
    try {
      const legacy = await hasLegacyContacts();
      if (legacy) {
        await migrateLegacyContacts();
      }
    } catch {
      // Migration failed - legacy contacts remain, will retry on next refresh.
    }

    try {
      const all = await loadAndDecryptContacts();
      setContacts(all);
      setLocked(false);
    } catch {
      // Decryption failed (corrupted blob, etc.)
      setContacts([]);
      setLocked(true);
    }
    setLoading(false);
  }, [masterUnlocked]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const add = useCallback(
    async (contact: PublicContactKey) => {
      if (!masterUnlocked) return;
      await addContactEncrypted(contact);
      await refresh();
    },
    [masterUnlocked, refresh],
  );

  const remove = useCallback(
    async (keyId: string) => {
      if (!masterUnlocked) return;
      await removeContactEncrypted(keyId);
      await refresh();
    },
    [masterUnlocked, refresh],
  );

  return { contacts, loading, locked, refresh, add, remove };
}
