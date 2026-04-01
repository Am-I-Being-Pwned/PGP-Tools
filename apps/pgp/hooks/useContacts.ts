import { useCallback, useEffect, useRef, useState } from "react";

import type { MasterProtection } from "../lib/storage/master-protection";
import type { PublicContactKey } from "../lib/storage/contacts";
import { fromBase64 } from "../lib/encoding";
import * as wasmApi from "../lib/pgp/wasm";
import { authenticateAndGetPrf } from "../lib/protection/webauthn-prf";
import {
  deleteContactsBlob,
  encryptAndSaveContacts,
  hasEncryptedContacts,
  hasLegacyContacts,
  loadAndDecryptContacts,
  migrateLegacyContacts,
} from "../lib/storage/contacts";

// ── Ephemeral WASM session helper ───────────────────────────────────

/**
 * Ensure a WASM contacts session is active, run `fn`, then drop the key.
 * If a session is already active (e.g. from the master unlock screen),
 * reuses it without requiring an additional authenticator tap.
 */
async function withPasskeySession<T>(
  mp: MasterProtection & { method: "passkey" },
  fn: () => Promise<T>,
): Promise<T> {
  const alreadyActive = await wasmApi.hasContactsSession();

  if (!alreadyActive) {
    let prfOutput: Uint8Array | undefined;
    const storedSecretBytes = new Uint8Array(fromBase64(mp.storedSecret));
    try {
      ({ prfOutput } = await authenticateAndGetPrf(
        mp.credentialId,
        fromBase64(mp.prfSalt),
      ));
      await wasmApi.initContactsSessionWithPrf(prfOutput, storedSecretBytes);
    } finally {
      prfOutput?.fill(0);
      storedSecretBytes.fill(0);
    }
  }

  try {
    return await fn();
  } finally {
    void wasmApi.dropContactsSession();
  }
}

/**
 * Run `fn` with an active WASM contacts session.
 * - Passkey: ephemeral session (one authenticator tap), dropped after.
 * - Password: session is already active for the duration of the master unlock.
 */
async function withContactsSession<T>(
  mp: MasterProtection,
  fn: () => Promise<T>,
): Promise<T> {
  if (mp.method === "passkey") {
    return withPasskeySession(mp, fn);
  }
  // Password: session persists, just run directly.
  return fn();
}

// ── Hook ────────────────────────────────────────────────────────────

export function useContacts(
  masterUnlocked: boolean,
  masterProtection: MasterProtection | null,
) {
  const [contacts, setContacts] = useState<PublicContactKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [locked, setLocked] = useState(false);

  // Mutex to serialize mutations (replaces the removed withLock from storage layer).
  const mutexRef = useRef<Promise<void>>(Promise.resolve());

  const refresh = useCallback(async () => {
    if (!masterUnlocked || !masterProtection) {
      const hasEncrypted = await hasEncryptedContacts();
      const hasLegacy = await hasLegacyContacts();
      setLocked(hasEncrypted || hasLegacy);
      setContacts([]);
      setLoading(false);
      return;
    }

    try {
      await withContactsSession(masterProtection, async () => {
        // Migrate legacy plaintext contacts if needed.
        const legacy = await hasLegacyContacts();
        if (legacy) {
          await migrateLegacyContacts();
        }

        const all = await loadAndDecryptContacts();
        setContacts(all);
        setLocked(false);
      });
    } catch {
      setContacts([]);
      setLocked(true);
    }
    setLoading(false);
  }, [masterUnlocked, masterProtection]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const add = useCallback(
    async (contact: PublicContactKey) => {
      if (!masterUnlocked || !masterProtection) return;

      // Serialize with other mutations to prevent lost writes.
      const op = mutexRef.current.then(async () => {
        // Use functional update to avoid stale closure.
        let updated: PublicContactKey[] = [];
        let existing: PublicContactKey | undefined;
        setContacts((prev) => {
          existing = prev.find((c) => c.keyId === contact.keyId);
          updated = [...prev.filter((c) => c.keyId !== contact.keyId), contact];
          return updated;
        });

        try {
          await withContactsSession(masterProtection, () =>
            encryptAndSaveContacts(updated),
          );
        } catch (e) {
          // Rollback: restore previous version of the contact (or remove if new).
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
    },
    [masterUnlocked, masterProtection],
  );

  const remove = useCallback(
    async (keyId: string) => {
      if (!masterUnlocked || !masterProtection) return;

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
            // No contacts left — delete the blob instead of encrypting empty.
            await deleteContactsBlob();
          } else {
            await withContactsSession(masterProtection, () =>
              encryptAndSaveContacts(updated),
            );
          }
        } catch (e) {
          // Rollback: re-add the removed contact.
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
    },
    [masterUnlocked, masterProtection],
  );

  return { contacts, loading, locked, refresh, add, remove };
}
