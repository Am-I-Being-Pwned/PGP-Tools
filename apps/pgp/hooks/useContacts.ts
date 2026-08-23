import { useCallback, useEffect, useRef, useState } from "react";

import type { PublicContactKey } from "../lib/storage/contacts";
import { parseKey } from "../lib/pgp/wasm";
import {
  loadContacts,
  removeContact,
  saveContact,
} from "../lib/storage/contacts";
import { isSshRecord } from "../lib/storage/key-kind";

/** One-time backfill: older versions never stored `expiresAt` (or
 *  `securityWarning`), so contact cards couldn't flag expired keys.
 *  Parse each legacy contact's armor once and persist the result --
 *  `expiresAt: null` marks "never expires", so `undefined` (not yet
 *  computed) can't recur and re-parse on every load. Returns the
 *  patched contacts, or [] when there was nothing to do.
 *
 *  An SSH contact needs BOTH halves of that rule and gets them here: it
 *  is skipped (its "armor" is a recipient line, which the OpenPGP parser
 *  throws on) AND written back with `expiresAt: null` (age keys never
 *  expire). Skipping alone would leave `undefined` on the record, so the
 *  refresh below would queue the same doomed parse again on every load,
 *  forever; writing alone would still parse it once per key. */
async function backfillExpiry(
  contacts: PublicContactKey[],
): Promise<PublicContactKey[]> {
  const patched: PublicContactKey[] = [];
  for (const c of contacts) {
    if (c.expiresAt !== undefined) continue;
    if (isSshRecord(c)) {
      // No parse: an SSH key has no expiry, no signing capability and no
      // SHA-1 problem to report. Persisting `null` closes the loop.
      const updated: PublicContactKey = { ...c, expiresAt: null };
      await saveContact(updated);
      patched.push(updated);
      continue;
    }
    try {
      const info = await parseKey(c.armoredPublicKey);
      const updated: PublicContactKey = {
        ...c,
        expiresAt: info.expiresAt,
        usableForEncryption: info.usableForEncryption,
        securityWarning: c.securityWarning ?? info.securityWarning,
      };
      await saveContact(updated);
      patched.push(updated);
    } catch {
      // Unparseable armor: leave untouched; the card just won't warn.
    }
  }
  return patched;
}

export function useContacts() {
  const [contacts, setContacts] = useState<PublicContactKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const mutexRef = useRef<Promise<void>>(Promise.resolve());

  /** Same contract as `useKeyring.refresh`: the store throws when the
   *  session key can't open the blob, and an unhandled throw here would
   *  render as "no contacts" rather than "these could not be read". See
   *  the long note in `useKeyring`. */
  const refresh = useCallback(async () => {
    let all: PublicContactKey[];
    try {
      all = await loadContacts();
    } catch (e) {
      setContacts([]);
      setError(e instanceof Error ? e : new Error(String(e)));
      setLoading(false);
      return;
    }
    setContacts(all);
    setError(null);
    setLoading(false);

    // Backfill legacy contacts in the background, serialized behind the
    // same mutex as add/remove so we never interleave saves.
    if (all.some((c) => c.expiresAt === undefined)) {
      const op = mutexRef.current.then(async () => {
        const patched = await backfillExpiry(all);
        if (patched.length > 0) {
          setContacts((prev) =>
            prev.map((c) => patched.find((p) => p.keyId === c.keyId) ?? c),
          );
        }
      });
      // eslint-disable-next-line @typescript-eslint/no-empty-function
      mutexRef.current = op.catch(() => {});
    }
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

  return { contacts, loading, error, refresh, add, remove };
}
