import { useCallback, useEffect, useRef, useState } from "react";

import type { PublicContactKey } from "../lib/storage/contacts";
import { parseKey } from "../lib/pgp/wasm";
import {
  loadContacts,
  removeContact,
  saveContact,
  updateContact,
  updateContactAlias,
  upsertContacts,
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
    // Parsed here, applied through `updateContact` -- which re-reads the
    // record inside the store's lock. Saving `{ ...c, expiresAt }`
    // instead would republish this whole snapshot, silently reverting
    // anything written to that contact since the load that produced it
    // (the recipient toggle is one full load+save per contact away).
    let patch: Partial<PublicContactKey>;
    if (isSshRecord(c)) {
      // No parse: an SSH key has no expiry, no signing capability and no
      // SHA-1 problem to report. Persisting `null` closes the loop.
      patch = { expiresAt: null };
    } else {
      try {
        const info = await parseKey(c.armoredPublicKey);
        patch = {
          expiresAt: info.expiresAt,
          usableForEncryption: info.usableForEncryption,
          ...(info.securityWarning
            ? { securityWarning: info.securityWarning }
            : {}),
        };
      } catch {
        // Unparseable armor: leave untouched; the card just won't warn.
        continue;
      }
    }
    const updated = await updateContact(c.keyId, (current) => ({
      // `current` first: it is the record as it is on disk right now, and
      // spreading it first also keeps its existing keys in their existing
      // order, so a backfilled record differs from the stored one by
      // exactly the fields being backfilled.
      ...current,
      ...patch,
      // Never overwrite a warning the stored record already carries.
      ...(current.securityWarning
        ? { securityWarning: current.securityWarning }
        : {}),
    }));
    if (updated) patched.push(updated);
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
      // The SAME rules `saveContact` applies, from the same function --
      // source-based identity, a hand-pasted duplicate that must not
      // replace a fetched person, `disabled` carried forward. This list
      // is what the Keys tab and the recipient picker render, and a
      // weaker rule here does not merely look wrong: a re-fetched GitHub
      // contact whose first key stopped being published gets a NEW
      // keyId, so a keyId-only filter would leave the superseded record
      // on screen (and selectable as a recipient) even though storage
      // holds exactly one contact.
      let previous: PublicContactKey[] = [];
      setContacts((prev) => {
        previous = prev;
        return upsertContacts(prev, contact);
      });

      try {
        await saveContact(contact);
      } catch (e) {
        setContacts(previous);
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

  /** Set (or clear, with a blank value) a contact's local display name.
   *  Same shape as `useKeyring.rename`: the store owns the write, and
   *  the list is re-read rather than patched, so the record on screen is
   *  the record on disk -- including anything else that changed under
   *  the lock. */
  const rename = useCallback(
    async (keyId: string, alias: string) => {
      const op = mutexRef.current.then(() => updateContactAlias(keyId, alias));
      // eslint-disable-next-line @typescript-eslint/no-empty-function
      mutexRef.current = op.catch(() => {});
      await op;
      await refresh();
    },
    [refresh],
  );

  return { contacts, loading, error, refresh, add, remove, rename };
}
