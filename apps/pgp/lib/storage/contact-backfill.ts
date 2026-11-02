import type { PublicContactKey } from "./contacts";
import { parseKey } from "../pgp/wasm";
import { IDENTITY_VERSION, updateContact } from "./contacts";
import { isSshRecord } from "./key-kind";

/** Fields older versions never stored, derived once per record. Each
 *  patch is applied through `updateContact`, inside the store's lock, so
 *  it never republishes a stale snapshot of the rest of the record. */
export function needsBackfill(c: PublicContactKey): boolean {
  return (
    c.expiresAt === undefined || (c.identityVersion ?? 0) < IDENTITY_VERSION
  );
}

/** `expiresAt` (null = never), plus the parse-derived flags. An SSH key
 *  is not parsed (its armor is a recipient line) but still gets `null`,
 *  or it would be re-queued on every load. */
async function backfillExpiry(c: PublicContactKey): Promise<void> {
  if (c.expiresAt !== undefined) return;
  let patch: Partial<PublicContactKey>;
  if (isSshRecord(c)) {
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
      return; // Unparseable armor: the card just won't warn.
    }
  }
  await updateContact(c.keyId, (current) => ({
    ...current,
    ...patch,
    // Never overwrite a warning the stored record already carries.
    ...(current.securityWarning
      ? { securityWarning: current.securityWarning }
      : {}),
  }));
}

/** Re-derive identity fields for records stored before
 *  {@link IDENTITY_VERSION}. Unparseable armor is still marked checked. */
export async function backfillIdentity(c: PublicContactKey): Promise<void> {
  if ((c.identityVersion ?? 0) >= IDENTITY_VERSION) return;
  let patch: Partial<PublicContactKey> = { identityVersion: IDENTITY_VERSION };
  if (!isSshRecord(c)) {
    try {
      const info = await parseKey(c.armoredPublicKey);
      patch = {
        ...patch,
        userIds: info.userIds,
        usableForEncryption: info.usableForEncryption,
        ...(info.revoked ? { revoked: true } : {}),
        ...(info.lookalike ? { lookalike: true } : {}),
        ...(info.securityWarning
          ? { securityWarning: info.securityWarning }
          : {}),
      };
    } catch {
      // Mark it checked and leave the rest alone.
    }
  }
  await updateContact(c.keyId, (current) => ({ ...current, ...patch }));
}

let running: Promise<void> | null = null;

/** Backfill every record that needs it, one pass at a time: each write
 *  reloads the list, and that reload must not start a second pass. */
export function backfillContacts(contacts: PublicContactKey[]): void {
  if (running || !contacts.some(needsBackfill)) return;
  running = (async () => {
    for (const c of contacts.filter(needsBackfill)) {
      await backfillExpiry(c);
      await backfillIdentity(c);
    }
  })()
    .catch(() => undefined)
    .finally(() => {
      running = null;
    });
}
