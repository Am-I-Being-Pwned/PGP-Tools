import { contactRecipients } from "~/lib/storage/contact-recipients";
import type { ContactSource, PublicContactKey } from "~/lib/storage/contacts";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";

/** A stored key an import can collide with; `armored` tells a no-op re-import from a change. */
export interface StoredKey {
  keyId: string;
  userIds: string[];
  /** PUBLIC armor only. */
  armored: string;
  addedAt?: number;
  createdAt?: number;
  expiresAt?: number | null;
  /** Where a fetched contact came from; absent when hand-supplied. */
  source?: ContactSource;
  /** A revoked key no longer holds its address (see identity/binding). */
  revoked?: boolean;
  /** Every key a multi-key contact holds; an SSH import is checked against all of them. */
  recipientIds?: string[];
  /** The user's local name for it: names conflicts, and is compared against imports. */
  alias?: string;
}

export interface StoredKeys {
  /** The user's own keys (keyring), matched against private imports. */
  own: StoredKey[];
  /** Contacts, matched against public imports. */
  contacts: StoredKey[];
}

/** The keyring and contacts as every `prepare*` entry point takes them. One
 *  builder so import and backup restore classify against the same facts. */
export function storedKeysFrom(
  own: readonly ProtectedKeyBlob[],
  contacts: readonly PublicContactKey[],
): StoredKeys {
  return {
    own: own.map((k) => ({
      keyId: k.keyId,
      userIds: k.userIds,
      armored: k.publicKeyArmored,
      createdAt: k.createdAt,
      ...(k.alias ? { alias: k.alias } : {}),
    })),
    contacts: contacts.map((c) => ({
      keyId: c.keyId,
      userIds: c.userIds,
      armored: c.armoredPublicKey,
      addedAt: c.addedAt,
      expiresAt: c.expiresAt,
      ...(c.source ? { source: c.source } : {}),
      ...(c.revoked ? { revoked: true } : {}),
      ...(c.recipients
        ? { recipientIds: contactRecipients(c).map((r) => r.keyId) }
        : {}),
      ...(c.alias ? { alias: c.alias } : {}),
    })),
  };
}

export function storedKeyIds(record: StoredKey): string[] {
  return record.recipientIds && record.recipientIds.length > 0
    ? record.recipientIds
    : [record.keyId];
}
