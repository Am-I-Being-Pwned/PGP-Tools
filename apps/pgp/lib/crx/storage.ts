/**
 * Persistence for CRX signing keys. Uses the same generic protected-key
 * store as the keyring (`storage/protected-store.ts`): the array is
 * JSON-serialised then AES-256-GCM sealed under a subkey of the in-WASM
 * contacts/master session key, domain-separated by this store's own
 * storage key, before it reaches chrome.storage. See
 * `storage/encrypted-store.ts`.
 *
 * Two things here are NOT shared with the keyring, both deliberate:
 * the identity check in `addCrxKey`, and the session guard below.
 */

import type { CrxSigningKeyBlob } from "./types";
import { STORAGE_CRX_KEYS } from "../constants";
import { AppError } from "../errors/app-error";
import { hasContactsSession } from "../pgp/wasm";
import { createProtectedStore } from "../storage/protected-store";
import { extensionIdFromPublicKeyDer, isCrxSigningKeyBlob } from "./types";

const crxStore = createProtectedStore<CrxSigningKeyBlob>({
  storageKey: STORAGE_CRX_KEYS,
  isValid: isCrxSigningKeyBlob,
  label: "crx-keys",
  idOf: (blob) => blob.extensionId,
});

/** One-time upgrade of a CRX-keys blob to canonical padding and to the
 *  domain-bound sealing envelope. */
export function normalizeCrxPadding(): Promise<void> {
  return crxStore.normalize();
}

/** Mutations must not run without the vault session: the load returns []
 *  while locked (indistinguishable from an empty store), so a
 *  read-modify-write here would silently drop every stored key. */
function requireSession(action: string): () => Promise<boolean> {
  return async () => {
    if (!(await hasContactsSession())) {
      throw new AppError(
        "vault-locked",
        `Cannot ${action}: the vault is locked`,
      );
    }
    return true;
  };
}

export async function getCrxKeys(): Promise<CrxSigningKeyBlob[]> {
  return crxStore.getAll();
}

export async function addCrxKey(blob: CrxSigningKeyBlob): Promise<void> {
  // The public half is not AEAD-covered, so never store a blob whose
  // publicKeyDerB64 doesn't hash to its claimed extensionId (a tampered
  // backup could otherwise plant a foreign public key under a real id).
  if (
    (await extensionIdFromPublicKeyDer(blob.publicKeyDerB64)) !==
    blob.extensionId
  ) {
    throw new Error(
      "Rejected CRX signing key: its public key does not match its extension id",
    );
  }
  await crxStore.put(blob, { guard: requireSession("save CRX signing key") });
}

export async function removeCrxKey(extensionId: string): Promise<void> {
  await crxStore.remove(extensionId, {
    guard: requireSession("delete CRX signing key"),
  });
}

/** Set (or clear, with a blank value) a CRX key's user-facing label. */
export async function updateCrxLabel(
  extensionId: string,
  label: string,
): Promise<void> {
  const trimmed = label.trim();
  await crxStore.update(
    extensionId,
    (key) => {
      key.label = trimmed || undefined;
    },
    { guard: requireSession("rename CRX signing key") },
  );
}

export async function updateCrxLastUsed(extensionId: string): Promise<void> {
  await crxStore.update(
    extensionId,
    (key) => {
      key.lastUsedAt = Date.now();
    },
    // Metadata-only write: a CRX key unlocks with its own password/PRF, not
    // the master session, so signing can legitimately outlive it. Skip the
    // timestamp rather than failing the signing act.
    { guard: () => hasContactsSession() },
  );
}
