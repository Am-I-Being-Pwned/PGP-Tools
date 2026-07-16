/**
 * Persistence for CRX signing keys. Uses the same double-envelope
 * encrypted store as the keyring: the array is JSON-serialised then
 * AES-256-GCM encrypted under the in-WASM contacts/master session key
 * before it reaches chrome.storage. See `storage/encrypted-store.ts`.
 */

import type { CrxSigningKeyBlob } from "./types";
import { STORAGE_CRX_KEYS } from "../constants";
import { AppError } from "../errors/app-error";
import { hasContactsSession } from "../pgp/wasm";
import {
  loadEncryptedArray,
  normalizePadding,
  saveEncryptedArray,
} from "../storage/encrypted-store";
import { removeItem, withLock } from "../storage/engine";
import { extensionIdFromPublicKeyDer, isCrxSigningKeyBlob } from "./types";

const CRX_STORE = {
  storageKey: STORAGE_CRX_KEYS,
  isValid: isCrxSigningKeyBlob,
  label: "crx-keys",
};

function loadEncrypted(): Promise<CrxSigningKeyBlob[]> {
  return loadEncryptedArray(CRX_STORE);
}

function saveAll(keys: CrxSigningKeyBlob[]): Promise<void> {
  return saveEncryptedArray(CRX_STORE, keys);
}

/** One-time upgrade of an unpadded CRX-keys blob to canonical padding. */
export function normalizeCrxPadding(): Promise<void> {
  return normalizePadding(CRX_STORE);
}

/** Mutations must not run without the vault session: `loadEncrypted`
 *  returns [] while locked (indistinguishable from an empty store), so a
 *  read-modify-write here would silently drop every stored key. */
async function requireSession(action: string): Promise<void> {
  if (!(await hasContactsSession())) {
    throw new AppError("vault-locked", `Cannot ${action}: the vault is locked`);
  }
}

export async function getCrxKeys(): Promise<CrxSigningKeyBlob[]> {
  return loadEncrypted();
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
  await withLock(STORAGE_CRX_KEYS, async () => {
    await requireSession("save CRX signing key");
    const keys = await loadEncrypted();
    const updated = [
      ...keys.filter((k) => k.extensionId !== blob.extensionId),
      blob,
    ];
    await saveAll(updated);
  });
}

export async function removeCrxKey(extensionId: string): Promise<void> {
  await withLock(STORAGE_CRX_KEYS, async () => {
    await requireSession("delete CRX signing key");
    const keys = await loadEncrypted();
    const updated = keys.filter((k) => k.extensionId !== extensionId);
    if (updated.length === 0) {
      await removeItem(STORAGE_CRX_KEYS);
    } else {
      await saveAll(updated);
    }
  });
}

/** Set (or clear, with a blank value) a CRX key's user-facing label. */
export async function updateCrxLabel(
  extensionId: string,
  label: string,
): Promise<void> {
  const trimmed = label.trim();
  await withLock(STORAGE_CRX_KEYS, async () => {
    await requireSession("rename CRX signing key");
    const keys = await loadEncrypted();
    const key = keys.find((k) => k.extensionId === extensionId);
    if (key) {
      key.label = trimmed || undefined;
      await saveAll(keys);
    }
  });
}

export async function updateCrxLastUsed(extensionId: string): Promise<void> {
  await withLock(STORAGE_CRX_KEYS, async () => {
    // Metadata-only write: a CRX key unlocks with its own password/PRF, not
    // the master session, so signing can legitimately outlive it. Skip the
    // timestamp rather than failing the signing act.
    if (!(await hasContactsSession())) return;
    const keys = await loadEncrypted();
    const key = keys.find((k) => k.extensionId === extensionId);
    if (key) {
      key.lastUsedAt = Date.now();
      await saveAll(keys);
    }
  });
}
