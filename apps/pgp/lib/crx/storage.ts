/**
 * Persistence for CRX signing keys. Uses the same double-envelope
 * encrypted store as the keyring: the array is JSON-serialised then
 * AES-256-GCM encrypted under the in-WASM contacts/master session key
 * before it reaches chrome.storage. See `storage/encrypted-store.ts`.
 */

import { STORAGE_CRX_KEYS } from "../constants";
import {
  loadEncryptedArray,
  saveEncryptedArray,
} from "../storage/encrypted-store";
import { removeItem, withLock } from "../storage/engine";
import type { CrxSigningKeyBlob } from "./types";
import { isCrxSigningKeyBlob } from "./types";

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

export async function getCrxKeys(): Promise<CrxSigningKeyBlob[]> {
  return loadEncrypted();
}

export async function addCrxKey(blob: CrxSigningKeyBlob): Promise<void> {
  await withLock(STORAGE_CRX_KEYS, async () => {
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
    const keys = await loadEncrypted();
    const updated = keys.filter((k) => k.extensionId !== extensionId);
    if (updated.length === 0) {
      await removeItem(STORAGE_CRX_KEYS);
    } else {
      await saveAll(updated);
    }
  });
}

export async function updateCrxLastUsed(extensionId: string): Promise<void> {
  await withLock(STORAGE_CRX_KEYS, async () => {
    const keys = await loadEncrypted();
    const key = keys.find((k) => k.extensionId === extensionId);
    if (key) {
      key.lastUsedAt = Date.now();
      await saveAll(keys);
    }
  });
}
