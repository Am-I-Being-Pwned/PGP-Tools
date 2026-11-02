/**
 * "Unlock keys when the vault unlocks". A key blob sealed under the
 * master's exact `(credentialId, prfSalt)` opens with the master
 * ceremony's PRF output; each blob's fresh `storedSecret` keeps derived
 * AES keys distinct, and the fingerprint AAD still binds each ciphertext.
 * Eligibility is EXACT (credential AND salt); anything else keeps its
 * own prompt.
 *
 * @secret-handling every `prfOutput` here is CALLER-OWNED and never
 * zeroed here (reused across a batch); the caller `.fill(0)`s it.
 */

import { fromBase64, toBase64 } from "~/lib/encoding";
import {
  reprotectKeyWithPrf,
  reprotectSshIdentityWithPrf,
  unlockSshIdentityWithPrf,
  unlockWithPrf,
} from "~/lib/pgp/wasm";
import { storedKeyKind, type StoredKeyKind } from "~/lib/storage/key-kind";
import type { ProtectedKeyBlob } from "~/lib/storage/keyring";
import type { MasterProtection } from "~/lib/storage/master-protection";
import { unpackPrfBlob, type KeyProtection } from "./protected-blob";
import { generateStoredSecret } from "./webauthn-prf";

/** Base64 as stored, so comparisons are plain string equality. */
export interface MasterPasskey {
  credentialId: string;
  /** base64 */
  prfSalt: string;
}

/** The master passkey, or null for a password master (nothing to reuse). */
export function masterPasskeyOf(
  mp: MasterProtection | null,
): MasterPasskey | null {
  if (mp?.method !== "passkey") return null;
  return { credentialId: mp.credentialId, prfSalt: mp.prfSalt };
}

/** True iff the master unlock's PRF output can open this blob. */
export function isSealedUnderMaster(
  blob: ProtectedKeyBlob,
  master: MasterPasskey,
): boolean {
  const p = blob.protection;
  return (
    p.method === "passkey" &&
    p.credentialId === master.credentialId &&
    p.prfSalt === master.prfSalt
  );
}

/** Same credential, different salt: the key's own prompt can also
 *  evaluate the master salt and re-seal it with no extra prompt. */
export function needsMasterReseal(
  blob: ProtectedKeyBlob,
  master: MasterPasskey,
): boolean {
  const p = blob.protection;
  return (
    p.method === "passkey" &&
    p.credentialId === master.credentialId &&
    p.prfSalt !== master.prfSalt
  );
}

export function partitionByMasterSeal(
  keys: ProtectedKeyBlob[],
  master: MasterPasskey,
): { eligible: ProtectedKeyBlob[]; ineligible: ProtectedKeyBlob[] } {
  const eligible: ProtectedKeyBlob[] = [];
  const ineligible: ProtectedKeyBlob[] = [];
  for (const blob of keys) {
    (isSealedUnderMaster(blob, master) ? eligible : ineligible).push(blob);
  }
  return { eligible, ineligible };
}

/**
 * Open one master-sealed blob and return the handle. Callers route this
 * through `KeySessionStore.unlock` for the lock-generation check.
 */
export function openWithMasterPrf(
  blob: ProtectedKeyBlob,
  prfOutput: Uint8Array,
): Promise<number> {
  if (blob.protection.method !== "passkey") {
    return Promise.reject(new Error("Key is not passkey-protected"));
  }
  const ciphertext = fromBase64(blob.encryptedPrivateKey);
  const iv = fromBase64(blob.iv);
  const storedSecret = fromBase64(blob.protection.storedSecret);
  return storedKeyKind(blob) === "ssh"
    ? unlockSshIdentityWithPrf(
        ciphertext,
        iv,
        prfOutput,
        storedSecret,
        blob.keyId,
      )
    : unlockWithPrf(ciphertext, iv, prfOutput, storedSecret, blob.keyId);
}

/** The fields a re-seal replaces; the store applies them under its own
 *  lock so no stale snapshot of other fields is written back. */
export type SealedParts = Pick<
  ProtectedKeyBlob,
  "protection" | "encryptedPrivateKey" | "iv"
>;

/**
 * Re-seal an unlocked key (handle read, not consumed) under the master
 * credential + salt with a fresh `storedSecret`. `prfOutput` MUST be the
 * master salt's output.
 *
 * REFUSES a handle not holding `blob`'s key: otherwise key Y's
 * ciphertext would be stored under key X's id, losing X for good.
 */
export async function resealUnderMaster(
  blob: ProtectedKeyBlob,
  handle: number,
  master: MasterPasskey,
  prfOutput: Uint8Array,
): Promise<SealedParts> {
  const kind: StoredKeyKind = storedKeyKind(blob);
  const storedSecret = new Uint8Array(generateStoredSecret());
  const { meta, blob: packed } =
    kind === "ssh"
      ? await reprotectSshIdentityWithPrf(handle, prfOutput, storedSecret)
      : await reprotectKeyWithPrf(handle, prfOutput, storedSecret);
  if (meta.keyId !== blob.keyId) {
    throw new Error(
      "Re-protect refused: the unlocked key does not match this keyring entry",
    );
  }
  const { iv, ct } = unpackPrfBlob(packed);
  const protection: KeyProtection = {
    method: "passkey",
    credentialId: master.credentialId,
    prfSalt: master.prfSalt,
    storedSecret: toBase64(storedSecret),
  };
  return {
    protection,
    encryptedPrivateKey: toBase64(ct),
    iv: toBase64(iv),
  };
}
