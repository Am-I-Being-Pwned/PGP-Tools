/**
 * ============================================================================
 * "Unlock keys when the vault unlocks" -- eligibility, unlock, re-seal.
 * ============================================================================
 *
 * The master passkey unlock is one WebAuthn ceremony that yields one PRF
 * output for the master's `(credentialId, prfSalt)`. A key blob sealed
 * under that SAME credential and salt can be opened with that same
 * output: each blob keeps its own fresh `storedSecret` (the HKDF salt), so
 * the derived AES keys stay distinct per blob, and the per-key fingerprint
 * AAD still binds each ciphertext to its key. No new crypto -- this is
 * exactly how onboarding's first key has always been sealed.
 *
 * Everything else is bookkeeping, and it lives here:
 *
 *   - {@link isSealedUnderMaster}: the eligibility test. It is EXACT --
 *     credential AND salt must match. A key on a different passkey, on the
 *     master passkey but its own salt, or on a password is left alone and
 *     keeps its per-key prompt.
 *   - {@link openWithMasterPrf}: unlock one eligible blob with the master
 *     PRF output, dispatching on engine (PGP vs SSH) like `useKeySession`
 *     does for the per-key paths.
 *   - {@link needsMasterReseal}: a key on the master CREDENTIAL but its
 *     own salt. Its own prompt can carry the master salt as the PRF
 *     extension's second evaluation, so the unlock the user is already
 *     doing also yields what is needed to re-seal it -- no extra prompt,
 *     no migration step. `useKeySession.unlockWithPasskey` does this.
 *   - {@link resealUnderMaster}: that re-seal. Re-seals an unlocked key
 *     (by handle, plaintext never crosses to JS) under the master
 *     credential + salt with a fresh stored secret.
 *
 * @secret-handling every `prfOutput` here is CALLER-OWNED. Nothing in
 * this module zeroes it, because the same output is deliberately used for
 * several blobs in a row (one ceremony, many keys) -- the same ownership
 * rule `protect-runner.ts` states for `prfReuse`. The caller `.fill(0)`s
 * it in a `finally` once the batch is done.
 */

import type { StoredKeyKind } from "../storage/key-kind";
import type { ProtectedKeyBlob } from "../storage/keyring";
import type { MasterProtection } from "../storage/master-protection";
import type { KeyProtection } from "./protected-blob";
import { fromBase64, toBase64 } from "../encoding";
import {
  reprotectKeyWithPrf,
  reprotectSshIdentityWithPrf,
  unlockSshIdentityWithPrf,
  unlockWithPrf,
} from "../pgp/wasm";
import { storedKeyKind } from "../storage/key-kind";
import { unpackPrfBlob } from "./protected-blob";
import { generateStoredSecret } from "./webauthn-prf";

/** The two public halves of the master passkey that decide eligibility.
 *  Both base64 as stored, so comparisons are plain string equality. */
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

/** True iff this key's OWN passkey prompt can also produce the master
 *  salt's output: same credential, different salt. A key on another
 *  passkey cannot (the ceremony is with the wrong authenticator secret);
 *  a password key has no ceremony at all; a master-sealed key needs
 *  nothing. */
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

/** Split a keyring into the keys the vault ceremony opens and the ones
 *  that keep their own prompt. */
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
 * Open one master-sealed blob into its engine's store and return the
 * handle. The caller routes this through `KeySessionStore.unlock` so the
 * lock-generation check brackets it like every other unlock.
 *
 * Throws on a blob that is not master-sealed: a caller that got here
 * without checking {@link isSealedUnderMaster} would otherwise get an
 * opaque AEAD failure, which the UI reports as a wrong credential.
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

/** The three fields a re-seal replaces on a stored blob. Everything else
 *  (identity, public half, alias, revocation cert, timestamps, `kind`)
 *  is left to the store, which applies these under its own lock so no
 *  stale snapshot of the other fields is ever written back. */
export type SealedParts = Pick<
  ProtectedKeyBlob,
  "protection" | "encryptedPrivateKey" | "iv"
>;

/**
 * Re-seal an unlocked key under the master credential + salt.
 *
 * `handle` is the key's live handle in the store `kind` names -- it is
 * read, not consumed, so the key stays unlocked afterwards. Returns only
 * the fields that change; persist them with `replaceKeyProtection`.
 *
 * `prfOutput` MUST be the output for the master's salt (the caller ran
 * that ceremony); a fresh `storedSecret` is generated per call so the
 * re-sealed blob's AES key is distinct from the vault's and from every
 * other migrated key's.
 *
 * REFUSES a handle that does not hold `blob`'s key. Wasm derives the AAD
 * from the key the handle holds and reports that identity back; if it is
 * not `blob.keyId`, writing the result would store key Y's ciphertext
 * under key X's id -- X gone for good, and Y's blob unopenable under X's
 * AAD. Handles are monotonic and never reused, so this is not reachable
 * today; the check is what keeps that a property rather than a hope.
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
