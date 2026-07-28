/**
 * The `{ iv, ciphertext }` envelope every master-session-protected store
 * writes, and the one place that knows how it is bound to its slot.
 *
 * ## Domain separation
 *
 * Each blob is sealed for a **domain**, and the domain is always the
 * browser.storage key the blob lives under (`pgp_keyring`,
 * `pgp_public_contacts`, `pgp_settings`, `pgp_crx_keys`,
 * `pgp_history_seg_<n>`). The wasm side derives BOTH an HKDF subkey and
 * the AEAD's AAD from it (`gpg-tools:store-subkey:v1:<domain>` /
 * `gpg-tools:store:v1:<domain>`), so a sealed blob only opens in the slot
 * it was written to.
 *
 * Using the storage key itself as the domain is deliberate: there is no
 * mapping table to keep in sync, the read and the write path cannot
 * disagree about which domain a slot uses, and "the blob is bound to
 * where it is stored" is checkable by eye at every call site. It is
 * NOT the storage *area*, so `copyEncryptedBlobRepacked` can still move a
 * blob between `local` and `sync` under the same key.
 *
 * ## Why (the bug this closes)
 *
 * Before this, every store was sealed under the raw contacts session key
 * with one fixed shared AAD, and nothing in the sealed data named the
 * store or the segment. Confidentiality was fine; integrity was not.
 * Anyone able to write browser.storage -- with NO knowledge of the vault
 * key -- could copy `pgp_history_seg_0` to `pgp_history_seg_1` and have
 * it adopted as a real segment, or drop it on `pgp_public_contacts` and
 * silently empty the user's contact list. Both fail the tag check now.
 *
 * ## Migration (read old, write new)
 *
 * {@link openEnvelope} tries the domain-bound scheme first and falls back
 * to the legacy shared one, reporting which it used via
 * `legacy: true`. Callers re-seal when it is safe for them to write (see
 * each call site). Legacy blobs therefore keep opening forever; the
 * fallback is the only thing standing between an upgrading user and an
 * unreadable keyring, so it is not conditional on any version marker or
 * migration flag that could itself be lost.
 */

import { fromBase64, toBase64, unpackIvCiphertext } from "../encoding";
import { decryptContacts, decryptStore, encryptStore } from "../pgp/wasm";

/** The persisted shape: base64 IV + base64 AES-256-GCM ciphertext. */
export interface StoredEnvelope {
  iv: string;
  ciphertext: string;
}

export function isStoredEnvelope(v: unknown): v is StoredEnvelope {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return typeof o.iv === "string" && typeof o.ciphertext === "string";
}

/**
 * Seal `plaintext` for `domain` (always the storage key it will be
 * written to). The caller owns `plaintext` and should zeroize it.
 */
export async function sealEnvelope(
  domain: string,
  plaintext: Uint8Array,
): Promise<StoredEnvelope> {
  const packed = await encryptStore(domain, plaintext);
  const { iv, ciphertext } = unpackIvCiphertext(packed);
  return { iv: toBase64(iv), ciphertext: toBase64(ciphertext) };
}

export interface OpenedEnvelope {
  /** Decrypted bytes. The caller owns them and should `.fill(0)` them. */
  plaintext: Uint8Array;
  /**
   * True when the blob was sealed under the pre-v1 shared-key/shared-AAD
   * scheme, i.e. it was written by a shipped version before domain
   * separation existed. The caller should re-seal it when it can do so
   * safely (holding the store's lock).
   */
  legacy: boolean;
}

/**
 * Open a blob for `domain`, accepting either scheme.
 *
 * Order matters: the domain-bound attempt goes first so that the common
 * (post-migration) case costs one AEAD open, and so a blob that *is*
 * domain-bound can never be reinterpreted through the legacy path. Only
 * when the tag check fails do we try the legacy binding.
 *
 * Throws when neither opens -- the error surfaced is the domain-bound
 * one, since that is the scheme the store is supposed to be using. A
 * locked vault also lands here (both attempts report no session).
 */
export async function openEnvelope(
  domain: string,
  blob: StoredEnvelope,
): Promise<OpenedEnvelope> {
  const ciphertext = fromBase64(blob.ciphertext);
  const iv = fromBase64(blob.iv);
  try {
    return {
      plaintext: await decryptStore(domain, ciphertext, iv),
      legacy: false,
    };
  } catch (err) {
    try {
      return { plaintext: await decryptContacts(ciphertext, iv), legacy: true };
    } catch {
      throw err;
    }
  }
}
