/**
 * The `{ iv, ciphertext }` envelope every master-session-protected store
 * writes, bound to its slot.
 *
 * Domain separation: the domain is always the chrome.storage KEY the blob
 * lives under (not the area, so a blob can still move local<->sync). The
 * wasm side derives both an HKDF subkey and the AAD from it
 * (`gpg-tools:store-subkey:v1:<domain>` / `gpg-tools:store:v1:<domain>`),
 * so a blob only opens in the slot it was written to -- an attacker who can
 * write storage can't replay one store/segment into another.
 *
 * Migration: {@link openEnvelope} falls back to the legacy shared-key/AAD
 * scheme and reports `legacy: true`; callers re-seal when safe. The
 * fallback is unconditional (no version flag that could itself be lost),
 * since it is all that keeps an upgrading user's keyring readable.
 */

import { fromBase64, toBase64, unpackIvCiphertext } from "~/lib/encoding";
import { decryptContacts, decryptStore, encryptStore } from "~/lib/pgp/wasm";

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

/** Seal `plaintext` for `domain` (always its storage key). The caller owns
 *  `plaintext` and should zeroize it. */
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
  /** Sealed under the pre-v1 shared scheme; re-seal when safe (holding
   *  the store's lock). */
  legacy: boolean;
}

/**
 * Open a blob for `domain`, accepting either scheme. Domain-bound goes
 * first so a domain-bound blob can never be reinterpreted through the
 * legacy path. Throws (with the domain-bound error) when neither opens,
 * including when the vault is locked.
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
