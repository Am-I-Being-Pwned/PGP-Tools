/**
 * ============================================================================
 * Public-side wasm wrappers — NO SECRET KEY MATERIAL CROSSES THIS BOUNDARY.
 * ============================================================================
 *
 * Every function in this file fits one of:
 *   - takes only public material (armored public keys, public metadata,
 *     ciphertext, signed messages, opaque integer handles)
 *   - returns only public material (public-key info, ciphertext,
 *     verification result, signature)
 *   - manipulates the WASM-side `KEY_STORE` indirectly (via opaque
 *     handle); the cert never returns to JS
 *
 * If you need a wrapper that takes a typed password / passphrase / PRF
 * output, OR returns plaintext private-key bytes, it goes in
 * `wasm-secrets.ts` instead.
 *
 * See `apps/pgp/SECURITY.md` §3 for the full file map.
 */

import type { KeyInfo } from "./types";
import { loadWasm } from "./wasm-loader";

// ── status / metadata ────────────────────────────────────────────────

export async function ping(): Promise<string> {
  const wasm = await loadWasm();
  return wasm.ping();
}

/** Parse an armored key for metadata only. Accepts public OR private
 *  armor; the secret material (if present) is parsed by Sequoia into
 *  its `Protected` containers and dropped at the end of the call. */
export async function parseKey(armored: string): Promise<KeyInfo> {
  const wasm = await loadWasm();
  const json = wasm.parseKey(armored);
  return JSON.parse(json) as KeyInfo;
}

/** Strip the secret half of a private key, returning the armored
 *  public-only cert. The secret material is parsed and dropped inside
 *  the wasm call. */
export async function extractPublicKey(
  armoredPrivateKey: string,
): Promise<string> {
  const wasm = await loadWasm();
  return wasm.extractPublicKey(armoredPrivateKey);
}

/** True iff the armored key contains any S2K-passphrase-protected
 *  secret packet. Pure metadata. */
export async function isSecretEncrypted(armored: string): Promise<boolean> {
  const wasm = await loadWasm();
  return wasm.isSecretEncrypted(armored);
}

// ── encrypt / sign / verify (public-key crypto only) ─────────────────

export async function encrypt(
  plaintext: Uint8Array,
  recipientPublicKeys: string[],
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.encrypt(plaintext, JSON.stringify(recipientPublicKeys), null);
}

export interface SignatureInfo {
  signatureValid: boolean | null;
  signerKeyId: string | null;
}

export interface VerifyResultWasm {
  text: string;
  signatureValid: boolean;
  signerKeyId: string | null;
}

export async function verify(
  signedMessage: string,
  verificationPublicKeys: string[],
): Promise<VerifyResultWasm> {
  const wasm = await loadWasm();
  const json = wasm.verify(
    signedMessage,
    JSON.stringify(verificationPublicKeys),
  );
  return JSON.parse(json) as VerifyResultWasm;
}

// ── handle-mediated operations ───────────────────────────────────────
// These take a u32 handle into KEY_STORE. The cert is materialised
// transiently inside wasm and dropped at function exit; the handle is
// the JS side's only view of it.

export async function encryptWithSigningHandle(
  plaintext: Uint8Array,
  recipientPublicKeys: string[],
  signingKeyHandle: number,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.encryptWithSigningHandle(
    plaintext,
    JSON.stringify(recipientPublicKeys),
    signingKeyHandle,
  );
}

export interface DecryptWithHandleResult {
  /** The user's plaintext message bytes. NOTE: this is *user data*,
   *  not key material. It crosses to JS by design (the user reads it). */
  plaintext: Uint8Array;
  signatureInfo: SignatureInfo;
}

export async function decryptWithHandle(
  ciphertext: Uint8Array,
  keyHandle: number,
  verificationPublicKeys?: string[],
): Promise<DecryptWithHandleResult> {
  const wasm = await loadWasm();
  const packed = wasm.decryptWithHandle(
    ciphertext,
    keyHandle,
    verificationPublicKeys ? JSON.stringify(verificationPublicKeys) : null,
  );

  // Unpack: [4 bytes sig_json length (LE u32)][sig_json][plaintext]
  const view = new DataView(
    packed.buffer,
    packed.byteOffset,
    packed.byteLength,
  );
  const sigLen = view.getUint32(0, true);
  const sigJson = new TextDecoder().decode(packed.slice(4, 4 + sigLen));
  const plaintext = packed.slice(4 + sigLen);
  const signatureInfo = JSON.parse(sigJson) as SignatureInfo;

  return { plaintext, signatureInfo };
}

export async function signWithHandle(
  text: string,
  keyHandle: number,
): Promise<string> {
  const wasm = await loadWasm();
  return wasm.signWithHandle(text, keyHandle);
}

/** Drop a KEY_STORE entry. Backing bytes are zeroized in Rust via the
 *  `Drop for StoredKey` impl. */
export async function dropKey(handle: number): Promise<void> {
  const wasm = await loadWasm();
  wasm.dropKey(handle);
}

// ── contacts session (uses an in-WASM AES key derived from master) ───
// The session key never crosses to JS; these wrappers only move
// ciphertext / plaintext for the contacts blob.

export async function dropContactsSession(): Promise<void> {
  const wasm = await loadWasm();
  wasm.dropContactsSession();
}

export async function hasContactsSession(): Promise<boolean> {
  const wasm = await loadWasm();
  return wasm.hasContactsSession();
}

export async function encryptContacts(
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.encryptContacts(plaintext);
}

export async function decryptContacts(
  ciphertext: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.decryptContacts(ciphertext, iv);
}
