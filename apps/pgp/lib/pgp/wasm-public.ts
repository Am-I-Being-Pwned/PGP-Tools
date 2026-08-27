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

import type { KeyDetails, KeyInfo, SignatureStatus } from "./types";
import { loadWasm } from "./wasm-loader";

// ── status / metadata ────────────────────────────────────────────────

export async function ping(): Promise<string> {
  const wasm = await loadWasm();
  return wasm.ping();
}

// ── CRX verification (no key material; pure public check) ────────────

/** Result of verifying a CRX3 (`.crx`) file. */
export interface CrxVerifyResult {
  /** True iff a `sha256_with_rsa` proof verifies AND its key names the
   *  extension (its SHA-256 matches the signed crx_id). */
  valid: boolean;
  /** 32-char `a`..`p` extension id the CRX claims to be, when parseable
   *  (present even for a tampered-but-well-formed CRX). */
  extensionId?: string;
  /** Signature algorithm found, e.g. `sha256_with_rsa`. */
  algorithm?: string;
  /** Human-readable reason when `valid` is false. */
  error?: string;
}

/**
 * Verify a CRX3 (`.crx`) file. Carries no secret material: it only reads
 * the file's own embedded public key + signature. Malformed input yields
 * `{ valid: false, error }` rather than throwing.
 */
export async function verifyCrx(crx: Uint8Array): Promise<CrxVerifyResult> {
  const wasm = await loadWasm();
  return JSON.parse(wasm.verifyCrx(crx)) as CrxVerifyResult;
}

/** Parse an armored key for metadata only. Accepts public OR private
 *  armor; the secret material (if present) is parsed by Sequoia into
 *  its `Protected` containers and dropped at the end of the call. */
export async function parseKey(armored: string): Promise<KeyInfo> {
  const wasm = await loadWasm();
  const json = wasm.parseKey(armored);
  return JSON.parse(json) as KeyInfo;
}

/** Per-component-key breakdown of a certificate: primary key first,
 *  then every subkey in cert order, each with capability flags and
 *  lifecycle status (active / expired / revoked / invalid). Accepts
 *  public or private armor; secret material (if present) is dropped
 *  inside the wasm call, as in `parseKey`. */
export async function parseKeyDetails(armored: string): Promise<KeyDetails> {
  const wasm = await loadWasm();
  const json = wasm.parseKeyDetails(armored);
  return JSON.parse(json) as KeyDetails;
}

/** A single cert split out of a (possibly multi-cert) armored blob,
 *  paired with its own re-armored form. */
export interface ParsedCert {
  keyInfo: KeyInfo;
  armored: string;
}

/** Parse every certificate in an armored blob. Some publishers bundle
 *  several yearly-rotated certs in one `.asc`; `parseKey` would only see
 *  the first (often expired) one. Each returned cert carries its own
 *  re-armored public key so callers store/encrypt against that exact
 *  cert, not the whole blob. */
export async function parseKeys(armored: string): Promise<ParsedCert[]> {
  const wasm = await loadWasm();
  const json = wasm.parseKeys(armored);
  return JSON.parse(json) as ParsedCert[];
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
  signatureStatus: SignatureStatus;
  signerKeyId: string | null;
}

export interface VerifyResultWasm {
  text: string;
  signatureValid: boolean;
  signatureStatus: SignatureStatus;
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

/**
 * Unpack `[4 bytes sig_json length (LE u32)][sig_json][plaintext]`.
 *
 * ONE COPY, TWO CALLERS -- `decryptWithHandle` here and
 * `decryptWithPassword` in `wasm-secrets.ts`. The Rust side packs it in
 * one function (`pack_decrypt_result`) for the same reason: the packing
 * is what makes signature status and plaintext arrive ATOMICALLY, and
 * two hand-rolled readers of that layout are two chances to disagree
 * with the writer.
 */
export function unpackDecryptResult(
  packed: Uint8Array,
): DecryptWithHandleResult {
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
  return unpackDecryptResult(packed);
}

export async function signWithHandle(
  text: string,
  keyHandle: number,
): Promise<string> {
  const wasm = await loadWasm();
  return wasm.signWithHandle(text, keyHandle);
}

/**
 * Given an encrypted message and a set of candidate public keys, return the
 * fingerprint of the key that should decrypt it (matched against the message's
 * recipients), or null if none match. Lets the UI default-select the right
 * decryption key without unlocking every candidate.
 */
export async function selectDecryptionKey(
  ciphertext: Uint8Array,
  candidatePublicKeys: string[],
): Promise<string | null> {
  const wasm = await loadWasm();
  const json = wasm.selectDecryptionKey(
    ciphertext,
    JSON.stringify(candidatePublicKeys),
  );
  return JSON.parse(json) as string | null;
}

/** Which kinds of session-key packet a message carries. Both can be
 *  true: a message may be encrypted to a password AND to recipients. */
export interface MessageEncryption {
  /** An SKESK is present -- the message can be opened with a password. */
  password: boolean;
  /** A PKESK is present -- the message can be opened with a private key. */
  publicKey: boolean;
}

/**
 * Read the session-key packets in front of the encrypted container and
 * report which kinds are there. Shape only: it cannot say whether any
 * particular password or key will actually work, and it needs neither to
 * answer.
 *
 * This is what lets the UI ask for the right thing. Without it a
 * `gpg --symmetric` message goes down the key path and comes back "no
 * suitable decryption key found" -- true, and useless, because the
 * message never wanted a key.
 */
export async function messageEncryption(
  ciphertext: Uint8Array,
): Promise<MessageEncryption> {
  const wasm = await loadWasm();
  return JSON.parse(wasm.messageEncryption(ciphertext)) as MessageEncryption;
}

/** Mint an armored revocation certificate for an unlocked key --
 *  backfills what generation provides, for imported keys. The result is
 *  a public signature packet; no secret material crosses the boundary. */
export async function revocationCertificateWithHandle(
  keyHandle: number,
): Promise<string> {
  const wasm = await loadWasm();
  return wasm.revocationCertificateWithHandle(keyHandle);
}

/** Drop a KEY_STORE entry. Backing bytes are zeroized in Rust via the
 *  `Zeroizing<Vec<u8>>` payload's `Drop` impl. */
export async function dropKey(handle: number): Promise<void> {
  const wasm = await loadWasm();
  wasm.dropKey(handle);
}

// ── age / SSH recipients (public key material only) ──────────────────
// The age engine's no-secret half (`gpg-wasm/src/age.rs`). An SSH
// *public* key line is exactly as public as a PGP public cert, and age
// ciphertext is ciphertext, so all three of these belong on this side of
// the split. The identity (private) half lives in `wasm-secrets.ts`.

/** An SSH public key line, decomposed. */
export interface SshRecipientInfo {
  /** Canonical `<type> <base64>` line with the comment stripped -- the
   *  form `encryptAgeToRecipients` expects back, and what we persist as
   *  an SSH contact's "armor". */
  recipient: string;
  /** `ssh-ed25519` / `ssh-rsa`. */
  algorithm: string;
  /** OpenSSH `SHA256:...` fingerprint; the key's stable identity. */
  fingerprint: string;
  /** Trailing comment, conventionally `user@host`. Empty when absent. */
  comment: string;
}

/** Parse one SSH public key line. Throws on anything that is not a
 *  usable `ssh-ed25519` / `ssh-rsa` recipient. */
export async function parseSshRecipient(
  line: string,
): Promise<SshRecipientInfo> {
  const wasm = await loadWasm();
  return JSON.parse(wasm.parseSshRecipient(line)) as SshRecipientInfo;
}

/** Encrypt to one or more SSH recipients (canonical `<type> <base64>`
 *  lines). `armor` selects the `-----BEGIN AGE ENCRYPTED FILE-----`
 *  form. A single unusable recipient fails the whole call rather than
 *  producing a file the user cannot share as intended. */
export async function encryptAgeToRecipients(
  plaintext: Uint8Array,
  recipients: string[],
  armor: boolean,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.encryptAgeToRecipients(
    plaintext,
    JSON.stringify(recipients),
    armor,
  );
}

/**
 * Which of `candidateRecipients` an age file is encrypted to, as an index
 * into that array, or null when none of them is a recipient.
 *
 * The age counterpart of {@link selectDecryptionKey}, and the same job:
 * default-select the right identity before anything is unlocked. It reads
 * only the file's header, whose ssh stanzas name their recipient by a
 * hash of its PUBLIC key -- so no identity is needed and nothing secret
 * crosses. Throws when `ciphertext` is not an age file at all.
 */
export async function selectAgeDecryptionKey(
  ciphertext: Uint8Array,
  candidateRecipients: string[],
): Promise<number | null> {
  const wasm = await loadWasm();
  const json = wasm.selectAgeDecryptionKey(
    ciphertext,
    JSON.stringify(candidateRecipients),
  );
  return JSON.parse(json) as number | null;
}

/**
 * Name the format of a private key file the age engine will not accept --
 * a PuTTY `.ppk`, a PKCS#8 key, a legacy encrypted PEM -- or null when it
 * is not one of those.
 *
 * Recognition, not acceptance: it lets the import preview say which
 * format this is and what to run instead, rather than making the user
 * pick a password first and fail at the protect step.
 *
 * Filed on this side for the reason `parseKey` is: the key file crosses
 * in, but nothing secret comes back, and the wasm side takes it by value
 * into a `Zeroizing` so the marshalled copy is wiped on return.
 */
export async function sshPrivateKeyFormatRejection(
  keyFile: Uint8Array,
): Promise<string | null> {
  const wasm = await loadWasm();
  return JSON.parse(wasm.sshPrivateKeyFormatRejection(keyFile)) as
    string | null;
}

/**
 * The exact message the SSH protect calls return when the key still
 * needs its passphrase. Read at runtime so the caller can recognise that
 * case by value instead of matching on prose -- a transcribed copy is
 * silently wrong the moment the Rust wording is edited, and the symptom
 * is that the passphrase field stops appearing and passphrase-protected
 * keys become unimportable. Carries no secret.
 */
export async function sshPassphraseRequiredMessage(): Promise<string> {
  const wasm = await loadWasm();
  return wasm.sshPassphraseRequiredMessage();
}

/** Whether `data` looks like an age message -- binary header or armor
 *  marker. A cheap sniff for routing, not a validity check. */
export async function isAgeMessage(data: Uint8Array): Promise<boolean> {
  const wasm = await loadWasm();
  return wasm.isAgeMessage(data);
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

// ── per-store envelope (domain-separated key AND AAD) ────────────────
// `domain` must be the chrome.storage key the blob lives under, so a
// sealed blob is bound to its slot and its store. Nothing outside
// `lib/storage/envelope.ts` should call these directly -- that module
// owns the domain convention and the legacy-blob fallback.

/** Seal `plaintext` for `domain`. Returns `[12-byte IV][ciphertext]`. */
export async function encryptStore(
  domain: string,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.encryptStore(domain, plaintext);
}

/** Open a blob sealed for the SAME `domain`; any other domain rejects. */
export async function decryptStore(
  domain: string,
  ciphertext: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.decryptStore(domain, ciphertext, iv);
}

// ── legacy (pre-v1) shared envelope ─────────────────────────────────
// Every store used to be sealed under the raw contacts key with one
// shared AAD. `decryptContacts` is retained as the migration read path
// for blobs already on users' disks; `encryptContacts` only exists so
// tests can synthesise one. Production code must not write this format
// -- use `encryptStore`.

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
