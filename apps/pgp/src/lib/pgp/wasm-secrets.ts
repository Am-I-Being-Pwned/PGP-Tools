/**
 * Secret-side wasm wrappers: every call carrying key material or
 * password/PRF secrets goes through this file. Each export has a
 * `@secret-handling` block (secret params, secret returns, caller's
 * zeroization contract).
 *
 * Wasm side: by-value secret params are `Zeroizing`-wrapped on entry
 * (`generate_protected_*` / `protect_imported_*`). `unlock_with_password`,
 * `unlock_with_prf` and `init_contacts_session_with_prf` take `&[u8]`, so
 * the marshalled bytes are freed un-zeroized; see `T-UNLOCK-PARAM-NOT-OWNED`.
 *
 * JS side: pass password/PRF material as `Uint8Array` (never strings, which
 * can't be zeroized) and `.fill(0)` it in a `finally`. The §9 audit grep is
 * code hygiene, NOT a security boundary: any same-realm code can `import()`
 * the glue and reach `KEY_STORE` directly (§8.10).
 *
 * Sole exception: `getKeyArmored` returns plaintext secret-key armor for the
 * user-initiated export, gated only in the UI.
 */

import { unpackMetaBlob, type MetaBlob } from "~/lib/protection/protected-blob";
import type { GenerateKeyOptions, ProtectResultMeta } from "./types";
import { loadWasm } from "./wasm-loader";
import {
  unpackDecryptResult,
  withOutputCap,
  type DecryptWithHandleResult,
} from "./wasm-public";

// ── shared types ─────────────────────────────────────────────────────

/** Protect-flow result; the plaintext cert lives only inside the wasm call. */
export type ProtectFlowResult = MetaBlob<ProtectResultMeta>;

const unpackProtectResult = unpackMetaBlob<ProtectResultMeta>;

// ── generate + protect (atomic; cert lives only in this call) ────────

/**
 * @secret-handling
 *   in:  password bytes
 *   out: encrypted blob bytes (NOT secret); public-only metadata
 *   contract: caller MUST `.fill(0)` `password` in a `finally`.
 * KEY_STORE is NOT touched.
 */
export async function generateProtectedWithPassword(
  opts: GenerateKeyOptions,
  password: Uint8Array,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<ProtectFlowResult> {
  const wasm = await loadWasm();
  return unpackProtectResult(
    wasm.generateProtectedWithPassword(
      JSON.stringify(opts),
      password,
      memoryKib,
      iterations,
      parallelism,
    ),
  );
}

/**
 * @secret-handling
 *   in:  prfOutput, storedSecret bytes
 *   out: encrypted blob bytes (NOT secret); public-only metadata
 *   contract: caller MUST `.fill(0)` `prfOutput`. `storedSecret` is
 *             persisted as the HKDF salt in the resulting blob and is
 *             NOT a secret in itself.
 */
export async function generateProtectedWithPrf(
  opts: GenerateKeyOptions,
  prfOutput: Uint8Array,
  storedSecret: Uint8Array,
): Promise<ProtectFlowResult> {
  const wasm = await loadWasm();
  return unpackProtectResult(
    wasm.generateProtectedWithPrf(
      JSON.stringify(opts),
      prfOutput,
      storedSecret,
    ),
  );
}

// ── import + protect (atomic; cert lives only in this call) ──────────

/**
 * @secret-handling
 *   in:  sourcePassphrase bytes (existing S2K passphrase; empty
 *        `Uint8Array(0)` if none), password bytes (new protection)
 *   out: encrypted blob bytes (NOT secret); public-only metadata
 *   contract: caller MUST `.fill(0)` BOTH input buffers in a `finally`.
 * KEY_STORE is NOT touched.
 */
export async function protectImportedWithPassword(
  armored: string,
  sourcePassphrase: Uint8Array,
  password: Uint8Array,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<ProtectFlowResult> {
  const wasm = await loadWasm();
  return unpackProtectResult(
    wasm.protectImportedWithPassword(
      armored,
      sourcePassphrase,
      password,
      memoryKib,
      iterations,
      parallelism,
    ),
  );
}

/**
 * @secret-handling
 *   in:  sourcePassphrase bytes (see above), prfOutput bytes,
 *        storedSecret bytes
 *   out: encrypted blob bytes (NOT secret); public-only metadata
 *   contract: caller MUST `.fill(0)` `sourcePassphrase` and `prfOutput`.
 *             `storedSecret` is persisted as HKDF salt; not a secret.
 */
export async function protectImportedWithPrf(
  armored: string,
  sourcePassphrase: Uint8Array,
  prfOutput: Uint8Array,
  storedSecret: Uint8Array,
): Promise<ProtectFlowResult> {
  const wasm = await loadWasm();
  return unpackProtectResult(
    wasm.protectImportedWithPrf(
      armored,
      sourcePassphrase,
      prfOutput,
      storedSecret,
    ),
  );
}

// ── unlock-and-store (the ONLY paths that populate KEY_STORE) ────────

/**
 * Add a password (SKESK) alongside any recipients; an empty recipient list
 * gives a `gpg -c`-style message. Lives here because of the password.
 *
 * `wasm.encrypt` is not in `SECRET_WASM_EXPORTS`: it is dual-use (password
 * only when arg 4 is non-null) and a name grep can't express that. The Rust
 * side owns and `Zeroizing`-wraps the param instead.
 *
 * @secret-handling
 *   in:  password bytes
 *   out: ciphertext (not secret -- it is the thing being produced)
 *   contract: caller MUST `.fill(0)` `password` in a `finally`.
 */
export async function encryptWithPassword(
  plaintext: Uint8Array,
  recipientPublicKeys: string[],
  password: Uint8Array,
  signingKeyHandle?: number,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  const recipients = JSON.stringify(recipientPublicKeys);
  return signingKeyHandle === undefined
    ? wasm.encrypt(plaintext, recipients, null, password)
    : wasm.encryptWithSigningHandle(
        plaintext,
        recipients,
        signingKeyHandle,
        password,
      );
}

/**
 * Decrypt a `gpg --symmetric` message. Here because of the password, not
 * the plaintext. Never touches KEY_STORE, so it works with an empty
 * keyring. Same result shape as `decryptWithHandle`.
 *
 * @secret-handling
 *   in:  password bytes
 *   out: message plaintext (user data, not key material)
 *   contract: caller MUST `.fill(0)` `password` in a `finally`.
 */
export async function decryptWithPassword(
  ciphertext: Uint8Array,
  password: Uint8Array,
  verificationPublicKeys?: string[],
  /** An unattended run's ceiling on the plaintext; see `verify`. */
  maxOutputBytes?: number,
): Promise<DecryptWithHandleResult> {
  const wasm = await loadWasm();
  const packed = withOutputCap(wasm, () =>
    wasm.decryptWithPassword(
      ciphertext,
      password,
      verificationPublicKeys ? JSON.stringify(verificationPublicKeys) : null,
      maxOutputBytes,
    ),
  );
  return unpackDecryptResult(packed);
}

/**
 * @secret-handling
 *   in:  password bytes; ciphertext/iv/salt are not secret
 *   out: opaque u32 KEY_STORE handle (NOT secret); the cert lives in
 *        wasm linear memory until `dropKey(handle)` is called
 *   contract: caller MUST `.fill(0)` `password` in a `finally`.
 *
 * One of the two KEY_STORE insert sites (SECURITY.md §4).
 */
export async function unlockWithPassword(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  salt: Uint8Array,
  keyId: string,
  password: Uint8Array,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<number> {
  const wasm = await loadWasm();
  return wasm.unlockWithPassword(
    ciphertext,
    iv,
    salt,
    keyId,
    password,
    memoryKib,
    iterations,
    parallelism,
  );
}

/**
 * @secret-handling
 *   in:  prfOutput bytes; storedSecret/ciphertext/iv are not secret
 *   out: opaque u32 KEY_STORE handle (NOT secret)
 *   contract: caller MUST `.fill(0)` `prfOutput`.
 *
 * The other KEY_STORE insert site.
 */
export async function unlockWithPrf(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  prfOutput: Uint8Array,
  storedSecret: Uint8Array,
  keyId: string,
): Promise<number> {
  const wasm = await loadWasm();
  return wasm.unlockWithPrf(ciphertext, iv, prfOutput, storedSecret, keyId);
}

/** `meta.keyId` is the AAD identity, so the caller can refuse to write over a different entry. */
export interface ResealResult {
  meta: { keyId: string };
  blob: Uint8Array;
}
const unpackResealResult = unpackMetaBlob<ResealResult["meta"]>;

/**
 * @secret-handling
 *   in:  an already-unlocked KEY_STORE handle; prfOutput bytes;
 *        storedSecret is the (fresh, per-blob) HKDF salt -- not secret
 *   out: the re-sealed `[12 iv][ct]` blob plus the sealed-under
 *        fingerprint (NOT secret)
 *   contract: caller MUST `.fill(0)` `prfOutput`.
 *
 * Re-seals a live key under another PRF output without the cert crossing
 * to JS (`lib/protection/vault-unlock.ts`). Handle is read, not consumed;
 * nothing is inserted into KEY_STORE.
 */
export async function reprotectKeyWithPrf(
  handle: number,
  prfOutput: Uint8Array,
  storedSecret: Uint8Array,
): Promise<ResealResult> {
  const wasm = await loadWasm();
  return unpackResealResult(
    wasm.reprotectKeyWithPrf(handle, prfOutput, storedSecret),
  );
}

// ── contacts session bootstrap (derives the in-WASM session key) ─────

/**
 * @secret-handling
 *   in:  prfOutput, storedSecret bytes
 *   out: void
 *   contract: caller MUST `.fill(0)` `prfOutput`. `storedSecret` is
 *             persisted plaintext as HKDF salt; not a secret.
 *
 * Initialises in-WASM `CONTACTS_KEY`; the derived key never crosses to JS.
 */
export async function initContactsSessionWithPrf(
  prfOutput: Uint8Array,
  storedSecret: Uint8Array,
): Promise<void> {
  const wasm = await loadWasm();
  wasm.initContactsSessionWithPrf(prfOutput, storedSecret);
}

/**
 * @secret-handling
 *   in:  password bytes
 *   out: packed `[12-byte IV][ciphertext]` of the canary (NOT secret;
 *        used for later password verification)
 *   contract: caller MUST `.fill(0)` `password`.
 *
 * Also initialises CONTACTS_KEY, in one call so the derived key never sits idle.
 */
export async function encryptCanaryAndInitSession(
  password: Uint8Array,
  salt: Uint8Array,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.encryptCanaryAndInitSession(
    password,
    salt,
    memoryKib,
    iterations,
    parallelism,
  );
}

/**
 * @secret-handling
 *   in:  password bytes
 *   out: boolean (true = correct, session now active; false = wrong)
 *   contract: caller MUST `.fill(0)` `password`.
 */
export async function verifyCanaryAndInitSession(
  canaryCiphertext: Uint8Array,
  canaryIv: Uint8Array,
  password: Uint8Array,
  salt: Uint8Array,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<boolean> {
  const wasm = await loadWasm();
  return wasm.verifyCanaryAndInitSession(
    canaryCiphertext,
    canaryIv,
    password,
    salt,
    memoryKib,
    iterations,
    parallelism,
  );
}

// ── workspace draft session (survives master lock) ───────────────────
// Separate in-WASM key keeping draft text across auto-lock without
// plaintext in the JS heap. Lifetime: side-panel session.

/** Idempotent. */
export async function initDraftSessionIfUnset(): Promise<void> {
  const wasm = await loadWasm();
  wasm.initDraftSessionIfUnset();
}

/**
 * @secret-handling
 *   in:  plaintext bytes (user's in-progress workspace text)
 *   out: packed `[12-byte IV][ciphertext]` (NOT secret)
 *   contract: caller MUST `.fill(0)` `plaintext` in a `finally`.
 */
export async function encryptDraft(plaintext: Uint8Array): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.encryptDraft(plaintext);
}

/**
 * @secret-handling
 *   in:  packed bytes from a prior `encryptDraft` call (NOT secret)
 *   out: plaintext bytes (user's text)
 *   contract: caller SHOULD `.fill(0)` the returned buffer once it has
 *             rehydrated the workspace state.
 */
export async function decryptDraft(packed: Uint8Array): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.decryptDraft(packed);
}

// ── CRX (Chrome extension) signing keys ──────────────────────────────
// RSA-2048 key in CRX_KEY_STORE; only its public half crosses to JS.
// See `gpg-wasm/src/crx.rs`.

interface CrxProtectMeta {
  /** 32-char `a`..`p` extension id derived from the public key. */
  extensionId: string;
  /** SubjectPublicKeyInfo DER, base64 (for the CWS dashboard / PEM). */
  publicKeyDerB64: string;
  algorithm: string;
}

export type CrxProtectFlowResult = MetaBlob<CrxProtectMeta>;

const unpackCrxProtectResult = unpackMetaBlob<CrxProtectMeta>;

/**
 * @secret-handling
 *   in:  password bytes
 *   out: encrypted blob bytes (NOT secret); public-only metadata
 *   contract: caller MUST `.fill(0)` `password` in a `finally`.
 * CRX_KEY_STORE is NOT touched.
 */
export async function generateCrxKeyWithPassword(
  password: Uint8Array,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<CrxProtectFlowResult> {
  const wasm = await loadWasm();
  return unpackCrxProtectResult(
    wasm.generateCrxKeyWithPassword(
      password,
      memoryKib,
      iterations,
      parallelism,
    ),
  );
}

/**
 * @secret-handling
 *   in:  prfOutput, storedSecret bytes
 *   out: encrypted blob bytes (NOT secret); public-only metadata
 *   contract: caller MUST `.fill(0)` `prfOutput`. `storedSecret` is
 *             persisted as HKDF salt; not a secret in itself.
 */
export async function generateCrxKeyWithPrf(
  prfOutput: Uint8Array,
  storedSecret: Uint8Array,
): Promise<CrxProtectFlowResult> {
  const wasm = await loadWasm();
  return unpackCrxProtectResult(
    wasm.generateCrxKeyWithPrf(prfOutput, storedSecret),
  );
}

/**
 * @secret-handling
 *   in:  pem (an existing RSA private key, PKCS#8 or PKCS#1 — SECRET),
 *        password bytes
 *   out: encrypted blob bytes (NOT secret); public-only metadata
 *   contract: caller MUST `.fill(0)` `password`. The `pem` string is an
 *             immutable JS String and cannot be zeroized — accept it only
 *             from a user paste/file that is dropped immediately after.
 */
export async function importCrxKeyWithPassword(
  pem: string,
  password: Uint8Array,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<CrxProtectFlowResult> {
  const wasm = await loadWasm();
  return unpackCrxProtectResult(
    wasm.importCrxKeyWithPassword(
      pem,
      password,
      memoryKib,
      iterations,
      parallelism,
    ),
  );
}

/**
 * @secret-handling
 *   in:  pem (SECRET, see above), prfOutput, storedSecret bytes
 *   out: encrypted blob bytes (NOT secret); public-only metadata
 *   contract: caller MUST `.fill(0)` `prfOutput`.
 */
export async function importCrxKeyWithPrf(
  pem: string,
  prfOutput: Uint8Array,
  storedSecret: Uint8Array,
): Promise<CrxProtectFlowResult> {
  const wasm = await loadWasm();
  return unpackCrxProtectResult(
    wasm.importCrxKeyWithPrf(pem, prfOutput, storedSecret),
  );
}

/**
 * @secret-handling
 *   in:  an already-unlocked CRX_KEY_STORE handle; password bytes
 *   out: encrypted blob bytes (NOT secret); public-only metadata
 *   contract: caller MUST `.fill(0)` `password` in a `finally`.
 *
 * Re-seals in WASM for the bulk export; the RSA key never crosses to JS.
 */
export async function reprotectCrxKeyWithPassword(
  handle: number,
  password: Uint8Array,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<CrxProtectFlowResult> {
  const wasm = await loadWasm();
  return unpackCrxProtectResult(
    wasm.reprotectCrxKeyWithPassword(
      handle,
      password,
      memoryKib,
      iterations,
      parallelism,
    ),
  );
}

/**
 * @secret-handling
 *   in:  an already-unlocked CRX_KEY_STORE handle
 *   out: the raw PKCS#8 PEM of the private key -- SECRET
 *   contract: this is the deliberately-unsafe plaintext export. The returned
 *             PEM is an immutable JS String (cannot be zeroized); callers MUST
 *             gate it behind explicit user confirmation and drop it promptly.
 */
export async function exportCrxPrivateKeyPem(handle: number): Promise<string> {
  const wasm = await loadWasm();
  return wasm.exportCrxPrivateKeyPem(handle);
}

/**
 * @secret-handling
 *   in:  password bytes; ciphertext/iv/salt/extensionId are not secret
 *   out: opaque u32 CRX_KEY_STORE handle (NOT secret)
 *   contract: caller MUST `.fill(0)` `password` in a `finally`.
 */
export async function unlockCrxWithPassword(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  salt: Uint8Array,
  extensionId: string,
  password: Uint8Array,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<number> {
  const wasm = await loadWasm();
  return wasm.unlockCrxWithPassword(
    ciphertext,
    iv,
    salt,
    extensionId,
    password,
    memoryKib,
    iterations,
    parallelism,
  );
}

/**
 * @secret-handling
 *   in:  prfOutput bytes; storedSecret/ciphertext/iv/extensionId not secret
 *   out: opaque u32 CRX_KEY_STORE handle (NOT secret)
 *   contract: caller MUST `.fill(0)` `prfOutput`.
 */
export async function unlockCrxWithPrf(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  prfOutput: Uint8Array,
  storedSecret: Uint8Array,
  extensionId: string,
): Promise<number> {
  const wasm = await loadWasm();
  return wasm.unlockCrxWithPrf(
    ciphertext,
    iv,
    prfOutput,
    storedSecret,
    extensionId,
  );
}

/**
 * @secret-handling
 *   in:  zip bytes (the packed extension — NOT secret); opaque handle
 *   out: the signed `.crx` bytes (NOT secret)
 *   contract: none for the buffers; the signing key stays in WASM behind
 *             `handle`. Call {@link dropCrxKey} when done.
 */
export async function signCrxWithHandle(
  zipBytes: Uint8Array,
  keyHandle: number,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return new Uint8Array(wasm.signCrxWithHandle(zipBytes, keyHandle));
}

/** Drop (and zeroize) an unlocked CRX key handle from CRX_KEY_STORE. */
export async function dropCrxKey(handle: number): Promise<void> {
  const wasm = await loadWasm();
  wasm.dropCrxKey(handle);
}

// ── age / SSH identities ─────────────────────────────────────────────
// OpenSSH keys in SSH_KEY_STORE NEVER cross back to JS: there is
// deliberately no `getSshIdentityArmored`. See `gpg-wasm/src/age.rs`.

/** All fields derive from the PUBLIC half. */
interface SshProtectMeta {
  /** `SHA256:...`; the AAD-bound identity and stored `keyId`. */
  fingerprint: string;
  /** Canonical `<type> <base64>` recipient line. */
  recipient: string;
  algorithm: string;
  /** Key-file comment, conventionally `user@host`. */
  comment: string;
}

export type SshProtectFlowResult = MetaBlob<SshProtectMeta>;

const unpackSshProtectResult = unpackMetaBlob<SshProtectMeta>;

/**
 * @secret-handling
 *   in:  keyFile (OpenSSH private key -- SECRET), sourcePassphrase bytes
 *        (empty `Uint8Array(0)` if none), password bytes (new vault password)
 *   out: encrypted blob bytes (NOT secret); public-only metadata
 *   contract: caller MUST `.fill(0)` ALL THREE input buffers in a
 *             `finally`. `keyFile` is bytes, not a string, so it can be scrubbed.
 * SSH_KEY_STORE is NOT touched.
 */
export async function protectSshIdentityWithPassword(
  keyFile: Uint8Array,
  sourcePassphrase: Uint8Array,
  password: Uint8Array,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<SshProtectFlowResult> {
  const wasm = await loadWasm();
  return unpackSshProtectResult(
    wasm.protectSshIdentityWithPassword(
      keyFile,
      sourcePassphrase,
      password,
      memoryKib,
      iterations,
      parallelism,
    ),
  );
}

/**
 * @secret-handling
 *   in:  keyFile (SECRET), sourcePassphrase bytes, prfOutput bytes,
 *        storedSecret bytes
 *   out: encrypted blob bytes (NOT secret); public-only metadata
 *   contract: caller MUST `.fill(0)` `keyFile`, `sourcePassphrase` and
 *             `prfOutput`. `storedSecret` is persisted as the HKDF salt
 *             in the resulting blob and is NOT a secret in itself.
 */
export async function protectSshIdentityWithPrf(
  keyFile: Uint8Array,
  sourcePassphrase: Uint8Array,
  prfOutput: Uint8Array,
  storedSecret: Uint8Array,
): Promise<SshProtectFlowResult> {
  const wasm = await loadWasm();
  return unpackSshProtectResult(
    wasm.protectSshIdentityWithPrf(
      keyFile,
      sourcePassphrase,
      prfOutput,
      storedSecret,
    ),
  );
}

/**
 * @secret-handling
 *   in:  password bytes; ciphertext/iv/salt/fingerprint are not secret
 *   out: opaque u32 SSH_KEY_STORE handle (NOT secret); the key lives in
 *        wasm linear memory until `dropSshIdentity(handle)`
 *   contract: caller MUST `.fill(0)` `password` in a `finally`.
 *
 * One of two SSH_KEY_STORE insert sites; mirrors SECURITY.md §4.
 */
export async function unlockSshIdentityWithPassword(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  salt: Uint8Array,
  fingerprint: string,
  password: Uint8Array,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<number> {
  const wasm = await loadWasm();
  return wasm.unlockSshIdentityWithPassword(
    ciphertext,
    iv,
    salt,
    fingerprint,
    password,
    memoryKib,
    iterations,
    parallelism,
  );
}

/**
 * @secret-handling
 *   in:  prfOutput bytes; storedSecret/ciphertext/iv/fingerprint not secret
 *   out: opaque u32 SSH_KEY_STORE handle (NOT secret)
 *   contract: caller MUST `.fill(0)` `prfOutput`.
 *
 * The other SSH_KEY_STORE insert site.
 */
export async function unlockSshIdentityWithPrf(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  prfOutput: Uint8Array,
  storedSecret: Uint8Array,
  fingerprint: string,
): Promise<number> {
  const wasm = await loadWasm();
  return wasm.unlockSshIdentityWithPrf(
    ciphertext,
    iv,
    prfOutput,
    storedSecret,
    fingerprint,
  );
}

/**
 * @secret-handling
 *   in:  an already-unlocked SSH_KEY_STORE handle; prfOutput bytes;
 *        storedSecret is the (fresh, per-blob) HKDF salt -- not secret
 *   out: the re-sealed `[12 iv][ct]` blob plus the sealed-under
 *        fingerprint (NOT secret)
 *   contract: caller MUST `.fill(0)` `prfOutput`.
 *
 * SSH twin of {@link reprotectKeyWithPrf}; the AAD fingerprint is derived
 * in wasm, never taken from JS.
 */
export async function reprotectSshIdentityWithPrf(
  handle: number,
  prfOutput: Uint8Array,
  storedSecret: Uint8Array,
): Promise<ResealResult> {
  const wasm = await loadWasm();
  return unpackResealResult(
    wasm.reprotectSshIdentityWithPrf(handle, prfOutput, storedSecret),
  );
}

/**
 * @secret-handling
 *   in:  age ciphertext (NOT secret); an opaque SSH_KEY_STORE handle
 *   out: the decrypted plaintext -- the user's message, which is secret
 *        user data (not key material) and crosses by design
 *   contract: the returned buffer is a JS-owned copy, the caller's to
 *             scrub. MUST `.fill(0)` it once handed on in another form
 *             (UTF-8 branch of `lib/age/operations.ts`), MUST NOT when the
 *             buffer itself is handed on (binary branch; wiped at master
 *             lock by `zeroizeResultBytes`). Saves one copy only: the
 *             decoded string can't be zeroized.
 *
 * Here, not in `wasm-public.ts`, to match `age.rs`'s secret-side filing.
 */
export async function decryptAgeWithHandle(
  ciphertext: Uint8Array,
  keyHandle: number,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.decryptAgeWithHandle(ciphertext, keyHandle);
}

/** Drop (and zeroize) an unlocked SSH identity handle. */
export async function dropSshIdentity(handle: number): Promise<void> {
  const wasm = await loadWasm();
  wasm.dropSshIdentity(handle);
}

// ── destructive export (last resort) ─────────────────────────────────

/**
 * @secret-handling
 *   in:  passphrase bytes; an opaque KEY_STORE handle
 *   out: armored cert re-encrypted under `passphrase` (sensitive: only
 *        as strong as the passphrase)
 *   contract: caller MUST `.fill(0)` `passphrase`.
 */
export async function encryptKeyForExportWithHandle(
  keyHandle: number,
  passphrase: Uint8Array,
): Promise<string> {
  const wasm = await loadWasm();
  return wasm.encryptKeyForExportWithHandle(keyHandle, passphrase);
}

/**
 * @secret-handling
 *   in:  opaque KEY_STORE handle
 *   out: PLAINTEXT armored secret-key material as a JS String
 *   contract: the ONLY path returning plaintext secret-key material to
 *             JS (key migration). UI-gated by type-to-confirm + clipboard
 *             auto-clear. Never call from a non-user-initiated path.
 */
export async function getKeyArmored(handle: number): Promise<string> {
  const wasm = await loadWasm();
  return wasm.getKeyArmored(handle);
}
