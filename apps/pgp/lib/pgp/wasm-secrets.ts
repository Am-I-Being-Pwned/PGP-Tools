/**
 * ============================================================================
 * Secret-side wasm wrappers — ALL CALLS THAT CARRY KEY MATERIAL OR
 * PASSWORD/PRF SECRETS GO THROUGH THIS FILE.
 * ============================================================================
 *
 * Every exported function below has a `@secret-handling` block stating:
 *   - which params carry secret material
 *   - which return values carry secret material
 *   - the caller's zeroization contract
 *
 * Wasm-side handling: the Rust crate wraps secret params it takes BY
 * VALUE in `Zeroizing<Vec<u8>>` immediately on entry, so the
 * wasm-bindgen marshalled copy is overwritten on function exit. This
 * holds for the four `generate_protected_*` / `protect_imported_*`
 * functions. It does NOT hold for `unlock_with_password`,
 * `unlock_with_prf` or `init_contacts_session_with_prf`, which take
 * `&[u8]`: there is no owned copy to wrap, so the marshalled password /
 * PRF bytes are freed un-zeroized and only the derived key is scrubbed.
 * See `T-UNLOCK-PARAM-NOT-OWNED` in `lib/security/threat-model.ts`.
 * `apps/pgp/gpg-wasm/src/lib.rs` also carries the doc-comment header for
 * the KEY_STORE-only-via-explicit-unlock invariant.
 *
 * JS-side handling: callers MUST pass `Uint8Array` for password/PRF
 * material (never JS strings -- those are immutable and unzeroizable)
 * and MUST `.fill(0)` the buffer in a `finally` block. This contract is
 * enforced by code review plus `scripts/audit-invariants.mjs`.
 *
 * SCOPE OF THAT ENFORCEMENT: the §9 grep proves no *first-party*
 * callsite outside this file touches the underlying wasm exports. It is
 * code hygiene, NOT a security boundary. The glue ships as an ES module
 * chunk, and the module registry is keyed by resolved URL, so any code
 * running in this realm can `import()` it and reach the live, populated
 * `KEY_STORE` directly -- bypassing this file entirely. See §8.10.
 *
 * The single exception: `getKeyArmored` returns plaintext armored
 * secret-key bytes as a JS String for the user-initiated destructive
 * export. That path is gated by a type-to-confirm UI ("EXPORT") and a
 * clipboard auto-clear timer -- both UI-level, neither a capability
 * check at the WASM boundary.
 */

import type { MetaBlob } from "../protection/protected-blob";
import type { GenerateKeyOptions, ProtectResultMeta } from "./types";
import { unpackMetaBlob } from "../protection/protected-blob";
import { loadWasm } from "./wasm-loader";

// ── shared types ─────────────────────────────────────────────────────

/** Atomic-blob protect-flow result: metadata + the raw protection blob.
 *  Plaintext cert lives only inside the wasm call. The packed wire format
 *  it arrives in is identical for every key type, so it is unpacked once
 *  in `protection/protected-blob.ts` -- see {@link unpackMetaBlob}. */
export type ProtectFlowResult = MetaBlob<ProtectResultMeta>;

const unpackProtectResult = unpackMetaBlob<ProtectResultMeta>;

// ── Argon2id ─────────────────────────────────────────────────────────

/**
 * @secret-handling
 *   in:  password bytes
 *   out: derived AES key bytes
 *   contract: caller MUST `.fill(0)` both `password` and the returned
 *             buffer once the derived key has been consumed.
 *
 * Direct callers should be rare; prefer the higher-level protect-flow
 * which keeps the derived key inside wasm and never returns it.
 */
export async function argon2Derive(
  password: Uint8Array,
  salt: Uint8Array,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  const result = wasm.argon2Derive(
    password,
    salt,
    memoryKib,
    iterations,
    parallelism,
  );
  return new Uint8Array(result);
}

// ── generate + protect (atomic; cert lives only in this call) ────────

/**
 * @secret-handling
 *   in:  password bytes
 *   out: encrypted blob bytes (NOT secret); public-only metadata
 *   contract: caller MUST `.fill(0)` `password` in a `finally`.
 *
 * Wasm-side: builds the cert, encrypts it under Argon2id+AES-GCM,
 * drops the cert at function exit. KEY_STORE is NOT touched.
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
 *   in:  sourcePassphrase bytes (the imported key's existing
 *        S2K-passphrase; pass an empty `Uint8Array(0)` if the imported
 *        key isn't passphrase-protected),
 *        password bytes (the new protection password)
 *   out: encrypted blob bytes (NOT secret); public-only metadata
 *   contract: caller MUST `.fill(0)` BOTH input buffers in a `finally`.
 *
 * Wasm-side: parses the armored input, strips S2K protection (if any),
 * encrypts under the new password, drops the cert at function exit.
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
 * @secret-handling
 *   in:  password bytes; ciphertext/iv/salt are not secret
 *   out: opaque u32 KEY_STORE handle (NOT secret); the cert lives in
 *        wasm linear memory until `dropKey(handle)` is called
 *   contract: caller MUST `.fill(0)` `password` in a `finally`.
 *
 * This is one of the two call sites in the entire system that may
 * insert into KEY_STORE. See SECURITY.md §4.
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
 * The other of the two KEY_STORE-insert call sites.
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

// ── contacts session bootstrap (derives the in-WASM session key) ─────

/**
 * @secret-handling
 *   in:  prfOutput, storedSecret bytes
 *   out: void
 *   contract: caller MUST `.fill(0)` `prfOutput`. `storedSecret` is
 *             persisted plaintext as HKDF salt; not a secret.
 *
 * Initialises the in-WASM `CONTACTS_KEY` thread-local. The derived
 * key never crosses to JS; only `encrypt_contacts`/`decrypt_contacts`
 * (in `wasm-public.ts`) consume it.
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
 * Single-pass: derives the master AES key from the password, encrypts
 * the canary, AND initialises CONTACTS_KEY in one wasm call so the
 * derived key never sits idle.
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
// A separate WASM-side AES key, independent of the master/contacts
// session, used solely to keep the user's in-progress workspace text
// alive across auto-lock cycles without leaving plaintext in the JS
// heap. Lifetime: side-panel session.

/** No-op if a draft key already exists; else generates 32 random bytes
 *  inside WASM. Safe to call repeatedly. */
export async function initDraftSessionIfUnset(): Promise<void> {
  const wasm = await loadWasm();
  wasm.initDraftSessionIfUnset();
}

/** Drop the in-WASM draft key. Any subsequent encryptDraft/decryptDraft
 *  call will error until `initDraftSessionIfUnset` is called again. */
export async function dropDraftSession(): Promise<void> {
  const wasm = await loadWasm();
  wasm.dropDraftSession();
}

/**
 * @secret-handling
 *   in:  plaintext bytes (user's in-progress workspace text)
 *   out: packed `[12-byte IV][ciphertext]` (NOT secret)
 *   contract: caller MUST `.fill(0)` `plaintext` in a `finally`.
 *
 * Encrypted under the in-WASM draft key; the JS-side ciphertext can
 * sit in App-level state across the lock cycle without exposing the
 * user's text in the V8 heap.
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
// A raw RSA-2048 signing key lives in the WASM-side CRX_KEY_STORE (a
// sibling of KEY_STORE), unlocked via the same Argon2id / PRF paths. The
// private key crosses to JS only as its public half. See
// `apps/pgp/gpg-wasm/src/crx.rs` and `apps/pgp/lib/crx/`.

/** Public-only metadata describing a freshly-protected CRX signing key. */
export interface CrxProtectMeta {
  /** 32-char `a`..`p` extension id derived from the public key. */
  extensionId: string;
  /** SubjectPublicKeyInfo DER, base64 (for the CWS dashboard / PEM). */
  publicKeyDerB64: string;
  /** Signing algorithm, currently always `rsa2048`. */
  algorithm: string;
}

/** Metadata + raw protection blob, matching {@link ProtectFlowResult} --
 *  the same packed format, so the same unpacker. */
export type CrxProtectFlowResult = MetaBlob<CrxProtectMeta>;

const unpackCrxProtectResult = unpackMetaBlob<CrxProtectMeta>;

/**
 * @secret-handling
 *   in:  password bytes
 *   out: encrypted blob bytes (NOT secret); public-only metadata
 *   contract: caller MUST `.fill(0)` `password` in a `finally`.
 *
 * Wasm-side: generates a fresh RSA-2048 key, encrypts its PKCS#8 DER
 * under Argon2id+AES-GCM, drops the key at function exit. CRX_KEY_STORE
 * is NOT touched.
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
 * Re-seals the key behind `handle` under `password`, entirely in WASM (the
 * plaintext RSA key never crosses into JS). Used by the bulk export to
 * re-wrap keys under one portable export passphrase.
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
// An OpenSSH private key lives in the WASM-side SSH_KEY_STORE (a sibling
// of KEY_STORE and CRX_KEY_STORE), unlocked via the same Argon2id / PRF
// paths. The key itself NEVER crosses back to JS -- there is no
// `getSshIdentityArmored`, deliberately; the only export trapdoor in the
// system stays the OpenPGP one below. See `gpg-wasm/src/age.rs` and
// `apps/pgp/lib/age/`.

/** Public-only metadata describing a freshly-protected SSH identity.
 *  Every field is derived from the key's PUBLIC half. */
export interface SshProtectMeta {
  /** OpenSSH `SHA256:...` fingerprint. The identity this blob is
   *  AAD-bound to, and the `keyId` it is stored under. */
  fingerprint: string;
  /** Canonical `<type> <base64>` recipient line -- the SSH equivalent of
   *  a PGP cert's public armor. */
  recipient: string;
  /** `ssh-ed25519` / `ssh-rsa`. */
  algorithm: string;
  /** Trailing comment from the key file, conventionally `user@host`.
   *  The only human-readable name an SSH key carries. */
  comment: string;
}

/** Metadata + raw protection blob, matching {@link ProtectFlowResult}. */
export type SshProtectFlowResult = MetaBlob<SshProtectMeta>;

const unpackSshProtectResult = unpackMetaBlob<SshProtectMeta>;

/**
 * @secret-handling
 *   in:  keyFile (the OpenSSH private key bytes -- SECRET),
 *        sourcePassphrase bytes (the passphrase already on the file;
 *        pass an empty `Uint8Array(0)` when it has none),
 *        password bytes (the new vault password)
 *   out: encrypted blob bytes (NOT secret); public-only metadata
 *   contract: caller MUST `.fill(0)` ALL THREE input buffers in a
 *             `finally`.
 *
 * `keyFile` is bytes rather than a string on purpose: the imported key is
 * secret material for the whole of its life in JS, and a JS String could
 * not be scrubbed afterwards (contrast `importCrxKeyWithPassword`, whose
 * PEM parameter carries exactly that caveat).
 *
 * Wasm-side: parses the OpenSSH file, strips its source passphrase,
 * re-seals under the new password, drops the key at function exit.
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
 * One of the two paths that may insert into SSH_KEY_STORE, mirroring the
 * KEY_STORE rule in SECURITY.md §4: every entry traces back to a
 * user-initiated unlock.
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
 * The other SSH_KEY_STORE-insert call site.
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
 *   in:  age ciphertext (NOT secret); an opaque SSH_KEY_STORE handle
 *   out: the decrypted plaintext -- the user's message, which is secret
 *        user data (not key material) and crosses by design
 *   contract: the returned buffer is a JS-owned copy (wasm-bindgen
 *             `.slice()`s it out of linear memory and frees the Rust
 *             side), so it is the caller's to scrub. Caller MUST
 *             `.fill(0)` it once the plaintext has been handed to the
 *             UI in another form, and MUST NOT when the buffer itself
 *             IS what it hands on -- scrubbing then returns zeros.
 *             `lib/age/operations.ts` `decryptWithHandle` is the only
 *             caller and does both: it fills on the UTF-8 branch (where
 *             the decoded string is the result) and passes ownership on
 *             the binary branch, where the workspace's
 *             `zeroizeResultBytes` wipes it at master lock instead.
 *             WHAT THAT BUYS, so the contract is not read as more than
 *             it is: one fewer live copy. The decoded string is an
 *             immutable V8 string and is not zeroizable at all, and it
 *             outlives this buffer by far. The SSH key itself stays in
 *             wasm behind `handle` and never crosses.
 *
 * Lives here rather than in `wasm-public.ts` -- where the equivalent
 * `decryptWithHandle` sits -- because `age.rs` files it under its own
 * secret-side header and gives it a `@secret-handling` block. Keeping the
 * two sides in agreement matters more than the local precedent.
 */
export async function decryptAgeWithHandle(
  ciphertext: Uint8Array,
  keyHandle: number,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.decryptAgeWithHandle(ciphertext, keyHandle);
}

/** Drop (and zeroize) an unlocked SSH identity handle from
 *  SSH_KEY_STORE. Backing bytes are wiped in Rust by the
 *  `Zeroizing<Vec<u8>>` payload's `Drop` impl. */
export async function dropSshIdentity(handle: number): Promise<void> {
  const wasm = await loadWasm();
  wasm.dropSshIdentity(handle);
}

// ── destructive export (last resort) ─────────────────────────────────

/**
 * @secret-handling
 *   in:  passphrase bytes; an opaque KEY_STORE handle
 *   out: armored cert with secrets re-encrypted under `passphrase`
 *        (NOT plaintext key material; protection is the user's chosen
 *        passphrase)
 *   contract: caller MUST `.fill(0)` `passphrase`. The returned String
 *             carries secret material gated by the user's passphrase
 *             strength. Caller should treat as sensitive (clipboard
 *             auto-clear, etc).
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
 *   contract: this is the ONLY path that returns plaintext
 *             secret-key material from wasm to JS. Gated in the UI
 *             by a type-to-confirm ("EXPORT") + clipboard auto-clear.
 *             Never call from a non-user-initiated path.
 *
 * If you are looking at this function for the first time as an
 * auditor: yes, this is the trapdoor. It exists because users
 * sometimes need to migrate keys to other PGP tools. See
 * `KeyCard.tsx` for the UI gate.
 */
export async function getKeyArmored(handle: number): Promise<string> {
  const wasm = await loadWasm();
  return wasm.getKeyArmored(handle);
}
