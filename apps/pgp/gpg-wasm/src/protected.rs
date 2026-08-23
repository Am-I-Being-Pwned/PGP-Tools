//! # At-rest key protection: the shared envelope
//!
//! Part of the WASM/Rust trust boundary -- see the header of `lib.rs` and
//! `apps/pgp/SECURITY.md`. Every private key this vault stores on disk,
//! whatever its type, is sealed by the code in this module: Argon2id (for a
//! password) or HKDF-SHA256 over a WebAuthn PRF output (for a passkey) down
//! to a 32-byte AES key, then AES-256-GCM with the key's identity bound into
//! the AAD.
//!
//! It exists because that envelope was implemented twice -- once over a
//! serialized OpenPGP cert in `lib.rs`, once over a raw RSA PKCS#8 DER in
//! `crx.rs` -- and the two copies had already begun to drift. The functions
//! here are deliberately **payload-agnostic**: they take `&[u8]` and hand
//! back `Zeroizing<Vec<u8>>`, and they know nothing about what the bytes
//! mean. Everything key-type-specific stays with its key type:
//!
//! - the **AAD prefix** (`gpg-tools:password:`, `gpg-tools:crx-passkey:`, ...),
//! - the **HKDF info** string (`gpg-tools-prf-v1` vs `gpg-tools-crx-prf-v1`),
//! - the **identity** the AAD binds to (cert fingerprint vs extension id),
//! - and any **validation** the plaintext must pass before it is stored.
//!
//! Those four are passed in per call. They are the entire reason a blob
//! sealed for one key type cannot be opened as another, so unifying them
//! would be a security regression, not a simplification -- hence they are
//! parameters and never defaults.
//!
//! ## Wire formats (unchanged, and load-bearing: these blobs are on users' disks)
//!
//! ```text
//! password seal:  [16-byte Argon2id salt][12-byte GCM IV][ciphertext||tag]
//! passkey  seal:  [12-byte GCM IV][ciphertext||tag]
//! packed meta:    [u32_le json_len][json][blob]
//! ```
//!
//! ## Zeroization
//!
//! Every derived AES key is `zeroize()`d immediately after the AEAD call,
//! *before* the call's `Result` is propagated -- the error path must scrub
//! too. Opened plaintext is returned in `Zeroizing`, so a caller that drops
//! it (including on an early `?`) wipes it. The crate's zeroize-on-free
//! global allocator in `lib.rs` is the backstop for everything else.

use std::cell::RefCell;
use std::collections::HashMap;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{aes_gcm_decrypt, aes_gcm_encrypt, argon2_derive, next_handle, rng};

// =====================================================================
// Key derivation
// =====================================================================

/// HKDF-SHA256(salt = `stored_secret`, ikm = `prf_output`, info) -> 32 bytes.
///
/// The stored secret is the per-key random salt kept next to the blob; the
/// PRF output is what the authenticator returns. Neither alone yields the
/// key. `info` is the caller's domain separator -- see the module header.
fn hkdf_derive(prf_output: &[u8], stored_secret: &[u8], info: &[u8]) -> Result<Vec<u8>, String> {
    let hk = Hkdf::<Sha256>::new(Some(stored_secret), prf_output);
    let mut derived = vec![0u8; 32];
    hk.expand(info, &mut derived)
        .map_err(|e| format!("HKDF failed: {e}"))?;
    Ok(derived)
}

// =====================================================================
// Seal (encrypt)
// =====================================================================

/// Seal `plaintext` under an Argon2id-derived AES-GCM key.
/// Returns `[16-byte salt][12-byte iv][ciphertext]`.
///
/// The AAD is `{aad_prefix}{identity}`, so a blob cannot be swapped onto
/// another key entry (different identity) or another key type (different
/// prefix) without failing the tag check.
pub(crate) fn seal_with_password(
    plaintext: &[u8],
    identity: &str,
    aad_prefix: &str,
    password: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 16];
    rng::fill(&mut salt)?;

    let mut derived = argon2_derive(password, &salt, memory_kib, iterations, parallelism)?;
    let aad = format!("{aad_prefix}{identity}");
    let iv_and_ct = aes_gcm_encrypt(&derived, plaintext, aad.as_bytes());
    derived.zeroize();
    let iv_and_ct = iv_and_ct?;

    let mut out = Vec::with_capacity(16 + iv_and_ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&iv_and_ct);
    Ok(out)
}

/// Seal `plaintext` under an HKDF(PRF, storedSecret)-derived AES-GCM key.
/// Returns `[12-byte iv][ciphertext]` -- no salt, because the KDF's salt is
/// the caller-persisted `stored_secret` rather than a per-blob value.
pub(crate) fn seal_with_prf(
    plaintext: &[u8],
    identity: &str,
    aad_prefix: &str,
    hkdf_info: &[u8],
    prf_output: &[u8],
    stored_secret: &[u8],
) -> Result<Vec<u8>, String> {
    let mut derived = hkdf_derive(prf_output, stored_secret, hkdf_info)?;
    let aad = format!("{aad_prefix}{identity}");
    let iv_and_ct = aes_gcm_encrypt(&derived, plaintext, aad.as_bytes());
    derived.zeroize();
    iv_and_ct
}

// =====================================================================
// Open (decrypt)
// =====================================================================

/// Open a password-sealed blob. `ciphertext`, `iv` and `salt` are the three
/// slices the caller split out of `[16 salt][12 iv][ct]`.
///
/// A wrong password, a tampered blob, or a blob sealed for a different
/// identity or key type all surface as the same opaque error -- the AEAD
/// cannot tell them apart and neither should the message.
// The argument list mirrors the wasm export it backs (`unlockWithPassword`,
// `unlockCrxWithPassword`), which carries the same nine values across the JS
// boundary. Bundling them into a struct here would only move the same list
// one layer out.
#[allow(clippy::too_many_arguments)]
pub(crate) fn open_with_password(
    ciphertext: &[u8],
    iv: &[u8],
    salt: &[u8],
    identity: &str,
    aad_prefix: &str,
    password: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut derived = argon2_derive(password, salt, memory_kib, iterations, parallelism)?;
    let aad = format!("{aad_prefix}{identity}");
    let result = aes_gcm_decrypt(&derived, iv, ciphertext, aad.as_bytes());
    derived.zeroize();
    Ok(Zeroizing::new(result?))
}

/// Open a passkey-sealed blob. `ciphertext` and `iv` are the two slices the
/// caller split out of `[12 iv][ct]`.
pub(crate) fn open_with_prf(
    ciphertext: &[u8],
    iv: &[u8],
    identity: &str,
    aad_prefix: &str,
    hkdf_info: &[u8],
    prf_output: &[u8],
    stored_secret: &[u8],
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut derived = hkdf_derive(prf_output, stored_secret, hkdf_info)?;
    let aad = format!("{aad_prefix}{identity}");
    let result = aes_gcm_decrypt(&derived, iv, ciphertext, aad.as_bytes());
    derived.zeroize();
    Ok(Zeroizing::new(result?))
}

// =====================================================================
// Packed metadata + blob
// =====================================================================

/// Pack `[u32_le json_len][json][blob]` so JS can split metadata from the
/// protection blob in one wasm call. Every protect/generate/import export
/// in the crate returns this shape; the JS side parses it in one place.
pub(crate) fn pack_meta_blob(json: &str, blob: &[u8]) -> Vec<u8> {
    let json_bytes = json.as_bytes();
    let mut out = Vec::with_capacity(4 + json_bytes.len() + blob.len());
    out.extend_from_slice(&(json_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(json_bytes);
    out.extend_from_slice(blob);
    out
}

// =====================================================================
// Handle store
// =====================================================================

/// A thread-local map of opaque `u32` handles to unlocked secret bytes.
///
/// This is the shape both `KEY_STORE` (serialized OpenPGP certs) and
/// `CRX_KEY_STORE` (RSA PKCS#8 DER) had grown independently. Payloads are
/// `Zeroizing<Vec<u8>>`, so removal, replacement and thread teardown all
/// wipe the bytes; handles come from the crate-wide monotonic
/// [`crate::next_handle`], so a handle is never valid in two stores at once
/// and a stale handle from a dropped key cannot be reused by a later one.
///
/// Each store is a separate `thread_local!` instance of this type, which is
/// what keeps `lib.rs`'s "KEY_STORE holds OpenPGP certs and is populated
/// only by the unlock paths" invariant (SECURITY.md §4) checkable: a store
/// is only reachable through the module that declares it.
pub(crate) struct HandleStore {
    entries: RefCell<HashMap<u32, Zeroizing<Vec<u8>>>>,
}

impl HandleStore {
    pub(crate) fn new() -> Self {
        HandleStore {
            entries: RefCell::new(HashMap::new()),
        }
    }

    /// Store `payload` and return its handle.
    pub(crate) fn insert(&self, payload: Zeroizing<Vec<u8>>) -> Result<u32, String> {
        let handle = next_handle()?;
        self.entries.borrow_mut().insert(handle, payload);
        Ok(handle)
    }

    /// Run `validate` over the payload and store it only if that succeeds.
    ///
    /// The hook exists because an AAD binds a blob to an identity *string*,
    /// and AAD strings are public -- so an attacker-crafted blob can carry a
    /// foreign key sealed (by them) under a victim's identity. Only the
    /// payload itself can settle whether it really is the key that identity
    /// names, and that check has to happen before the key becomes usable.
    /// `crx.rs` uses it to re-derive the extension id from the decrypted
    /// key's public half; any future key type with a self-certifying
    /// identity wants exactly the same hook.
    ///
    /// On rejection the payload is dropped here, which zeroizes it -- a
    /// rejected key must not linger in linear memory.
    pub(crate) fn insert_validated(
        &self,
        payload: Zeroizing<Vec<u8>>,
        validate: impl FnOnce(&[u8]) -> Result<(), String>,
    ) -> Result<u32, String> {
        validate(&payload)?;
        self.insert(payload)
    }

    /// Borrow the payload behind `handle` and run `f` over it. Returns
    /// `None` if the handle is unknown (dropped, locked, never issued).
    ///
    /// Borrowed rather than cloned on purpose: handing out a copy would
    /// double the number of plaintext key copies each caller has to scrub.
    pub(crate) fn with<T>(&self, handle: u32, f: impl FnOnce(&[u8]) -> T) -> Option<T> {
        self.entries.borrow().get(&handle).map(|p| f(p))
    }

    /// Drop (and zeroize) the payload behind `handle`. A no-op for an
    /// unknown handle, so callers can drop idempotently.
    pub(crate) fn remove(&self, handle: u32) {
        self.entries.borrow_mut().remove(&handle);
    }
}
