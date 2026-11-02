//! At-rest key protection: the shared, payload-agnostic envelope (see
//! `apps/pgp/SECURITY.md`). Argon2id (password) or HKDF-SHA256 over a PRF
//! output (passkey) to an AES-256-GCM key, with the key's identity in the AAD.
//!
//! AAD prefix, HKDF info, identity and plaintext validation are per-call
//! parameters, never defaults: they are what stops a blob sealed for one key
//! type opening as another.
//!
//! Wire formats (on users' disks; never change):
//!
//! ```text
//! password seal:  [16-byte Argon2id salt][12-byte GCM IV][ciphertext||tag]
//! passkey  seal:  [12-byte GCM IV][ciphertext||tag]
//! packed meta:    [u32_le json_len][json][blob]
//! ```
//!
//! Every derived AES key is zeroized right after the AEAD call, before its
//! `Result` propagates (error paths scrub too); opened plaintext is returned
//! in `Zeroizing`.

use std::cell::RefCell;
use std::collections::HashMap;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{aes_gcm_decrypt, aes_gcm_encrypt, argon2_derive, next_handle, rng};

/// HKDF-SHA256(salt = `stored_secret`, ikm = `prf_output`, info) -> 32 bytes.
/// Neither the stored salt nor the PRF output alone yields the key.
pub(crate) fn hkdf_derive(prf_output: &[u8], stored_secret: &[u8], info: &[u8]) -> Result<Vec<u8>, String> {
    let hk = Hkdf::<Sha256>::new(Some(stored_secret), prf_output);
    let mut derived = vec![0u8; 32];
    hk.expand(info, &mut derived)
        .map_err(|e| format!("HKDF failed: {e}"))?;
    Ok(derived)
}

/// Seal under an Argon2id-derived key. Returns `[16 salt][12 iv][ct]`.
/// AAD `{aad_prefix}{identity}` binds the blob to its key entry and key type.
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

/// Seal under an HKDF(PRF, stored_secret)-derived key. Returns `[12 iv][ct]`;
/// the KDF salt is the caller-persisted `stored_secret`.
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

/// Open a password-sealed blob. Wrong password, tampering and wrong
/// identity/key type all give the same opaque error.
// Arguments mirror the wasm export it backs.
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

/// Pack `[u32_le json_len][json][blob]`; every protect/generate/import export
/// returns this shape.
pub(crate) fn pack_meta_blob(json: &str, blob: &[u8]) -> Vec<u8> {
    let json_bytes = json.as_bytes();
    let mut out = Vec::with_capacity(4 + json_bytes.len() + blob.len());
    out.extend_from_slice(&(json_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(json_bytes);
    out.extend_from_slice(blob);
    out
}

/// Thread-local map of opaque `u32` handles to unlocked secret bytes.
///
/// Payloads are `Zeroizing`, so removal, replacement and teardown wipe them.
/// Handles come from the crate-wide monotonic [`crate::next_handle`], so a
/// handle is never valid in two stores and is never reused. Each store is
/// reachable only through its declaring module, which keeps the KEY_STORE
/// unlock-only invariant (SECURITY.md §4) checkable.
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
    /// AAD identity strings are public, so a crafted blob can seal a foreign key
    /// under a victim's identity; only the payload can prove it is that key, and
    /// that must happen before it is usable. A rejected payload is dropped
    /// (zeroized) here.
    pub(crate) fn insert_validated(
        &self,
        payload: Zeroizing<Vec<u8>>,
        validate: impl FnOnce(&[u8]) -> Result<(), String>,
    ) -> Result<u32, String> {
        validate(&payload)?;
        self.insert(payload)
    }

    /// Borrow the payload behind `handle`; `None` if unknown. Borrowed, not
    /// cloned, so callers never get another plaintext copy to scrub.
    pub(crate) fn with<T>(&self, handle: u32, f: impl FnOnce(&[u8]) -> T) -> Option<T> {
        self.entries.borrow().get(&handle).map(|p| f(p))
    }

    /// Drop (and zeroize) the payload behind `handle`; no-op if unknown.
    pub(crate) fn remove(&self, handle: u32) {
        self.entries.borrow_mut().remove(&handle);
    }
}
