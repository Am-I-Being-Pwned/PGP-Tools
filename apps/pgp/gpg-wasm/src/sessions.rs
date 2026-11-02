//! Session keys held in WASM: the contacts/master key (with the per-store
//! envelope and canary built on it) and the workspace draft key.

use std::cell::RefCell;

use hkdf::Hkdf;
use sha2::Sha256;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::{aes_gcm_decrypt, aes_gcm_encrypt, argon2_derive, rng};

// ---- Contacts session: derived key in WASM memory, set by the master
// unlock, independent of key handles. ----

pub(crate) const CONTACTS_AAD: &[u8] = b"gpg-tools:contacts:master";
const CONTACTS_HKDF_INFO: &[u8] = b"gpg-tools-contacts-v1";
pub(crate) const CANARY_PLAINTEXT: &[u8] = b"pgp-tools-master-v1";
/// The canary's own AAD. Canaries sealed under `CONTACTS_AAD` were blobs
/// the legacy store fallback would accept if planted in a store slot; a
/// separate label keeps them out. Old canaries still verify.
const CANARY_AAD: &[u8] = b"gpg-tools:master-canary:v1";

thread_local! {
    pub(crate) static CONTACTS_KEY: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

fn set_contacts_key(new_key: Option<Vec<u8>>) {
    CONTACTS_KEY.with(|slot| {
        let mut slot = slot.borrow_mut();
        if let Some(ref mut old) = *slot {
            old.zeroize();
        }
        *slot = new_key;
    });
}

/// Run `f` with the borrowed contacts key (no heap clone to zeroize).
fn with_contacts_key<T>(f: impl FnOnce(&[u8]) -> T) -> Result<T, String> {
    CONTACTS_KEY.with(|slot| {
        let guard = slot.borrow();
        guard
            .as_ref()
            .map(|k| f(k.as_slice()))
            .ok_or_else(|| "Contacts session not active - unlock required".to_string())
    })
}

/// HKDF contacts key: IKM is the Argon2id output (password) or PRF output
/// (passkey); salt is the salt / storedSecret.
pub(crate) fn derive_contacts_key(ikm: &[u8], hkdf_salt: &[u8]) -> Result<Vec<u8>, String> {
    let hk = Hkdf::<Sha256>::new(Some(hkdf_salt), ikm);
    let mut key = vec![0u8; 32];
    if let Err(e) = hk.expand(CONTACTS_HKDF_INFO, &mut key) {
        key.zeroize();
        return Err(format!("HKDF failed: {e}"));
    }
    Ok(key)
}

/// Argon2id + HKDF contacts key; zeroizes the Argon2id output.
pub(crate) fn derive_contacts_key_from_password(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    let mut argon2_output = argon2_derive(password, salt, memory_kib, iterations, parallelism)?;
    let result = derive_contacts_key(&argon2_output, salt);
    argon2_output.zeroize();
    result
}

// ---- Session lifecycle ----

/// HKDF(prfOutput, storedSecret, "gpg-tools-contacts-v1") -> contacts session key.
#[wasm_bindgen(js_name = "initContactsSessionWithPrf")]
pub fn init_contacts_session_with_prf(
    prf_output: Vec<u8>,
    stored_secret: Vec<u8>,
) -> Result<(), String> {
    // Owned + Zeroizing: see unlock_with_password.
    let prf_output = Zeroizing::new(prf_output);
    let stored_secret = Zeroizing::new(stored_secret);
    let key = derive_contacts_key(&prf_output, &stored_secret)?;
    set_contacts_key(Some(key));
    Ok(())
}

/// Drop the contacts session key (zeroized).
#[wasm_bindgen(js_name = "dropContactsSession")]
pub fn drop_contacts_session() {
    set_contacts_key(None);
}

#[wasm_bindgen(js_name = "hasContactsSession")]
pub fn has_contacts_session() -> bool {
    CONTACTS_KEY.with(|slot| slot.borrow().is_some())
}

// ---- Draft session: an AES key for the in-progress workspace across
// auto-lock, INDEPENDENT of the master session (auto-lock drops KEY_STORE
// but the draft still opens on re-unlock). Never crosses to JS. ----

const DRAFT_AAD: &[u8] = b"gpg-tools:workspace-draft:v1";

thread_local! {
    static DRAFT_KEY: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

fn set_draft_key(new_key: Option<Vec<u8>>) {
    DRAFT_KEY.with(|slot| {
        let mut slot = slot.borrow_mut();
        if let Some(ref mut old) = *slot {
            old.zeroize();
        }
        *slot = new_key;
    });
}

pub(crate) fn with_draft_key<T>(f: impl FnOnce(&[u8]) -> T) -> Result<T, String> {
    DRAFT_KEY.with(|slot| {
        let guard = slot.borrow();
        guard
            .as_ref()
            .map(|k| f(k.as_slice()))
            .ok_or_else(|| "Draft session not initialised".to_string())
    })
}

/// Generate a draft key if none is set (no-op otherwise, keeping drafts).
#[wasm_bindgen(js_name = "initDraftSessionIfUnset")]
pub fn init_draft_session_if_unset() -> Result<(), String> {
    let exists = DRAFT_KEY.with(|slot| slot.borrow().is_some());
    if exists {
        return Ok(());
    }
    let mut key = vec![0u8; 32];
    rng::fill(&mut key)?;
    set_draft_key(Some(key));
    Ok(())
}

/// Drop the draft key (panel close, or when the user wipes drafts).
#[wasm_bindgen(js_name = "dropDraftSession")]
pub fn drop_draft_session() {
    set_draft_key(None);
}

/// Encrypt under the draft key -> `[12-byte IV][ciphertext]`. Plaintext is
/// owned and `Zeroizing`.
#[wasm_bindgen(js_name = "encryptDraft")]
pub fn encrypt_draft(plaintext: Vec<u8>) -> Result<Vec<u8>, String> {
    let plaintext = Zeroizing::new(plaintext);
    with_draft_key(|key| aes_gcm_encrypt(key, &plaintext, DRAFT_AAD))?
}

/// Decrypt `encryptDraft` output; the plaintext returns to JS to rehydrate.
#[wasm_bindgen(js_name = "decryptDraft")]
pub fn decrypt_draft(packed: &[u8]) -> Result<Vec<u8>, String> {
    if packed.len() < 12 + 16 {
        return Err("Draft blob too short".to_string());
    }
    let (iv, ct) = packed.split_at(12);
    with_draft_key(|key| aes_gcm_decrypt(key, iv, ct, DRAFT_AAD))?
}

// ---- Per-store envelope (v1): domain-separated key AND AAD ----
// Each store sealed under the master session gets its own HKDF subkey and
// AAD from `domain` (JS passes the chrome.storage key: `pgp_keyring`,
// `pgp_history_seg_<n>`, ...), so a blob can't be replayed into another
// slot -- the legacy envelope allowed exactly that. Two bindings on
// purpose: a distinct key holds even if a bug drops or mismatches the AAD.
const STORE_SUBKEY_INFO_PREFIX: &str = "gpg-tools:store-subkey:v1:";
const STORE_AAD_PREFIX: &str = "gpg-tools:store:v1:";

/// HKDF-Expand the contacts session key into a `Zeroizing` 32-byte subkey
/// for `domain`. Inherits that key's lifetime: domain separation, not an
/// independent unlock window (T-HISTORY-KEY-COUPLING).
pub(crate) fn derive_store_subkey(domain: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    if domain.is_empty() {
        return Err("Store domain must not be empty".to_string());
    }
    let info = format!("{STORE_SUBKEY_INFO_PREFIX}{domain}");
    with_contacts_key(|key| {
        // The session key is already an HKDF output; Extract is a formality.
        let hk = Hkdf::<Sha256>::new(None, key);
        let mut subkey = Zeroizing::new(vec![0u8; 32]);
        hk.expand(info.as_bytes(), subkey.as_mut_slice())
            .map_err(|e| format!("HKDF failed: {e}"))?;
        Ok(subkey)
    })?
}

/// Seal for `domain` -> `[12-byte IV][ciphertext]`. Plaintext is owned and
/// `Zeroizing` (up to 64 KB of messages per history segment).
#[wasm_bindgen(js_name = "encryptStore")]
pub fn encrypt_store(domain: &str, plaintext: Vec<u8>) -> Result<Vec<u8>, String> {
    let plaintext = Zeroizing::new(plaintext);
    let subkey = derive_store_subkey(domain)?;
    let aad = format!("{STORE_AAD_PREFIX}{domain}");
    aes_gcm_encrypt(&subkey, &plaintext, aad.as_bytes())
}

/// Open an `encrypt_store` blob; only the SAME `domain` passes the tag check.
#[wasm_bindgen(js_name = "decryptStore")]
pub fn decrypt_store(domain: &str, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    let subkey = derive_store_subkey(domain)?;
    let aad = format!("{STORE_AAD_PREFIX}{domain}");
    aes_gcm_decrypt(&subkey, iv, ciphertext, aad.as_bytes())
}

// ---- Legacy (pre-v1) shared envelope: raw contacts key + `CONTACTS_AAD` ----
// RETAINED: `decrypt_contacts` is the migration read path for blobs on
// users' disks (`lib/storage/envelope.ts` falls back to it);
// `encrypt_contacts` exists so tests can synthesise a legacy blob.
// Do NOT reintroduce either as a production write path.

/// Encrypt under the legacy envelope (tests only; see above). Plaintext is
/// owned + `Zeroizing`.
#[wasm_bindgen(js_name = "encryptContacts")]
pub fn encrypt_contacts(plaintext: Vec<u8>) -> Result<Vec<u8>, String> {
    let plaintext = Zeroizing::new(plaintext);
    with_contacts_key(|key| aes_gcm_encrypt(key, &plaintext, CONTACTS_AAD))?
}

/// Decrypt a legacy shared-envelope blob (migration read path).
#[wasm_bindgen(js_name = "decryptContacts")]
pub fn decrypt_contacts(ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    with_contacts_key(|key| aes_gcm_decrypt(key, iv, ciphertext, CONTACTS_AAD))?
}

// ---- Master protection canary ----

/// Onboarding: encrypt a canary and init the contacts session in one
/// Argon2id pass -> `[12-byte IV][ciphertext]`.
#[wasm_bindgen(js_name = "encryptCanaryAndInitSession")]
pub fn encrypt_canary_and_init_session(
    password: Vec<u8>,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    // Owned (the master password): the borrowed glue copy is freed unscrubbed
    // (SECURITY.md §8.4, T-UNLOCK-PARAM-NOT-OWNED).
    let password = Zeroizing::new(password);
    let mut key =
        derive_contacts_key_from_password(&password, salt, memory_kib, iterations, parallelism)?;
    let result = aes_gcm_encrypt(&key, CANARY_PLAINTEXT, CANARY_AAD);
    if result.is_ok() {
        set_contacts_key(Some(key));
    } else {
        key.zeroize();
    }
    result
}

/// Verify a password and init the contacts session in one Argon2id pass;
/// false (no session) on a wrong password. Tries `CANARY_AAD` then legacy
/// `CONTACTS_AAD`; both are AEAD opens under the same key, so the fallback
/// adds no way in. Old canaries are NOT re-sealed: losing this record makes
/// the vault unopenable, and an older build on a synced device couldn't
/// verify a re-sealed one.
#[wasm_bindgen(js_name = "verifyCanaryAndInitSession")]
pub fn verify_canary_and_init_session(
    canary_ciphertext: &[u8],
    canary_iv: &[u8],
    password: Vec<u8>,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<bool, String> {
    // Owned, so even the wrong-password branch (attacker-repeatable) scrubs it
    // (SECURITY.md §8.4, T-UNLOCK-PARAM-NOT-OWNED).
    let password = Zeroizing::new(password);
    let mut key =
        derive_contacts_key_from_password(&password, salt, memory_kib, iterations, parallelism)?;
    let opened = aes_gcm_decrypt(&key, canary_iv, canary_ciphertext, CANARY_AAD)
        .or_else(|_| aes_gcm_decrypt(&key, canary_iv, canary_ciphertext, CONTACTS_AAD));
    match opened {
        Ok(_) => {
            // AEAD: a successful decrypt proves the key.
            set_contacts_key(Some(key));
            Ok(true)
        }
        Err(_) => {
            key.zeroize();
            Ok(false)
        }
    }
}
