//! AES-256-GCM with AAD. Callers own (and zeroize) the key; the expanded key
//! schedule is wiped here.

use aes_gcm::aead::{Aead, Nonce, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};

use crate::{coded, rng, ErrorCode};

/// Wipe an `Aes256Gcm`'s expanded key schedule before drop. aes-gcm's
/// `zeroize` feature already does this on drop; this explicit wipe doesn't
/// depend on that flag and runs before any `Result` propagates.
fn zeroize_cipher(cipher: &mut Aes256Gcm) {
    let ptr = cipher as *mut Aes256Gcm as *mut u8;
    let len = std::mem::size_of::<Aes256Gcm>();
    // SAFETY: Aes256Gcm is a repr(Rust) struct of fixed size that we own.
    // We are about to drop it, so zeroing its memory is safe.
    unsafe { std::ptr::write_bytes(ptr, 0, len) };
}

/// AES-256-GCM decrypt with AAD. `key` is borrowed: the caller zeroizes it;
/// the expanded key schedule is zeroized here.
pub(crate) fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    // A wrong-length IV must be an `Err`, not a panic (a panic aborts the whole
    // wasm module). Checked before the cipher exists: no schedule to scrub.
    let nonce = Nonce::<Aes256Gcm>::try_from(iv)
        .map_err(|_| "Decryption failed - malformed IV".to_string())?;
    let mut cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| format!("AES key init failed: {e}"))?;
    let result = cipher
        .decrypt(&nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| {
            coded(ErrorCode::WrongPassphrase, "Decryption failed - wrong credentials or corrupted data")
        });
    zeroize_cipher(&mut cipher);
    result
}

/// AES-256-GCM encrypt with AAD -> `[12-byte IV][ciphertext]`. `key` is
/// borrowed: the caller zeroizes it; the key schedule is zeroized here.
pub(crate) fn aes_gcm_encrypt(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let mut cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| format!("AES key init failed: {e}"))?;

    let mut iv = [0u8; 12];
    rng::fill(&mut iv)?;

    let ciphertext = cipher
        .encrypt(&Nonce::<Aes256Gcm>::from(iv), Payload { msg: plaintext, aad })
        .map_err(|_| "Encryption failed".to_string());
    zeroize_cipher(&mut cipher);

    let ct = ciphertext?;
    let mut result = Vec::with_capacity(12 + ct.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ct);
    Ok(result)
}
