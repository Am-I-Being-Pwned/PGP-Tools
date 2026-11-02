//! `KEY_STORE` and the key-handle API. Keys enter only via the unlock paths
//! (SECURITY.md §4).

use std::cell::RefCell;

use openpgp::cert::CertRevocationBuilder;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize as _;
use openpgp::serialize::SerializeInto as _;
use sequoia_openpgp as openpgp;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{
    armor_cert, encrypt_cert_with_prf, protected, serialize_secret_cert, StrErr,
    PASSKEY_AAD_PREFIX, PASSKEY_HKDF_INFO, PASSWORD_AAD_PREFIX,
};
#[cfg(test)]
use crate::{build_cert_from_options, extract_key_info};

// KEY_STORE: unlocked certs, serialized in `Zeroizing<Vec<u8>>` so removal,
// overwrite and teardown wipe them. A distinct `HandleStore` instance from
// crx.rs's, reachable only from this module, so "populated only by the
// unlock paths" (SECURITY.md §4) is a property of `insert_key`'s call sites.
thread_local! {
    static KEY_STORE: protected::HandleStore = protected::HandleStore::new();
    static NEXT_HANDLE: RefCell<u32> = const { RefCell::new(1) };
}

/// Next handle: monotonic and shared by every store in the crate (crx.rs
/// too), so a stale handle can never address a later key.
pub(crate) fn next_handle() -> Result<u32, String> {
    NEXT_HANDLE.with(|next| {
        let mut n = next.borrow_mut();
        let current = *n;
        *n = current.checked_add(1).ok_or("Handle counter overflow")?;
        Ok::<u32, &str>(current)
    })
    .str_err()
}

pub(crate) fn insert_key(cert: &openpgp::Cert) -> Result<u32, String> {
    let stored = serialize_secret_cert(cert)?;
    KEY_STORE.with(|store| store.insert(stored))
}

pub(crate) fn get_cert_from_handle(handle: u32) -> Result<openpgp::Cert, String> {
    KEY_STORE
        .with(|store| store.with(handle, |bytes| openpgp::Cert::from_bytes(bytes).str_err()))
        .ok_or("Key handle not found - key may have been locked")?
}

/// Test-only shims to mint a cert and a handle without a full
/// protect + unlock round trip (keys otherwise enter `KEY_STORE` only via unlock).
#[cfg(test)]
pub(crate) fn generate_key(options_json: &str) -> Result<String, String> {
    let (cert, revocation) = build_cert_from_options(options_json)?;
    let json = serde_json::json!({
        "publicKeyArmored": armor_cert(&cert, false)?,
        "privateKeyArmored": armor_cert(&cert, true)?,
        "revocationCertificate": revocation,
        "keyInfo": extract_key_info(&cert, true),
    });
    Ok(json.to_string())
}

#[cfg(test)]
pub(crate) fn store_key(armored: &str) -> Result<u32, String> {
    let cert = openpgp::Cert::from_bytes(armored.as_bytes()).str_err()?;
    insert_key(&cert)
}

// ---- Key handle API (private keys stay in WASM memory) ----

// No public `storeKey(armored)` export, intentionally: `KEY_STORE` is filled
// only by the unlock paths, so every handle is a user-initiated unlock.

/// Drop a key from WASM memory. The backing bytes are zeroized.
#[wasm_bindgen(js_name = "dropKey")]
pub fn drop_key(handle: u32) -> Result<(), String> {
    KEY_STORE.with(|store| store.remove(handle));
    Ok(())
}

/// Armored private key from a handle. WARNING: returns plaintext secret key
/// material to JS; only for explicit user-initiated "export without passphrase".
#[wasm_bindgen(js_name = "getKeyArmored")]
pub fn get_key_armored(key_handle: u32) -> Result<String, String> {
    armor_cert(&get_cert_from_handle(key_handle)?, true)
}

/// Armored revocation certificate for an unlocked key (imported keys arrive
/// without one). Returns only a public signature packet.
#[wasm_bindgen(js_name = "revocationCertificateWithHandle")]
pub fn revocation_certificate_with_handle(key_handle: u32) -> Result<String, String> {
    use openpgp::types::ReasonForRevocation;

    let cert = get_cert_from_handle(key_handle)?;
    let mut signer = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|_| "Primary key has no secret material".to_string())?
        .into_keypair()
        .str_err()?;
    // "Unspecified", as gpg's pre-generated certificates: the reason isn't known yet.
    let sig = CertRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::Unspecified, b"")
        .str_err()?
        .build(&mut signer, &cert, None)
        .str_err()?;

    let rev_packet: openpgp::Packet = sig.into();
    let mut rev_buf = Vec::with_capacity(rev_packet.serialized_len() + 256);
    let mut rev_writer =
        openpgp::armor::Writer::new(&mut rev_buf, openpgp::armor::Kind::Signature).str_err()?;
    rev_packet.serialize(&mut rev_writer).str_err()?;
    rev_writer.finalize().str_err()?;
    String::from_utf8(rev_buf).str_err()
}

/// Export a stored key encrypted under a passphrase (never plaintext). The
/// passphrase is owned so the wasm side can zeroize it.
#[wasm_bindgen(js_name = "encryptKeyForExportWithHandle")]
pub fn encrypt_key_for_export_with_handle(
    key_handle: u32,
    passphrase: Vec<u8>,
) -> Result<String, String> {
    let passphrase = Zeroizing::new(passphrase);
    let cert = get_cert_from_handle(key_handle)?;
    encrypt_cert_for_export(&cert, &passphrase)
}

/// Encrypt a cert's secret keys with a passphrase for safe export.
fn encrypt_cert_for_export(cert: &openpgp::Cert, passphrase: &[u8]) -> Result<String, String> {
    let password = openpgp::crypto::Password::from(passphrase);

    let primary = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|_| "Primary key has no secret material".to_string())?
        .encrypt_secret(&password)
        .str_err()?;

    let mut packets: Vec<openpgp::Packet> = vec![primary.role_into_primary().into()];
    for subkey in cert.keys().subkeys().secret() {
        packets.push(
            subkey
                .key()
                .clone()
                .encrypt_secret(&password)
                .str_err()?
                .role_into_subordinate()
                .into(),
        );
    }

    let (encrypted_cert, _) = cert.clone().insert_packets(packets).str_err()?;
    armor_cert(&encrypted_cert, true)
}

// ---- Unlock-and-store: decrypt blob + store key in one call; the
// decrypted key never leaves WASM. ----

/// Unlock a password-protected key in WASM -> key handle.
/// Argon2id(password, salt) -> AES-GCM decrypt -> parse Cert -> store.
#[wasm_bindgen(js_name = "unlockWithPassword")]
#[allow(clippy::too_many_arguments)] // flat wasm ABI; KDF params come from the blob
pub fn unlock_with_password(
    ciphertext: &[u8],
    iv: &[u8],
    salt: &[u8],
    key_id: &str,
    password: Vec<u8>,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<u32, String> {
    // Owned, not `&[u8]`: the borrowed glue copy is freed unscrubbed
    // (SECURITY.md §8.4, T-UNLOCK-PARAM-NOT-OWNED).
    let password = Zeroizing::new(password);
    let plaintext = protected::open_with_password(
        ciphertext,
        iv,
        salt,
        key_id,
        PASSWORD_AAD_PREFIX,
        &password,
        memory_kib,
        iterations,
        parallelism,
    )?;
    parse_and_store_private_key(plaintext)
}

/// Unlock a passkey-protected key in WASM -> key handle.
/// HKDF(prfOutput, storedSecret) -> AES-GCM decrypt -> parse Cert -> store.
#[wasm_bindgen(js_name = "unlockWithPrf")]
pub fn unlock_with_prf(
    ciphertext: &[u8],
    iv: &[u8],
    prf_output: Vec<u8>,
    stored_secret: Vec<u8>,
    key_id: &str,
) -> Result<u32, String> {
    // Owned + Zeroizing: see unlock_with_password.
    let prf_output = Zeroizing::new(prf_output);
    let stored_secret = Zeroizing::new(stored_secret);
    let plaintext = protected::open_with_prf(
        ciphertext,
        iv,
        key_id,
        PASSKEY_AAD_PREFIX,
        PASSKEY_HKDF_INFO,
        &prf_output,
        &stored_secret,
    )?;
    parse_and_store_private_key(plaintext)
}

/// Re-seal an unlocked key (by handle) under a NEW PRF output + stored
/// secret without the plaintext leaving WASM ("unlock keys when the vault
/// unlocks"). The stored secret is fresh per blob, so the AES key stays
/// unique. The handle is read, not consumed, and nothing is inserted into
/// `KEY_STORE` (SECURITY.md §4).
///
/// Returns `[u32_le json_len][{"keyId"}][12 iv][ct]`. The keyId (the AAD,
/// from the key the HANDLE holds) lets JS refuse to overwrite an entry with
/// a different id -- a mix-up would store Y's ciphertext under X and destroy X.
///
/// @secret-handling
///   in:  `prf_output`; `stored_secret` is the persisted HKDF salt
///   out: ciphertext + public fingerprint (not secret)
#[wasm_bindgen(js_name = "reprotectKeyWithPrf")]
pub fn reprotect_key_with_prf(
    handle: u32,
    prf_output: Vec<u8>,
    stored_secret: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let prf_output = Zeroizing::new(prf_output);
    let stored_secret = Zeroizing::new(stored_secret);
    let cert = get_cert_from_handle(handle)?;
    let blob = encrypt_cert_with_prf(&cert, &prf_output, &stored_secret)?;
    let meta = serde_json::json!({ "keyId": cert.fingerprint().to_hex() });
    Ok(protected::pack_meta_blob(&meta.to_string(), &blob))
}

/// Parse a decrypted private key and store it. The `Zeroizing` plaintext is
/// wiped as soon as it is parsed, so the serialized copy exists in one place.
fn parse_and_store_private_key(plaintext: Zeroizing<Vec<u8>>) -> Result<u32, String> {
    let result = openpgp::Cert::from_bytes(&plaintext).str_err();
    drop(plaintext);
    let cert = result?;
    if cert.keys().secret().next().is_none() {
        return Err("Decrypted data is not a private key".to_string());
    }
    insert_key(&cert)
}
