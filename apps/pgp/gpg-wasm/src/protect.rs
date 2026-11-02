//! Protect flows (generate/import -> sealed blob), Argon2id, and the per-key
//! AAD / HKDF constants.

use std::time::Duration;

use argon2::{Algorithm, Argon2, Params, Version};
use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::parse::Parse;
use openpgp::serialize::Serialize as _;
use openpgp::serialize::SerializeInto as _;
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{armor_cert, decrypt_cert_secrets, extract_key_info, protected, KeyInfo, StrErr};

/// Protect-flow metadata; the blob itself is appended as a binary tail
/// (`pack_protect_result`).
#[derive(Serialize)]
struct ProtectResultMeta {
    #[serde(rename = "publicKeyArmored")]
    public_key_armored: String,
    #[serde(rename = "keyInfo")]
    key_info: KeyInfo,
    #[serde(rename = "revocationCertificate", skip_serializing_if = "Option::is_none")]
    revocation_certificate: Option<String>,
}

#[derive(Deserialize)]
pub struct GenerateKeyOptions {
    pub name: String,
    /// A UID may have no address. Empty is treated as absent.
    #[serde(default)]
    pub email: Option<String>,
    pub comment: Option<String>,
    #[serde(rename = "type")]
    pub key_type: Option<String>,
    #[serde(rename = "expiresIn")]
    pub expires_in: Option<u64>,
}

/// Build a new cert + its armored revocation cert from `GenerateKeyOptions` JSON.
pub(crate) fn build_cert_from_options(
    options_json: &str,
) -> Result<(openpgp::Cert, String), String> {
    let opts: GenerateKeyOptions = serde_json::from_str(options_json).str_err()?;

    let mut userid = opts.name.clone();
    if let Some(ref comment) = opts.comment {
        userid = format!("{} ({})", userid, comment);
    }
    if let Some(email) = opts
        .email
        .as_deref()
        .map(str::trim)
        .filter(|e| !e.is_empty())
    {
        userid = format!("{} <{}>", userid, email);
    }

    let mut builder = CertBuilder::new()
        .add_userid(userid)
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .add_storage_encryption_subkey();

    if opts.key_type.as_deref() == Some("rsa") {
        builder = builder.set_cipher_suite(CipherSuite::RSA4k);
    } else {
        builder = builder.set_cipher_suite(CipherSuite::Cv25519);
    }

    if let Some(seconds) = opts.expires_in {
        if seconds > 0 {
            builder = builder.set_validity_period(Duration::from_secs(seconds));
        }
    }

    let (cert, revocation) = builder.generate().str_err()?;

    let rev_packet: openpgp::Packet = revocation.into();
    let mut rev_buf = Vec::with_capacity(rev_packet.serialized_len() + 256);
    let mut rev_writer =
        openpgp::armor::Writer::new(&mut rev_buf, openpgp::armor::Kind::Signature).str_err()?;
    rev_packet.serialize(&mut rev_writer).str_err()?;
    rev_writer.finalize().str_err()?;

    Ok((cert, String::from_utf8(rev_buf).str_err()?))
}

/// Serialize a cert with secrets (binary) into a `Zeroizing` buffer.
/// `to_vec()` pre-sizes, so no realloc leaves partial copies behind.
pub(crate) fn serialize_secret_cert(cert: &openpgp::Cert) -> Result<Zeroizing<Vec<u8>>, String> {
    Ok(Zeroizing::new(cert.as_tsk().to_vec().str_err()?))
}

/// Pack as `[u32_le json_len][json][blob]` (`protected::pack_meta_blob`,
/// shared with CRX).
fn pack_protect_result(meta: &ProtectResultMeta, blob: &[u8]) -> Result<Vec<u8>, String> {
    let json = serde_json::to_string(meta).str_err()?;
    Ok(protected::pack_meta_blob(&json, blob))
}

/// Encrypt a cert's secrets under an Argon2id-derived AES-GCM key ->
/// `[16-byte salt][12-byte iv][ciphertext]`. AAD binds the fingerprint (no
/// swapping between entries) and `PASSWORD_AAD_PREFIX` (no swapping with CRX).
pub(crate) fn encrypt_cert_with_password(
    cert: &openpgp::Cert,
    password: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    let plaintext = serialize_secret_cert(cert)?;
    protected::seal_with_password(
        &plaintext,
        &cert.fingerprint().to_hex(),
        PASSWORD_AAD_PREFIX,
        password,
        memory_kib,
        iterations,
        parallelism,
    )
}

/// Encrypt a cert's secrets under HKDF(PRF, storedSecret) AES-GCM ->
/// `[12-byte iv][ciphertext]`.
pub(crate) fn encrypt_cert_with_prf(
    cert: &openpgp::Cert,
    prf_output: &[u8],
    stored_secret: &[u8],
) -> Result<Vec<u8>, String> {
    let plaintext = serialize_secret_cert(cert)?;
    protected::seal_with_prf(
        &plaintext,
        &cert.fingerprint().to_hex(),
        PASSKEY_AAD_PREFIX,
        PASSKEY_HKDF_INFO,
        prf_output,
        stored_secret,
    )
}

// ---- Atomic protect-flow API ----
// Generate or import, under password or passkey. The plaintext cert lives
// for one call and is NEVER inserted into `KEY_STORE` (only `unlockWith*`
// does). Each returns `[u32_le json_len][ProtectResultMeta json][blob]`;
// blob is `[16 salt][12 iv][ct]` (password) or `[12 iv][ct]` (prf).

#[wasm_bindgen(js_name = "generateProtectedWithPassword")]
pub fn generate_protected_with_password(
    options_json: &str,
    password: Vec<u8>,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    let password = Zeroizing::new(password);
    let (cert, revocation_armored) = build_cert_from_options(options_json)?;
    let blob = encrypt_cert_with_password(
        &cert, &password, memory_kib, iterations, parallelism,
    )?;
    let meta = ProtectResultMeta {
        public_key_armored: armor_cert(&cert, false)?,
        key_info: extract_key_info(&cert, true),
        revocation_certificate: Some(revocation_armored),
    };
    pack_protect_result(&meta, &blob)
}

#[wasm_bindgen(js_name = "generateProtectedWithPrf")]
pub fn generate_protected_with_prf(
    options_json: &str,
    prf_output: Vec<u8>,
    stored_secret: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let prf_output = Zeroizing::new(prf_output);
    let stored_secret = Zeroizing::new(stored_secret);
    let (cert, revocation_armored) = build_cert_from_options(options_json)?;
    let blob = encrypt_cert_with_prf(&cert, &prf_output, &stored_secret)?;
    let meta = ProtectResultMeta {
        public_key_armored: armor_cert(&cert, false)?,
        key_info: extract_key_info(&cert, true),
        revocation_certificate: Some(revocation_armored),
    };
    pack_protect_result(&meta, &blob)
}

/// Import an armored private key, strip its source passphrase (empty if
/// none), and re-encrypt under a new password.
#[wasm_bindgen(js_name = "protectImportedWithPassword")]
pub fn protect_imported_with_password(
    armored: &str,
    source_passphrase: Vec<u8>,
    password: Vec<u8>,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    let source_passphrase = Zeroizing::new(source_passphrase);
    let password = Zeroizing::new(password);
    let raw = openpgp::Cert::from_bytes(armored.as_bytes()).str_err()?;
    let cert = decrypt_cert_secrets(raw, &source_passphrase)?;
    let blob = encrypt_cert_with_password(
        &cert, &password, memory_kib, iterations, parallelism,
    )?;
    let meta = ProtectResultMeta {
        public_key_armored: armor_cert(&cert, false)?,
        key_info: extract_key_info(&cert, true),
        revocation_certificate: None,
    };
    pack_protect_result(&meta, &blob)
}

#[wasm_bindgen(js_name = "protectImportedWithPrf")]
pub fn protect_imported_with_prf(
    armored: &str,
    source_passphrase: Vec<u8>,
    prf_output: Vec<u8>,
    stored_secret: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let source_passphrase = Zeroizing::new(source_passphrase);
    let prf_output = Zeroizing::new(prf_output);
    let stored_secret = Zeroizing::new(stored_secret);
    let raw = openpgp::Cert::from_bytes(armored.as_bytes()).str_err()?;
    let cert = decrypt_cert_secrets(raw, &source_passphrase)?;
    let blob = encrypt_cert_with_prf(&cert, &prf_output, &stored_secret)?;
    let meta = ProtectResultMeta {
        public_key_armored: armor_cert(&cert, false)?,
        key_info: extract_key_info(&cert, true),
        revocation_certificate: None,
    };
    pack_protect_result(&meta, &blob)
}

// ---- Argon2id key derivation (password -> AES key) ----

/// Argon2id password -> 32-byte AES key (JS entry point): 64 MB, 3
/// iterations, parallelism 1.
///
/// Owned at the ABI: a borrowed param's marshalled copy is freed unscrubbed
/// (SECURITY.md §8.4, T-UNLOCK-PARAM-NOT-OWNED). `argon2_derive` stays
/// borrowing because its in-crate callers already hold a `Zeroizing`; by
/// value there would add an unscrubbed copy.
#[wasm_bindgen(js_name = "argon2Derive")]
pub fn argon2_derive_owned(
    password: Vec<u8>,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    let password = Zeroizing::new(password);
    argon2_derive(&password, salt, memory_kib, iterations, parallelism)
}

/// In-crate Argon2id. Not a wasm export; see `argon2_derive_owned`.
pub fn argon2_derive(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    if salt.len() < 16 {
        return Err("Salt must be at least 16 bytes".to_string());
    }

    let params = Params::new(memory_kib, iterations, parallelism, Some(32)).str_err()?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = vec![0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut output)
        .str_err()?;

    Ok(output)
}

// ---- Shared helpers ----

/// Per-key protection AAD prefixes (mirrored in `encrypt-private-key.ts`).
/// Distinct from crx.rs's `gpg-tools:crx-*`, so the blobs can't be swapped.
pub(crate) const PASSWORD_AAD_PREFIX: &str = "gpg-tools:password:";
pub(crate) const PASSKEY_AAD_PREFIX: &str = "gpg-tools:passkey:";
/// HKDF info for the PRF-derived OpenPGP key. Distinct from crx.rs's: one
/// PRF output must never derive the same key for two key types.
pub(crate) const PASSKEY_HKDF_INFO: &[u8] = b"gpg-tools-prf-v1";
