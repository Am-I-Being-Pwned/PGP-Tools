//! # GPG Tools - Sequoia-PGP WASM Module
//!
//! ## For auditors
//!
//! Start at `apps/pgp/SECURITY.md` for the threat model and file map.
//! This file is the entire WASM/Rust trust boundary -- every
//! cryptographic operation lives here. The JS side talks to this
//! module only through `apps/pgp/lib/pgp/wasm-public.ts` (no secret
//! material) and `apps/pgp/lib/pgp/wasm-secrets.ts` (secret material,
//! with per-function zeroize contracts).
//!
//! All OpenPGP cryptographic operations run in this Rust/WASM module.
//! Private keys are stored in WASM linear memory behind opaque integer
//! handles - the JavaScript side never sees raw private key material
//! during normal operations (encrypt, decrypt, sign).
//!
//! ## Security model
//!
//! - Key isolation: Private keys live in WASM's linear memory (StoredKey),
//!   serialized bytes that are zeroized on drop. JS holds only integer handles.
//! - Signature verification: check() returns Err on bad signatures,
//!   aborting the entire operation. No plaintext is surfaced for forged messages.
//! - Argon2id KDF: Password-derived keys use Argon2id (64MB, 3 iterations),
//!   making GPU brute-force impractical for reasonable passwords.
//! - Constant-time caveat: The RustCrypto backend requires
//!   allow-variable-time-crypto for WASM. Browser sandboxing mitigates
//!   timing side-channels in practice.
//!
//! ## JS boundary
//!
//! Data crosses the WASM/JS boundary via:
//! - JSON strings for structured data (key info, options, verify results)
//! - Raw `Vec<u8>` / `Uint8Array` for ciphertext and plaintext
//! - Packed binary format for decrypt results (sig info header + plaintext)
//!
//! Plaintext-cert lifetime invariants:
//! - The `KEY_STORE` (handle-backed cache) is populated **only** by the
//!   explicit unlock paths (`unlockWithPassword`, `unlockWithPrf`). A
//!   handle in the store always corresponds to a user-initiated unlock.
//! - Generation and import (`generateProtectedWith*`, `protectImportedWith*`)
//!   keep the plaintext cert in WASM only for the duration of a single
//!   call -- they encrypt under the user's chosen protection and return
//!   the blob; the cert never enters the long-lived store.
//! - Sign/encrypt/decrypt operations rematerialize a transient `Cert`
//!   from the store per-call and drop it at function exit.
//! - Plaintext armored secret material crosses the JS boundary only via
//!   `getKeyArmored`, which is gated behind a destructive export UI.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::Write;
use std::time::{Duration, SystemTime};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use openpgp::cert::prelude::*;
use openpgp::crypto::SessionKey;
use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::*;
use openpgp::serialize::Serialize as _;
use openpgp::serialize::SerializeInto as _;
use openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

static POLICY: StandardPolicy<'static> = StandardPolicy::new();

trait StrErr<T> {
    fn str_err(self) -> Result<T, String>;
}
impl<T, E: std::fmt::Display> StrErr<T> for Result<T, E> {
    fn str_err(self) -> Result<T, String> {
        self.map_err(|e| e.to_string())
    }
}

// =====================================================================
// Types (serialized to/from JS via JSON)
// =====================================================================

#[derive(Serialize)]
pub struct KeyInfo {
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "userIds")]
    pub user_ids: Vec<String>,
    pub algorithm: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<f64>,
    #[serde(rename = "isPrivate")]
    pub is_private: bool,
}

/// Metadata returned alongside an encrypted blob from the protect-flow
/// functions. The encrypted blob itself is appended as a binary tail
/// to keep the JS boundary tidy (`pack_protect_result`).
#[derive(Serialize)]
struct ProtectResultMeta {
    #[serde(rename = "publicKeyArmored")]
    public_key_armored: String,
    #[serde(rename = "keyInfo")]
    key_info: KeyInfo,
    #[serde(rename = "revocationCertificate", skip_serializing_if = "Option::is_none")]
    revocation_certificate: Option<String>,
}

#[derive(Serialize)]
pub struct VerifyResult {
    pub text: String,
    #[serde(rename = "signatureValid")]
    pub signature_valid: bool,
    #[serde(rename = "signerKeyId")]
    pub signer_key_id: Option<String>,
}

#[derive(Deserialize)]
pub struct GenerateKeyOptions {
    pub name: String,
    pub email: String,
    pub comment: Option<String>,
    #[serde(rename = "type")]
    pub key_type: Option<String>,
    #[serde(rename = "expiresIn")]
    pub expires_in: Option<u64>,
}

// =====================================================================
// Internal helpers
// =====================================================================

fn system_time_to_millis(t: SystemTime) -> f64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as f64
}

fn extract_key_info(cert: &openpgp::Cert, is_private: bool) -> KeyInfo {
    let key_id = cert.fingerprint().to_hex();
    let user_ids: Vec<String> = cert
        .userids()
        .map(|uid| String::from_utf8_lossy(uid.userid().value()).to_string())
        .collect();
    let algorithm = cert.primary_key().key().pk_algo().to_string();
    let created_at = system_time_to_millis(cert.primary_key().key().creation_time());
    let expires_at = cert
        .with_policy(&POLICY, None)
        .ok()
        .and_then(|vc| vc.primary_key().key_expiration_time())
        .map(system_time_to_millis);

    KeyInfo {
        key_id,
        user_ids,
        algorithm,
        created_at,
        expires_at,
        is_private,
    }
}

fn armor_cert(cert: &openpgp::Cert, is_private: bool) -> Result<String, String> {
    // Pre-size the sink: armored = base64(payload) + framing, so payload * 1.4
    // + a generous 256B for headers/CRC/footer comfortably fits any real cert
    // and avoids realloc-trail-of-partial-secrets for the is_private branch.
    let payload_len = if is_private {
        cert.as_tsk().serialized_len()
    } else {
        cert.serialized_len()
    };
    let mut buf = Vec::with_capacity(payload_len + payload_len / 2 + 256);
    let kind = if is_private {
        openpgp::armor::Kind::SecretKey
    } else {
        openpgp::armor::Kind::PublicKey
    };
    let mut writer = openpgp::armor::Writer::new(&mut buf, kind).str_err()?;
    if is_private {
        cert.as_tsk().serialize(&mut writer).str_err()?;
    } else {
        cert.serialize(&mut writer).str_err()?;
    }
    writer.finalize().str_err()?;
    String::from_utf8(buf).str_err()
}

/// Parse a JSON array of armored key strings into Certs,
/// silently skipping any that fail to parse.
fn parse_armored_certs(json: &str) -> Result<Vec<openpgp::Cert>, String> {
    let armors: Vec<String> = serde_json::from_str(json).str_err()?;
    Ok(armors
        .iter()
        .filter_map(|a| openpgp::Cert::from_bytes(a.as_bytes()).ok())
        .collect())
}

/// Zeroize an `Aes256Gcm` cipher's expanded key schedule on drop.
/// The `aes-gcm` crate does not implement `Zeroize`/`ZeroizeOnDrop`,
/// so we must manually clear the backing memory.
fn zeroize_cipher(cipher: &mut Aes256Gcm) {
    let ptr = cipher as *mut Aes256Gcm as *mut u8;
    let len = std::mem::size_of::<Aes256Gcm>();
    // SAFETY: Aes256Gcm is a repr(Rust) struct of fixed size that we own.
    // We are about to drop it, so zeroing its memory is safe.
    unsafe { std::ptr::write_bytes(ptr, 0, len) };
}

/// AES-256-GCM decrypt with AAD. Key material is borrowed, not consumed --
/// the caller is responsible for zeroizing. The cipher's expanded key
/// schedule is zeroized after use.
fn aes_gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let mut cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| format!("AES key init failed: {e}"))?;
    let result = cipher
        .decrypt(Nonce::from_slice(iv), Payload { msg: ciphertext, aad })
        .map_err(|_| "Decryption failed - wrong credentials or corrupted data".to_string());
    zeroize_cipher(&mut cipher);
    result
}

/// AES-256-GCM encrypt with AAD. Returns `[12-byte IV][ciphertext]`.
/// Key material is borrowed, not consumed -- the caller is responsible for
/// zeroizing. The cipher's expanded key schedule is zeroized after use.
fn aes_gcm_encrypt(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let mut cipher =
        Aes256Gcm::new_from_slice(key).map_err(|e| format!("AES key init failed: {e}"))?;

    let mut iv = [0u8; 12];
    getrandom::fill(&mut iv).map_err(|e| format!("RNG failed: {e}"))?;

    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&iv), Payload { msg: plaintext, aad })
        .map_err(|_| "Encryption failed".to_string());
    zeroize_cipher(&mut cipher);

    let ct = ciphertext?;
    let mut result = Vec::with_capacity(12 + ct.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ct);
    Ok(result)
}

// =====================================================================
// Shared crypto operations
// =====================================================================

/// Encrypt plaintext to recipients, optionally signing with `signer_cert`.
///
/// Pipeline: Armorer -> Encryptor -> [Signer] -> LiteralWriter -> plaintext
fn encrypt_impl(
    plaintext: &[u8],
    recipient_keys_json: &str,
    signer_cert: Option<&openpgp::Cert>,
) -> Result<Vec<u8>, String> {
    let recipient_armors: Vec<String> =
        serde_json::from_str(recipient_keys_json).str_err()?;

    let mut recipients = Vec::new();
    for armor in &recipient_armors {
        recipients.push(openpgp::Cert::from_bytes(armor.as_bytes()).str_err()?);
    }

    let mut recipient_keys = Vec::new();
    for cert in &recipients {
        let vc = cert.with_policy(&POLICY, None).str_err()?;
        for key in vc
            .keys()
            .supported()
            .alive()
            .revoked(false)
            .for_transport_encryption()
            .chain(
                vc.keys()
                    .supported()
                    .alive()
                    .revoked(false)
                    .for_storage_encryption(),
            )
        {
            recipient_keys.push(key);
        }
    }

    let mut sink = Vec::new();
    let message = Armorer::new(Message::new(&mut sink)).build().str_err()?;
    let encryptor = Encryptor::for_recipients(message, recipient_keys)
        .build()
        .str_err()?;

    let inner: Message = if let Some(cert) = signer_cert {
        let keypair = signing_keypair(cert)?;
        Signer::new(encryptor, keypair).str_err()?.build().str_err()?
    } else {
        encryptor
    };
    let mut literal = LiteralWriter::new(inner).build().str_err()?;
    literal.write_all(plaintext).str_err()?;
    literal.finalize().str_err()?;

    Ok(sink)
}

/// Extract the first valid signing keypair from a cert.
fn signing_keypair(cert: &openpgp::Cert) -> Result<openpgp::crypto::KeyPair, String> {
    let vc = cert.with_policy(&POLICY, None).str_err()?;
    vc.keys()
        .secret()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .ok_or("No signing key found")?
        .key()
        .clone()
        .into_keypair()
        .str_err()
}

/// Create a cleartext-signed message from text + signing cert.
fn cleartext_sign(text: &str, cert: &openpgp::Cert) -> Result<String, String> {
    let keypair = signing_keypair(cert)?;

    let mut sink = Vec::new();
    let mut signer = Signer::new(Message::new(&mut sink), keypair)
        .str_err()?
        .cleartext()
        .build()
        .str_err()?;
    signer.write_all(text.as_bytes()).str_err()?;
    signer.finalize().str_err()?;

    Ok(String::from_utf8_lossy(&sink).into_owned())
}

/// Verify signatures in a message structure. Returns Err on any bad signature.
fn process_signatures(
    structure: MessageStructure,
) -> openpgp::Result<(Option<bool>, Option<String>)> {
    let mut signature_valid = None;
    let mut signer_key_id = None;
    for layer in structure {
        if let MessageLayer::SignatureGroup { results } = layer {
            for result in results {
                match result {
                    Ok(GoodChecksum { ka, .. }) => {
                        signature_valid = Some(true);
                        signer_key_id = Some(ka.cert().fingerprint().to_hex());
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("Bad signature: {}", e));
                    }
                }
            }
        }
    }
    Ok((signature_valid, signer_key_id))
}

// =====================================================================
// Private key store (keys live in WASM linear memory, never in JS)
// =====================================================================

/// Private key stored as serialized bytes. Zeroized when dropped.
struct StoredKey {
    bytes: Vec<u8>,
}

impl StoredKey {
    fn from_cert(cert: &openpgp::Cert) -> Result<Self, String> {
        // SerializeInto::to_vec() pre-allocates exactly serialized_len() bytes,
        // so the backing buffer is never grown -- no realloc trail of unzeroed
        // partial copies for the zeroize-on-drop to miss.
        let bytes = cert.as_tsk().to_vec().str_err()?;
        Ok(StoredKey { bytes })
    }

    fn to_cert(&self) -> Result<openpgp::Cert, String> {
        openpgp::Cert::from_bytes(&self.bytes).str_err()
    }
}

impl Drop for StoredKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

thread_local! {
    static KEY_STORE: RefCell<HashMap<u32, StoredKey>> = RefCell::new(HashMap::new());
    static NEXT_HANDLE: RefCell<u32> = RefCell::new(1);
}

fn with_store<T>(f: impl FnOnce(&mut HashMap<u32, StoredKey>) -> T) -> T {
    KEY_STORE.with(|store| f(&mut store.borrow_mut()))
}

fn next_handle() -> Result<u32, String> {
    NEXT_HANDLE.with(|next| {
        let mut n = next.borrow_mut();
        let current = *n;
        *n = current.checked_add(1).ok_or("Handle counter overflow")?;
        Ok::<u32, &str>(current)
    })
    .str_err()
}

fn insert_key(cert: &openpgp::Cert) -> Result<u32, String> {
    let stored = StoredKey::from_cert(cert)?;
    let handle = next_handle()?;
    with_store(|store| store.insert(handle, stored));
    Ok(handle)
}

fn get_cert_from_handle(handle: u32) -> Result<openpgp::Cert, String> {
    with_store(|store| store.get(&handle).map(|sk| sk.to_cert()))
        .ok_or("Key handle not found - key may have been locked")?
}

// =====================================================================
// Sequoia verification/decryption helpers
// =====================================================================

struct DecryptHelper {
    decryption_cert: openpgp::Cert,
    verification_certs: Vec<openpgp::Cert>,
    signature_valid: Option<bool>,
    signer_key_id: Option<String>,
}

impl VerificationHelper for DecryptHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(self.verification_certs.clone())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        let (sig_valid, key_id) = process_signatures(structure)?;
        self.signature_valid = sig_valid;
        self.signer_key_id = key_id;
        Ok(())
    }
}

impl DecryptionHelper for DecryptHelper {
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        let vc = self.decryption_cert.with_policy(&POLICY, None)?;
        for pkesk in pkesks {
            for key in vc
                .keys()
                .secret()
                .alive()
                .revoked(false)
                .for_transport_encryption()
                .chain(vc.keys().secret().alive().revoked(false).for_storage_encryption())
            {
                let mut pair = key.key().clone().into_keypair()?;
                if pkesk
                    .decrypt(&mut pair, sym_algo)
                    .map(|(algo, ref session_key)| decrypt(algo, session_key))
                    .unwrap_or(false)
                {
                    return Ok(Some(self.decryption_cert.clone()));
                }
            }
        }
        Err(anyhow::anyhow!("No suitable decryption key found"))
    }
}

struct VerifyHelper {
    certs: Vec<openpgp::Cert>,
    signature_valid: bool,
    signer_key_id: Option<String>,
}

impl VerificationHelper for VerifyHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(self.certs.clone())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        let (sig_valid, key_id) = process_signatures(structure)?;
        self.signature_valid = sig_valid.unwrap_or(false);
        self.signer_key_id = key_id;
        Ok(())
    }
}

// =====================================================================
// Public WASM API (called from JavaScript via wasm-bindgen)
// =====================================================================

#[wasm_bindgen(js_name = "ping")]
pub fn ping() -> String {
    "gpg-wasm ok".to_string()
}

/// Parse an armored public or private key. Returns JSON `KeyInfo`.
#[wasm_bindgen(js_name = "parseKey")]
pub fn parse_key(armored: &str) -> Result<String, String> {
    let cert = openpgp::Cert::from_bytes(armored.as_bytes()).str_err()?;
    let is_private = cert.keys().secret().next().is_some();
    serde_json::to_string(&extract_key_info(&cert, is_private)).str_err()
}

/// Internal: build a new cert + its armored revocation cert from
/// `GenerateKeyOptions` JSON.
fn build_cert_from_options(
    options_json: &str,
) -> Result<(openpgp::Cert, String), String> {
    let opts: GenerateKeyOptions = serde_json::from_str(options_json).str_err()?;

    let mut userid = opts.name.clone();
    if let Some(ref comment) = opts.comment {
        userid = format!("{} ({})", userid, comment);
    }
    userid = format!("{} <{}>", userid, opts.email);

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

/// Extract the public key from an armored private key.
#[wasm_bindgen(js_name = "extractPublicKey")]
pub fn extract_public_key(armored_private_key: &str) -> Result<String, String> {
    let cert = openpgp::Cert::from_bytes(armored_private_key.as_bytes()).str_err()?;
    armor_cert(&cert, false)
}

/// Encrypt plaintext to recipients. Optional signing via armored private key.
#[wasm_bindgen(js_name = "encrypt")]
pub fn encrypt(
    plaintext: &[u8],
    recipient_keys_json: &str,
    signing_key_armored: Option<String>,
) -> Result<Vec<u8>, String> {
    let signer_cert = signing_key_armored
        .as_deref()
        .map(|armor| openpgp::Cert::from_bytes(armor.as_bytes()).str_err())
        .transpose()?;
    encrypt_impl(plaintext, recipient_keys_json, signer_cert.as_ref())
}

/// Create a cleartext-signed message.
#[wasm_bindgen(js_name = "sign")]
pub fn sign_message(text: &str, signing_key_armored: &str) -> Result<String, String> {
    let cert = openpgp::Cert::from_bytes(signing_key_armored.as_bytes()).str_err()?;
    cleartext_sign(text, &cert)
}

/// Verify a cleartext-signed message. Returns JSON `VerifyResult`.
#[wasm_bindgen(js_name = "verify")]
pub fn verify_message(
    signed_message: &str,
    verification_keys_json: &str,
) -> Result<String, String> {
    let certs = parse_armored_certs(verification_keys_json)?;

    let helper = VerifyHelper {
        certs,
        signature_valid: false,
        signer_key_id: None,
    };

    let mut verifier = VerifierBuilder::from_bytes(signed_message.as_bytes())
        .str_err()?
        .with_policy(&POLICY, None, helper)
        .str_err()?;

    let mut content = Vec::new();
    std::io::copy(&mut verifier, &mut content).str_err()?;
    let helper = verifier.into_helper();

    serde_json::to_string(&VerifyResult {
        text: String::from_utf8(content).str_err()?,
        signature_valid: helper.signature_valid,
        signer_key_id: helper.signer_key_id,
    })
    .str_err()
}

// =====================================================================
// Key handle API (private keys stay in WASM memory)
// =====================================================================

// Note: there is intentionally no public `storeKey(armored)` wasm export.
// `KEY_STORE` is populated only by the explicit unlock paths
// (`unlockWithPassword`, `unlockWithPrf`), so a handle in the store
// always corresponds to a user-initiated unlock action.

/// Drop a key from WASM memory. The backing bytes are zeroized.
#[wasm_bindgen(js_name = "dropKey")]
pub fn drop_key(handle: u32) -> Result<(), String> {
    with_store(|store| store.remove(&handle));
    Ok(())
}

/// Encrypt + sign using a stored signing key handle.
#[wasm_bindgen(js_name = "encryptWithSigningHandle")]
pub fn encrypt_with_signing_handle(
    plaintext: &[u8],
    recipient_keys_json: &str,
    signing_key_handle: u32,
) -> Result<Vec<u8>, String> {
    let signer_cert = get_cert_from_handle(signing_key_handle)?;
    encrypt_impl(plaintext, recipient_keys_json, Some(&signer_cert))
}

/// Decrypt a message using a stored key handle.
///
/// Returns a packed binary: `[4-byte LE sig_json_len][sig_json][plaintext]`
/// so signature info and plaintext are returned atomically (no TOCTOU).
#[wasm_bindgen(js_name = "decryptWithHandle")]
pub fn decrypt_with_handle(
    ciphertext: &[u8],
    key_handle: u32,
    verification_keys_json: Option<String>,
) -> Result<Vec<u8>, String> {
    let decryption_cert = get_cert_from_handle(key_handle)?;

    let verification_certs = match verification_keys_json {
        Some(ref json) => parse_armored_certs(json)?,
        None => Vec::new(),
    };

    let helper = DecryptHelper {
        decryption_cert,
        verification_certs,
        signature_valid: None,
        signer_key_id: None,
    };

    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
        .str_err()?
        .with_policy(&POLICY, None, helper)
        .str_err()?;

    let mut plaintext = Vec::new();
    std::io::copy(&mut decryptor, &mut plaintext).str_err()?;
    let helper = decryptor.into_helper();

    // Pack sig info + plaintext into one return to avoid TOCTOU
    let sig_json = serde_json::json!({
        "signatureValid": helper.signature_valid,
        "signerKeyId": helper.signer_key_id,
    })
    .to_string();
    let sig_bytes = sig_json.as_bytes();
    let sig_len = (sig_bytes.len() as u32).to_le_bytes();

    let mut result = Vec::with_capacity(4 + sig_bytes.len() + plaintext.len());
    result.extend_from_slice(&sig_len);
    result.extend_from_slice(sig_bytes);
    result.extend_from_slice(&plaintext);
    Ok(result)
}

/// Sign using a stored key handle.
#[wasm_bindgen(js_name = "signWithHandle")]
pub fn sign_with_handle(text: &str, key_handle: u32) -> Result<String, String> {
    cleartext_sign(text, &get_cert_from_handle(key_handle)?)
}

/// Get the armored private key from a handle.
///
/// WARNING: This returns plaintext private key material to JS.
/// Only used for explicit user-initiated "export without passphrase".
#[wasm_bindgen(js_name = "getKeyArmored")]
pub fn get_key_armored(key_handle: u32) -> Result<String, String> {
    armor_cert(&get_cert_from_handle(key_handle)?, true)
}

/// Export a stored key encrypted with a passphrase (key never leaves WASM as plaintext).
/// Passphrase is taken as owned bytes so we can zeroize on the wasm side.
#[wasm_bindgen(js_name = "encryptKeyForExportWithHandle")]
pub fn encrypt_key_for_export_with_handle(
    key_handle: u32,
    passphrase: Vec<u8>,
) -> Result<String, String> {
    let passphrase = Zeroizing::new(passphrase);
    let cert = get_cert_from_handle(key_handle)?;
    encrypt_cert_for_export(&cert, &passphrase)
}

/// Returns true if the armored key contains any passphrase-protected secret material.
#[wasm_bindgen(js_name = "isSecretEncrypted")]
pub fn is_secret_encrypted(armored: &str) -> Result<bool, String> {
    let cert = openpgp::Cert::from_bytes(armored.as_bytes()).str_err()?;
    Ok(cert
        .keys()
        .secret()
        .any(|ka| ka.key().secret().is_encrypted()))
}

/// Serialize a cert (with secret material) into a Zeroizing buffer for
/// in-WASM encryption. Binary OpenPGP -- the unlock side accepts both
/// binary and armored via `Cert::from_bytes`.
/// `to_vec()` pre-sizes the backing buffer so it never reallocs partway,
/// keeping the zeroize-on-drop story honest.
fn serialize_secret_cert(cert: &openpgp::Cert) -> Result<Zeroizing<Vec<u8>>, String> {
    Ok(Zeroizing::new(cert.as_tsk().to_vec().str_err()?))
}

/// Pack `[u32_le json_len][json][blob]` so JS can split metadata from
/// the protection blob in one wasm call.
fn pack_protect_result(meta: &ProtectResultMeta, blob: &[u8]) -> Result<Vec<u8>, String> {
    let json = serde_json::to_string(meta).str_err()?;
    let json_bytes = json.as_bytes();
    let mut out = Vec::with_capacity(4 + json_bytes.len() + blob.len());
    out.extend_from_slice(&(json_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(json_bytes);
    out.extend_from_slice(blob);
    Ok(out)
}

/// Encrypt a cert's secret material under an Argon2id-derived AES-GCM key.
/// Returns `[16-byte salt][12-byte iv][ciphertext]`.
/// AAD is bound to the cert's fingerprint so the blob can't be swapped
/// between key entries.
fn encrypt_cert_with_password(
    cert: &openpgp::Cert,
    password: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    let key_id = cert.fingerprint().to_hex();

    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|e| format!("RNG failed: {e}"))?;

    let mut derived = argon2_derive(password, &salt, memory_kib, iterations, parallelism)?;

    let plaintext = serialize_secret_cert(cert)?;
    let aad = format!("{PASSWORD_AAD_PREFIX}{key_id}");
    let iv_and_ct = aes_gcm_encrypt(&derived, &plaintext, aad.as_bytes());
    derived.zeroize();
    let iv_and_ct = iv_and_ct?;

    let mut out = Vec::with_capacity(16 + iv_and_ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&iv_and_ct);
    Ok(out)
}

/// Encrypt a cert's secret material under a HKDF(PRF, storedSecret)-derived
/// AES-GCM key. Returns `[12-byte iv][ciphertext]`.
fn encrypt_cert_with_prf(
    cert: &openpgp::Cert,
    prf_output: &[u8],
    stored_secret: &[u8],
) -> Result<Vec<u8>, String> {
    let key_id = cert.fingerprint().to_hex();

    let hk = Hkdf::<Sha256>::new(Some(stored_secret), prf_output);
    let mut derived = vec![0u8; 32];
    hk.expand(b"gpg-tools-prf-v1", &mut derived)
        .map_err(|e| format!("HKDF failed: {e}"))?;

    let plaintext = serialize_secret_cert(cert)?;
    let aad = format!("{PASSKEY_AAD_PREFIX}{key_id}");
    let iv_and_ct = aes_gcm_encrypt(&derived, &plaintext, aad.as_bytes());
    derived.zeroize();
    iv_and_ct
}

/// Strip OpenPGP S2K passphrase protection from any encrypted secret
/// packets in `cert`. Returns a new cert with plaintext secret material.
/// If `cert` already has no encrypted secrets, returns it unchanged.
fn decrypt_cert_secrets(
    cert: openpgp::Cert,
    source_passphrase: &[u8],
) -> Result<openpgp::Cert, String> {
    if !cert.keys().secret().any(|ka| ka.key().secret().is_encrypted()) {
        return Ok(cert);
    }

    let password = openpgp::crypto::Password::from(source_passphrase);

    let primary_key = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|_| "Primary key has no secret material".to_string())?;
    let primary = if primary_key.secret().is_encrypted() {
        primary_key
            .decrypt_secret(&password)
            .map_err(|_| "Incorrect passphrase".to_string())?
    } else {
        primary_key
    };

    let mut packets: Vec<openpgp::Packet> = vec![primary.role_into_primary().into()];
    for subkey in cert.keys().subkeys().secret() {
        let key = subkey.key().clone();
        let decrypted = if key.secret().is_encrypted() {
            key.decrypt_secret(&password)
                .map_err(|_| "Incorrect passphrase".to_string())?
        } else {
            key
        };
        packets.push(decrypted.role_into_subordinate().into());
    }

    let (decrypted_cert, _) = cert.insert_packets(packets).str_err()?;
    Ok(decrypted_cert)
}

// ============================================================================
// Atomic protect-flow API.
//
// These four functions cover every "produce a fresh encrypted-key blob"
// case (generate or import; password or passkey). The plaintext cert
// exists only for the duration of a single call -- it is NEVER inserted
// into the long-lived `KEY_STORE`. The handle store is reserved
// exclusively for the explicit `unlockWith*` paths, so cached unlocked
// keys correspond 1:1 with user-initiated unlock actions.
//
// Each returns a packed `[u32_le json_len][json][blob_bytes]` Vec where
// `json` is `ProtectResultMeta` and `blob_bytes` is the protection blob:
//   - password variants:  `[16 salt][12 iv][ciphertext]`
//   - prf variants:       `[12 iv][ciphertext]`
// ============================================================================

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

/// Import an armored private key, optionally strip its source-passphrase
/// protection, and re-encrypt under a new password. Pass an empty
/// `source_passphrase` for keys that aren't passphrase-protected.
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

// =====================================================================
// Argon2id key derivation (password -> AES key)
// =====================================================================

/// Derive a 32-byte AES key from a password using Argon2id.
///
/// Parameters are chosen for browser use: 64MB memory, 3 iterations,
/// parallelism 1 (WASM is single-threaded). This makes GPU brute-force
/// impractical for passwords with reasonable entropy.
#[wasm_bindgen(js_name = "argon2Derive")]
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

// =====================================================================
// Unlock-and-store: decrypt protection blob + store key in one call.
// The decrypted private key never leaves WASM.
// =====================================================================

/// Unlock a password-protected key entirely in WASM. Returns a key handle.
///
/// Flow: Argon2id(password, salt) -> AES key -> AES-GCM decrypt -> parse Cert -> store
/// The decrypted private key never enters the JS heap.
#[wasm_bindgen(js_name = "unlockWithPassword")]
pub fn unlock_with_password(
    ciphertext: &[u8],
    iv: &[u8],
    salt: &[u8],
    key_id: &str,
    password: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<u32, String> {
    let mut derived = argon2_derive(password, salt, memory_kib, iterations, parallelism)?;
    let aad = format!("{PASSWORD_AAD_PREFIX}{key_id}");
    let result = aes_gcm_decrypt(&derived, iv, ciphertext, aad.as_bytes());
    derived.zeroize();
    parse_and_store_private_key(result?)
}

/// Unlock a passkey-protected key entirely in WASM. Returns a key handle.
///
/// Flow: HKDF(prfOutput, storedSecret) -> AES key -> AES-GCM decrypt -> parse Cert -> store
/// JS calls WebAuthn to get the PRF output, passes it here as raw bytes.
/// The decrypted private key never enters the JS heap.
#[wasm_bindgen(js_name = "unlockWithPrf")]
pub fn unlock_with_prf(
    ciphertext: &[u8],
    iv: &[u8],
    prf_output: &[u8],
    stored_secret: &[u8],
    key_id: &str,
) -> Result<u32, String> {
    let hk = Hkdf::<Sha256>::new(Some(stored_secret), prf_output);
    let mut derived = vec![0u8; 32];
    hk.expand(b"gpg-tools-prf-v1", &mut derived)
        .map_err(|e| format!("HKDF failed: {e}"))?;

    let aad = format!("{PASSKEY_AAD_PREFIX}{key_id}");
    let result = aes_gcm_decrypt(&derived, iv, ciphertext, aad.as_bytes());
    derived.zeroize();
    parse_and_store_private_key(result?)
}

// =====================================================================
// Shared helpers
// =====================================================================

/// AAD prefixes for per-key protection (also used by the JS side in
/// `encrypt-private-key.ts` -- keep in sync).
const PASSWORD_AAD_PREFIX: &str = "gpg-tools:password:";
const PASSKEY_AAD_PREFIX: &str = "gpg-tools:passkey:";

/// Parse a decrypted private key, zeroize the plaintext, and store it.
fn parse_and_store_private_key(mut plaintext: Vec<u8>) -> Result<u32, String> {
    let result = openpgp::Cert::from_bytes(&plaintext).str_err();
    plaintext.zeroize();
    let cert = result?;
    if cert.keys().secret().next().is_none() {
        return Err("Decrypted data is not a private key".to_string());
    }
    insert_key(&cert)
}

// =====================================================================
// Contacts session: derived key stored in WASM linear memory.
// Managed independently from key handles -- initialised via the master
// protection unlock, not tied to any individual keypair.
// =====================================================================

const CONTACTS_AAD: &[u8] = b"gpg-tools:contacts:master";
const CONTACTS_HKDF_INFO: &[u8] = b"gpg-tools-contacts-v1";
const CANARY_PLAINTEXT: &[u8] = b"pgp-tools-master-v1";

thread_local! {
    static CONTACTS_KEY: RefCell<Option<Vec<u8>>> = RefCell::new(None);
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

/// Borrow the contacts session key and run `f` with it. Avoids cloning
/// the key onto the heap, reducing the number of copies to zeroize.
fn with_contacts_key<T>(f: impl FnOnce(&[u8]) -> T) -> Result<T, String> {
    CONTACTS_KEY.with(|slot| {
        let guard = slot.borrow();
        guard
            .as_ref()
            .map(|k| f(k.as_slice()))
            .ok_or_else(|| "Contacts session not active - unlock required".to_string())
    })
}

/// Derive a contacts key via HKDF. Used for both password (Argon2id output
/// as IKM, salt as HKDF salt) and passkey (PRF output as IKM, storedSecret
/// as HKDF salt) paths.
fn derive_contacts_key(ikm: &[u8], hkdf_salt: &[u8]) -> Result<Vec<u8>, String> {
    let hk = Hkdf::<Sha256>::new(Some(hkdf_salt), ikm);
    let mut key = vec![0u8; 32];
    if let Err(e) = hk.expand(CONTACTS_HKDF_INFO, &mut key) {
        key.zeroize();
        return Err(format!("HKDF failed: {e}"));
    }
    Ok(key)
}

/// Derive the contacts key from a password via Argon2id + HKDF.
/// Returns the key. Zeroizes the Argon2id output.
fn derive_contacts_key_from_password(
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

// ── Session lifecycle ───────────────────────────────────────────────

/// Init the contacts session with a passkey PRF output.
/// HKDF(prfOutput, storedSecret, "gpg-tools-contacts-v1") -> session key.
#[wasm_bindgen(js_name = "initContactsSessionWithPrf")]
pub fn init_contacts_session_with_prf(
    prf_output: &[u8],
    stored_secret: &[u8],
) -> Result<(), String> {
    let key = derive_contacts_key(prf_output, stored_secret)?;
    set_contacts_key(Some(key));
    Ok(())
}

/// Drop the contacts session key. The backing bytes are zeroized.
#[wasm_bindgen(js_name = "dropContactsSession")]
pub fn drop_contacts_session() {
    set_contacts_key(None);
}

/// Check whether a contacts session is currently active.
#[wasm_bindgen(js_name = "hasContactsSession")]
pub fn has_contacts_session() -> bool {
    CONTACTS_KEY.with(|slot| slot.borrow().is_some())
}

// =====================================================================
// Draft session: a separate AES key used solely for stashing the user's
// in-progress workspace state across auto-lock cycles. The key lives in
// WASM linear memory for the lifetime of the side-panel session and is
// INDEPENDENT of the master/contacts session -- so an auto-lock can
// drop KEY_STORE entries while still letting us decrypt the draft on
// re-unlock. The key never crosses to JS.
//
// Plaintext drafts are sensitive (they're the user's text) but are not
// key material; the encrypt/decrypt API just protects the JS-heap copy
// during the locked window.
// =====================================================================

const DRAFT_AAD: &[u8] = b"gpg-tools:workspace-draft:v1";

thread_local! {
    static DRAFT_KEY: RefCell<Option<Vec<u8>>> = RefCell::new(None);
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

fn with_draft_key<T>(f: impl FnOnce(&[u8]) -> T) -> Result<T, String> {
    DRAFT_KEY.with(|slot| {
        let guard = slot.borrow();
        guard
            .as_ref()
            .map(|k| f(k.as_slice()))
            .ok_or_else(|| "Draft session not initialised".to_string())
    })
}

/// Generate a fresh 32-byte random draft key if one isn't already set.
/// No-op if a key already exists (preserves drafts across re-init).
#[wasm_bindgen(js_name = "initDraftSessionIfUnset")]
pub fn init_draft_session_if_unset() -> Result<(), String> {
    let exists = DRAFT_KEY.with(|slot| slot.borrow().is_some());
    if exists {
        return Ok(());
    }
    let mut key = vec![0u8; 32];
    getrandom::fill(&mut key).map_err(|e| format!("RNG failed: {e}"))?;
    set_draft_key(Some(key));
    Ok(())
}

/// Drop the draft session key. Use on side-panel close (or as a
/// belt-and-braces measure when the user wipes drafts).
#[wasm_bindgen(js_name = "dropDraftSession")]
pub fn drop_draft_session() {
    set_draft_key(None);
}

/// Encrypt a draft buffer under the in-WASM draft key. Returns
/// `[12-byte IV][ciphertext]`. Plaintext is wrapped in `Zeroizing` and
/// dropped at function exit.
#[wasm_bindgen(js_name = "encryptDraft")]
pub fn encrypt_draft(plaintext: Vec<u8>) -> Result<Vec<u8>, String> {
    let plaintext = Zeroizing::new(plaintext);
    with_draft_key(|key| aes_gcm_encrypt(key, &plaintext, DRAFT_AAD))?
}

/// Decrypt a packed `[12-byte IV][ciphertext]` produced by `encryptDraft`.
/// The plaintext crosses back to JS so the workspace can rehydrate.
#[wasm_bindgen(js_name = "decryptDraft")]
pub fn decrypt_draft(packed: &[u8]) -> Result<Vec<u8>, String> {
    if packed.len() < 12 + 16 {
        return Err("Draft blob too short".to_string());
    }
    let (iv, ct) = packed.split_at(12);
    with_draft_key(|key| aes_gcm_decrypt(key, iv, ct, DRAFT_AAD))?
}

// ── Contacts encrypt / decrypt ──────────────────────────────────────

/// Encrypt contacts JSON using the session key.
/// Returns `[12-byte IV][ciphertext]`.
#[wasm_bindgen(js_name = "encryptContacts")]
pub fn encrypt_contacts(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    with_contacts_key(|key| aes_gcm_encrypt(key, plaintext, CONTACTS_AAD))?
}

/// Decrypt contacts JSON using the session key.
#[wasm_bindgen(js_name = "decryptContacts")]
pub fn decrypt_contacts(ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    with_contacts_key(|key| aes_gcm_decrypt(key, iv, ciphertext, CONTACTS_AAD))?
}

// ── Master protection canary ────────────────────────────────────────

/// Encrypt a canary and init the contacts session in one Argon2id pass.
/// Used during onboarding password setup.
/// Returns `[12-byte IV][ciphertext]`.
#[wasm_bindgen(js_name = "encryptCanaryAndInitSession")]
pub fn encrypt_canary_and_init_session(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    let mut key = derive_contacts_key_from_password(password, salt, memory_kib, iterations, parallelism)?;
    let result = aes_gcm_encrypt(&key, CANARY_PLAINTEXT, CONTACTS_AAD);
    if result.is_ok() {
        set_contacts_key(Some(key));
    } else {
        key.zeroize();
    }
    result
}

/// Verify a password and init the contacts session in one Argon2id pass.
/// Returns true if the password is correct and the session is now active.
/// Returns false (without initialising the session) if the password is wrong.
#[wasm_bindgen(js_name = "verifyCanaryAndInitSession")]
pub fn verify_canary_and_init_session(
    canary_ciphertext: &[u8],
    canary_iv: &[u8],
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<bool, String> {
    let mut key = derive_contacts_key_from_password(password, salt, memory_kib, iterations, parallelism)?;
    match aes_gcm_decrypt(&key, canary_iv, canary_ciphertext, CONTACTS_AAD) {
        Ok(_) => {
            // AES-GCM is AEAD: successful decryption guarantees correct key.
            set_contacts_key(Some(key));
            Ok(true)
        }
        Err(_) => {
            key.zeroize();
            Ok(false)
        }
    }
}

// =====================================================================

#[cfg(test)]
mod tests;
