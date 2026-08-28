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
//! - Key isolation: Private keys live in WASM's linear memory (KEY_STORE,
//!   a `protected::HandleStore`), serialized bytes that are zeroized on
//!   drop. JS holds only integer handles.
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

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;
use std::io::Write;
use std::time::{Duration, SystemTime};

/// Zeroize-on-free global allocator.
///
/// WASM linear memory only ever grows; freed allocations are handed back
/// to the allocator's free list *without* being cleared, so their bytes
/// linger until some later allocation happens to reuse the region. That
/// let decrypted material survive in memory long after it was logically
/// dropped -- e.g. the contacts/keyring plaintext that wasm-bindgen
/// copies to JS and then frees (its `Vec<u8>` return is deallocated by
/// the JS-side `__wbindgen_free`, bypassing any Rust `Drop`), and the
/// armored private-key strings from the export paths.
///
/// Wrapping the system allocator so every `dealloc` wipes the block
/// first closes that gap comprehensively: it doesn't depend on any
/// individual call remembering to zeroize, and it covers buffers freed
/// across the wasm-bindgen ABI where `Drop`/`Zeroizing` can't reach.
/// `realloc` is intentionally left to the trait default (alloc + copy +
/// dealloc), so a moved reallocation also wipes the old block via our
/// `dealloc`.
///
/// Cost: a `write_bytes` over each freed block. This module's workload is
/// occasional, user-initiated crypto (not a hot allocation loop), so the
/// overhead is not observable in practice and the hardening is worth it.
struct ZeroizeOnFree;

unsafe impl GlobalAlloc for ZeroizeOnFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        std::ptr::write_bytes(ptr, 0, layout.size());
        System.dealloc(ptr, layout);
    }
}

#[global_allocator]
static GLOBAL: ZeroizeOnFree = ZeroizeOnFree;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use openpgp::cert::prelude::*;
use openpgp::crypto::SessionKey;
use openpgp::parse::stream::*;
use openpgp::parse::Parse;
use openpgp::policy::{HashAlgoSecurity, StandardPolicy};
use openpgp::serialize::stream::*;
use openpgp::serialize::Serialize as _;
use openpgp::serialize::SerializeInto as _;
use openpgp::types::{HashAlgorithm, KeyFlags, RevocationStatus, SymmetricAlgorithm};
use sequoia_openpgp as openpgp;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use wasm_bindgen::prelude::*;

/// The policy that gates every key operation (parse, encrypt, sign,
/// decrypt). It is Sequoia's `StandardPolicy` relaxed in exactly one
/// way: SHA-1 is accepted in *binding-signature* contexts (primary-key
/// self-signatures, User ID and subkey bindings), which only require
/// second-preimage resistance.
///
/// Rationale: SHA-1's collision resistance is broken (Shambles), but
/// its second-preimage resistance is still intact. Collision resistance
/// is what matters for data signatures and third-party certifications --
/// those keep using the hardened default and stay rejected. Binding
/// signatures only need second-preimage resistance, so accepting SHA-1
/// there is safe enough to keep legacy keys working. Without this, a key
/// whose only live self-signature is SHA-1 (common for older RSA keys)
/// hard-fails with "No binding signature at time ...". We instead import
/// and use it, and surface a `securityWarning` on the key so the user
/// knows it leans on weak crypto. See `strict_policy` for the flag.
fn policy() -> &'static StandardPolicy<'static> {
    static POLICY: OnceLock<StandardPolicy<'static>> = OnceLock::new();
    POLICY.get_or_init(|| {
        let mut p = StandardPolicy::new();
        p.accept_hash_property(
            HashAlgorithm::SHA1,
            HashAlgoSecurity::SecondPreImageResistance,
        );
        p
    })
}

/// Sequoia's hardened defaults, unrelaxed. Used only to *detect* whether
/// a key leans on weak crypto so we can flag it -- never to gate an
/// operation. A key usable under `policy()` but not under this one
/// relies on something the hardened policy rejects (in practice, a SHA-1
/// binding signature).
fn strict_policy() -> &'static StandardPolicy<'static> {
    static STRICT: OnceLock<StandardPolicy<'static>> = OnceLock::new();
    STRICT.get_or_init(StandardPolicy::new)
}

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
    /// True iff our `policy()` accepts at least one encryption-capable,
    /// alive, non-revoked key on this cert.
    #[serde(rename = "usableForEncryption")]
    pub usable_for_encryption: bool,
    /// True iff our `policy()` accepts at least one signing-capable,
    /// alive, non-revoked key on this cert.
    #[serde(rename = "usableForSigning")]
    pub usable_for_signing: bool,
    /// Human-readable reason the cert is unusable. Present only when
    /// `usable_for_encryption` and `usable_for_signing` are both false
    /// because of a policy rejection (e.g. SHA-1 binding signatures,
    /// expiry, revocation).
    #[serde(rename = "policyError", skip_serializing_if = "Option::is_none")]
    pub policy_error: Option<String>,
    /// Non-blocking flag: the key is usable, but only because we relaxed
    /// the hardened policy to accept it (e.g. it relies on a SHA-1
    /// binding signature). Present so the UI can warn the user while
    /// still allowing the import. Mutually exclusive with a fatal
    /// `policy_error`.
    #[serde(rename = "securityWarning", skip_serializing_if = "Option::is_none")]
    pub security_warning: Option<String>,
}

/// One row in the per-key breakdown of a certificate: the primary key
/// or one subkey, with its capability flags and lifecycle status.
/// Returned (as an array, primary first) by `parse_key_details`.
/// Complements `KeyInfo`, which only answers "is this cert usable at
/// all" -- this says *which* component key does what, and which are
/// dead weight (expired / revoked / policy-rejected).
#[derive(Serialize)]
pub struct SubkeyDetail {
    pub fingerprint: String,
    /// Short (64-bit) key ID, the form most other tools print.
    #[serde(rename = "keyId")]
    pub key_id: String,
    pub algorithm: String,
    /// Public-key size in bits, when the algorithm has a meaningful one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bits: Option<usize>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<f64>,
    #[serde(rename = "isPrimary")]
    pub is_primary: bool,
    #[serde(rename = "canSign")]
    pub can_sign: bool,
    #[serde(rename = "canEncrypt")]
    pub can_encrypt: bool,
    #[serde(rename = "canCertify")]
    pub can_certify: bool,
    #[serde(rename = "canAuthenticate")]
    pub can_authenticate: bool,
    /// "active" | "expired" | "revoked" | "invalid".
    /// "invalid" means the binding signature fails our `policy()`
    /// (see `policy_error` for why); capability flags are then unknown
    /// and reported as all-false.
    pub status: String,
    #[serde(rename = "revocationReason", skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
    #[serde(rename = "policyError", skip_serializing_if = "Option::is_none")]
    pub policy_error: Option<String>,
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
    /// Fine-grained status: "valid" | "invalid" | "unknown_key" | "unsigned".
    #[serde(rename = "signatureStatus")]
    pub signature_status: String,
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
    // User IDs are attacker-controlled and rendered by the UI: strip
    // control/bidi characters (a U+202E override in a UID visually
    // reverses the displayed email -- address spoofing) and cap length.
    let user_ids: Vec<String> = cert
        .userids()
        .map(|uid| sanitize_untrusted(&String::from_utf8_lossy(uid.userid().value()), 300))
        .collect();
    let algorithm = cert.primary_key().key().pk_algo().to_string();
    let created_at = system_time_to_millis(cert.primary_key().key().creation_time());

    let (expires_at, usable_for_encryption, usable_for_signing, policy_error, security_warning) =
        match cert.with_policy(policy(), None) {
            Ok(vc) => {
                let expires_at = vc.primary_key().key_expiration_time().map(system_time_to_millis);
                let (has_enc, has_sig) = usable_keys(&vc);
                let policy_error = if !has_enc && !has_sig {
                    // Name revocation explicitly -- it's the one cause the
                    // user can't fix by waiting or asking for a re-export.
                    Some(match verified_revocation_reason(&vc.revocation_status()) {
                        Some(reason) => format!(
                            "This key has been revoked by its owner ({reason}) \
                             and can no longer be used. Ask the owner for \
                             their current key."
                        ),
                        None => "Key has no usable encryption or signing subkey \
                                 (expired, revoked, or unsupported algorithm)."
                            .to_string(),
                    })
                } else {
                    None
                };
                // Usable, but only thanks to our relaxed policy? Flag it,
                // naming the specific key (primary self-sig vs a subkey
                // binding) that leans on weak crypto.
                let security_warning = if policy_error.is_some() {
                    None
                } else {
                    security_warning(cert, has_enc, has_sig)
                };
                (expires_at, has_enc, has_sig, policy_error, security_warning)
            }
            Err(e) => {
                let raw = e.to_string();
                (None, false, false, Some(humanize_policy_error(&raw)), None)
            }
        };

    KeyInfo {
        key_id,
        user_ids,
        algorithm,
        created_at,
        expires_at,
        is_private,
        usable_for_encryption,
        usable_for_signing,
        policy_error,
        security_warning,
    }
}

/// Whether a validated cert exposes an alive, non-revoked encryption
/// key (`.0`) and/or signing key (`.1`).
fn usable_keys(vc: &openpgp::cert::ValidCert) -> (bool, bool) {
    // A revocation of the whole certificate does NOT mark the component
    // keys revoked in Sequoia's per-key status, so without this check a
    // fully revoked cert would still report usable "active" subkeys and
    // import as a normal contact (the same cascade parse_key_details
    // applies to its per-subkey rows).
    if verified_revocation_reason(&vc.revocation_status()).is_some() {
        return (false, false);
    }
    let has_enc = vc
        .keys()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .next()
        .is_some()
        || vc
            .keys()
            .alive()
            .revoked(false)
            .for_storage_encryption()
            .next()
            .is_some();
    let has_sig = vc
        .keys()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .is_some();
    (has_enc, has_sig)
}

/// Build a non-blocking security warning for a cert that is already
/// usable under our relaxed `policy()`. The *only* difference between
/// `policy()` and `strict_policy()` is SHA-1 acceptance for binding
/// signatures, so any capability we have that the hardened policy lacks
/// is one that leans on a SHA-1 signature -- and we can name which.
///
/// `has_enc`/`has_sig` are the relaxed-policy capabilities the caller
/// already computed. Returns `None` when the hardened policy would
/// accept everything we use (no weak crypto in play).
fn security_warning(cert: &openpgp::Cert, has_enc: bool, has_sig: bool) -> Option<String> {
    // If the hardened policy rejects the cert outright, the weakness is
    // in the primary binding itself (the direct-key / User ID
    // self-signature), not a subkey.
    let (strict_enc, strict_sig) = match cert.with_policy(strict_policy(), None) {
        Ok(vc) => usable_keys(&vc),
        Err(_) => return Some(sha1_warning("primary self-signature", false)),
    };

    // Primary is fine under the hardened policy; a subkey binding is the
    // weak link. Flag exactly the capability/capabilities affected so we
    // never silently encrypt to (or trust signatures from) a SHA-1-bound
    // subkey.
    match (has_enc && !strict_enc, has_sig && !strict_sig) {
        (true, true) => Some(sha1_warning("encryption and signing subkeys", true)),
        (true, false) => Some(sha1_warning("encryption subkey", false)),
        (false, true) => Some(sha1_warning("signing subkey", false)),
        (false, false) => None,
    }
}

/// The shared "weak SHA-1, allowed but flagged" message for `subject`
/// (e.g. "encryption subkey", "primary key's self-signature").
fn sha1_warning(subject: &str, plural: bool) -> String {
    let (verb, obj, is_are) = if plural {
        ("rely", "legacy SHA-1 signatures", "are")
    } else {
        ("relies", "a legacy SHA-1 signature", "is")
    };
    format!(
        "This key's {subject} {verb} on {obj}, which {is_are} considered weak. It has \
         been imported so you can keep using it, but you should ask the key owner to \
         reissue it with SHA-256 or stronger."
    )
}

/// Translate a raw Sequoia policy-rejection string into something a
/// non-cryptographer can act on. The most common case in 2026 is keys
/// self-signed with SHA-1, which Sequoia's StandardPolicy refuses.
fn humanize_policy_error(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("sha1") || lower.contains("sha-1") {
        return format!(
            "This key was self-signed with SHA-1, which is no longer considered \
             secure and is rejected by default. Ask the key owner to reissue \
             with SHA-256 or stronger. (details: {raw})"
        );
    }
    if lower.contains("md5") {
        return format!(
            "This key uses MD5 signatures, which are broken. Ask the key owner \
             to reissue with SHA-256 or stronger. (details: {raw})"
        );
    }
    format!("Key rejected by security policy: {raw}")
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
    rng::fill(&mut iv)?;

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
    // Already `Zeroizing` -- the EXPORTS wrap it, because they are where
    // the wasm-bindgen allocation lands and where `audit-invariants.mjs`
    // checks. Taking the wrapper here rather than re-wrapping keeps that
    // one owner: it is moved down, never copied.
    password: Option<Zeroizing<Vec<u8>>>,
) -> Result<Vec<u8>, String> {
    let recipient_armors: Vec<String> =
        serde_json::from_str(recipient_keys_json).str_err()?;

    let mut recipients = Vec::new();
    for armor in &recipient_armors {
        recipients.push(openpgp::Cert::from_bytes(armor.as_bytes()).str_err()?);
    }

    let mut recipient_keys = Vec::new();
    for cert in &recipients {
        let vc = cert.with_policy(policy(), None).str_err()?;
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

    // A message must be openable by SOMEONE. Without this, an empty
    // recipient list and no password produce a valid OpenPGP message that
    // nothing on earth can decrypt -- and it would look like a success.
    if recipient_keys.is_empty() && password.is_none() {
        return Err("No recipients and no password: nothing could open this message".to_string());
    }

    let mut sink = Vec::new();
    let message = Armorer::new(Message::new(&mut sink)).build().str_err()?;

    let mut builder = Encryptor::for_recipients(message, recipient_keys)
        // PINNED, not inherited. Sequoia's default happens to be AES-256
        // today, and a default that changes underneath us is a cipher
        // change nobody reviewed. The S2K is NOT pinned here because the
        // stream API does not expose it -- see the note in
        // `encrypt_with_password` about what it uses and why that is the
        // strongest the format can express.
        .symmetric_algo(SymmetricAlgorithm::AES256);
    if let Some(ref pw) = password {
        // ADDITIVE. A password does not replace the recipients: the
        // message gets an SKESK alongside whatever PKESKs it already had,
        // and either opens it. That mirrors the UI, where the password is
        // a badge next to the recipient list rather than a mode that
        // replaces it.
        builder = builder.add_passwords(vec![openpgp::crypto::Password::from(
            pw.as_slice(),
        )]);
    }
    let encryptor = builder.build().str_err()?;

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
    let vc = cert.with_policy(policy(), None).str_err()?;
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

/// Best-effort issuer key id (hex) advertised by a signature's subpackets.
/// Used to name the signer even when we don't hold their public key.
fn issuer_hex(sig: &openpgp::packet::Signature) -> Option<String> {
    sig.get_issuers().into_iter().next().map(|kh| match kh {
        openpgp::KeyHandle::Fingerprint(fp) => fp.to_hex(),
        openpgp::KeyHandle::KeyID(kid) => kid.to_hex(),
    })
}

/// Rank of a signature status, so that across multiple signature layers we
/// report the strongest outcome ("valid" beats a tamper signal beats
/// "can't verify" beats "unsigned").
fn sig_rank(status: &str) -> u8 {
    match status {
        "valid" => 3,
        "invalid" => 2,
        "unknown_key" => 1,
        _ => 0,
    }
}

/// Classify the signatures in a message structure WITHOUT ever failing.
///
/// Decryption and signature verification are SEPARATE concerns: a message
/// must still decrypt even when we cannot verify who signed it (e.g. we do
/// not hold the signer's public key). This function therefore never returns
/// an error for a signature outcome -- it only reports one:
///
///   "valid"       - a good signature we could cryptographically verify
///   "invalid"     - a signature we had the key for but that failed to
///                   verify (tamper / forgery signal -- callers should warn)
///   "unknown_key" - signed, but we don't hold the signer's public key, so
///                   the signature could not be checked either way
///   "unsigned"    - no signatures present
fn process_signatures(structure: MessageStructure) -> (&'static str, Option<String>) {
    let mut status: &'static str = "unsigned";
    let mut signer_key_id: Option<String> = None;

    for layer in structure {
        if let MessageLayer::SignatureGroup { results } = layer {
            for result in results {
                let (new_status, key): (&'static str, Option<String>) = match result {
                    Ok(GoodChecksum { ka, .. }) => {
                        ("valid", Some(ka.cert().fingerprint().to_hex()))
                    }
                    // Signer's public key was not supplied -> cannot verify.
                    // This is NOT a failure; the message is still authentic
                    // as far as we can tell, we just can't confirm the signer.
                    Err(VerificationError::MissingKey { sig }) => {
                        ("unknown_key", issuer_hex(sig))
                    }
                    Err(VerificationError::UnboundKey { .. }) => ("unknown_key", None),
                    // We had a key but verification failed: possible tamper.
                    Err(_) => ("invalid", None),
                };
                if sig_rank(new_status) > sig_rank(status) {
                    status = new_status;
                    signer_key_id = key;
                } else if signer_key_id.is_none() {
                    signer_key_id = key;
                }
            }
        }
    }
    (status, signer_key_id)
}

// =====================================================================
// Private key store (keys live in WASM linear memory, never in JS)
// =====================================================================

// KEY_STORE: the unlocked-cert cache. Entries are the serialized secret cert
// (`serialize_secret_cert`) in a `Zeroizing<Vec<u8>>`, so removal, overwrite
// and teardown all wipe the bytes -- the store type is
// `protected::HandleStore`, the same machinery `crx.rs` uses for
// `CRX_KEY_STORE`.
//
// It is a *distinct instance*, not a shared one: nothing outside this module
// can reach it, which is what keeps "populated only by the unlock paths"
// (SECURITY.md §4) a property of `insert_key`'s call sites rather than a hope
// about every caller in the crate.
thread_local! {
    static KEY_STORE: protected::HandleStore = protected::HandleStore::new();
    static NEXT_HANDLE: RefCell<u32> = RefCell::new(1);
}

/// Hand out the next handle. Monotonic and never reused across *any* store
/// in the crate (`crx.rs` draws from this counter too), so a stale handle
/// from a dropped key can never silently address a later one.
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
    let stored = serialize_secret_cert(cert)?;
    KEY_STORE.with(|store| store.insert(stored))
}

fn get_cert_from_handle(handle: u32) -> Result<openpgp::Cert, String> {
    KEY_STORE
        .with(|store| store.with(handle, |bytes| openpgp::Cert::from_bytes(bytes).str_err()))
        .ok_or("Key handle not found - key may have been locked")?
}

/// Test-only bridges to the internal cert/handle API.
///
/// The old public `generateKey` / `storeKey` wasm exports were removed (keys
/// now only enter `KEY_STORE` via the unlock paths -- see the note above the
/// public API). The unit tests predate that change, so these thin shims give
/// them a way to mint a cert and a handle directly without a full
/// password/PRF protect+unlock round trip.
#[cfg(test)]
fn generate_key(options_json: &str) -> Result<String, String> {
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
fn store_key(armored: &str) -> Result<u32, String> {
    let cert = openpgp::Cert::from_bytes(armored.as_bytes()).str_err()?;
    insert_key(&cert)
}


// =====================================================================
// Output size caps
// =====================================================================

/// Absolute ceiling on any decrypted message: wasm32 cannot address more
/// than 4 GiB in total, so nothing above this is reachable regardless of
/// what we allow. `u64` because 4 GiB does not fit in a wasm32 `usize`
/// (it overflows by exactly one byte).
const MAX_DECRYPTED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// How much larger than its ciphertext a message may legitimately
/// decrypt to.
///
/// THIS, not a flat number, is what separates a big file from a bomb.
/// A real encrypted file decrypts to roughly its own size -- this app's
/// own `encrypt` does not even compress (8 MiB of one repeated byte
/// produced an 11 MiB ciphertext), and GnuPG's deflate manages single
/// digits on ordinary data. A decompression bomb is 754x, measured.
/// Four leaves enormous room for the former while refusing the latter,
/// and unlike a flat ceiling it does not have to choose between allowing
/// a 1 GiB file and refusing a 5 MiB paste that expands to 3.7 GiB.
const MAX_EXPANSION_RATIO: u64 = 4;

/// Below this, the ratio is meaningless: a 200-byte message legitimately
/// decrypts to far more than 4x its armored size once the PKESK and
/// packet framing come off. So small messages get a flat allowance and
/// the ratio only starts binding once there is enough size for it to
/// mean something.
const MIN_EXPANSION_ALLOWANCE: u64 = 64 * 1024 * 1024;

/// Ceiling on verified cleartext. Kept separate and much tighter, and
/// not as a matter of taste: `verify_message` returns its content inside
/// a JSON string, escaping costs 6 bytes per NUL (`\u0000`), and the
/// whole thing then has to exist as one `String` in a 32-bit address
/// space. 4 GiB is not merely unwise here, it is unrepresentable.
///
/// 16 MiB of UTF-8 is on the order of ten thousand pages -- no
/// cleartext-signed message a person reads in a side panel comes close.
const MAX_VERIFIED_BYTES: u64 = 16 * 1024 * 1024;

/// The output ceiling for a given ciphertext: generous in absolute terms
/// so a legitimately large file is not refused, but tied to the input so
/// amplification cannot run away.
fn decrypt_limit(ciphertext_len: usize) -> u64 {
    (ciphertext_len as u64)
        .saturating_mul(MAX_EXPANSION_RATIO)
        .max(MIN_EXPANSION_ALLOWANCE)
        .min(MAX_DECRYPTED_BYTES)
}

fn read_capped<R: std::io::Read>(
    reader: R,
    limit: u64,
    what: &str,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    std::io::copy(&mut reader.take(limit + 1), &mut out).str_err()?;

    if out.len() as u64 > limit {
        out.zeroize();
        return Err(format!(
            "This {what} is too large to open here (limit {} MiB).",
            limit / (1024 * 1024),
        ));
    }
    Ok(out)
}

// =====================================================================
// Sequoia verification/decryption helpers
// =====================================================================

struct DecryptHelper {
    decryption_cert: openpgp::Cert,
    verification_certs: Vec<openpgp::Cert>,
    signature_status: &'static str,
    signer_key_id: Option<String>,
}

impl VerificationHelper for DecryptHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(self.verification_certs.clone())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        // NOTE: signature classification must never abort decryption. A
        // missing signer key or a bad signature is reported as status, not
        // returned as an error, so the plaintext is always delivered.
        let (status, key_id) = process_signatures(structure);
        self.signature_status = status;
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
        let vc = self.decryption_cert.with_policy(policy(), None)?;
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

/// The symmetric sibling of [`DecryptHelper`]: opens a message that was
/// encrypted to a PASSWORD (`gpg -c`) rather than to a public key.
///
/// The two are separate helpers rather than one helper with an optional
/// password, and that is the point. A message can carry both SKESK
/// (password) and PKESK (public key) packets, and which one this app
/// uses must be decided by the caller in the open -- not by a helper
/// that quietly falls back to whichever happens to work. This one
/// ignores `pkesks` entirely, and `DecryptHelper` ignores `skesks`.
struct PasswordDecryptHelper {
    /// Sequoia's `Password` keeps the bytes in protected memory and
    /// zeroizes on drop, so the passphrase is not left in a plain
    /// `String` for the lifetime of the parse.
    password: openpgp::crypto::Password,
    verification_certs: Vec<openpgp::Cert>,
    signature_status: &'static str,
    signer_key_id: Option<String>,
}

impl VerificationHelper for PasswordDecryptHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(self.verification_certs.clone())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        // Same rule as the key path: signature classification must never
        // abort decryption. A symmetric message CAN be signed, and the
        // signer is then someone whose key we may or may not hold.
        let (status, key_id) = process_signatures(structure);
        self.signature_status = status;
        self.signer_key_id = key_id;
        Ok(())
    }
}

impl DecryptionHelper for PasswordDecryptHelper {
    fn decrypt(
        &mut self,
        _pkesks: &[openpgp::packet::PKESK],
        skesks: &[openpgp::packet::SKESK],
        _sym_algo: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<openpgp::Cert>> {
        // Every SKESK is tried: `gpg --symmetric` writes one, but the
        // format permits several (the same message encrypted under more
        // than one password), and refusing the second one would be a
        // silent "wrong password" for a message we can actually open.
        //
        // NOTE ON WHAT A SUCCESSFUL `skesk.decrypt` MEANS: for a v4 SKESK
        // it means almost nothing. The password-derived key unwraps the
        // session key with no integrity check, so a WRONG password
        // yields a plausible-looking session key here and the failure
        // surfaces later, as an MDC mismatch, out of the reader. That is
        // why the wasm entry point below treats a failure anywhere in the
        // parse as "the password did not work" rather than trying to tell
        // the two apart. A v5/v6 SKESK is AEAD-protected and does fail
        // here -- both paths end in the same message.
        for skesk in skesks {
            if let Ok((algo, session_key)) = skesk.decrypt(&self.password) {
                if decrypt(algo, &session_key) {
                    // No cert was involved: this message was not opened
                    // with anyone's key, and saying otherwise would put a
                    // fingerprint in the result that decrypted nothing.
                    return Ok(None);
                }
            }
        }
        Err(anyhow::anyhow!(
            "None of this message's password packets accepted that password"
        ))
    }
}

struct VerifyHelper {
    certs: Vec<openpgp::Cert>,
    signature_status: &'static str,
    signer_key_id: Option<String>,
}

impl VerificationHelper for VerifyHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(self.certs.clone())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        let (status, key_id) = process_signatures(structure);
        self.signature_status = status;
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
///
/// Parses only the *first* certificate in the input. For blobs that may
/// bundle several certs (see `parse_keys`), prefer `parseKeys`.
#[wasm_bindgen(js_name = "parseKey")]
pub fn parse_key(armored: &str) -> Result<String, String> {
    let cert = openpgp::Cert::from_bytes(armored.as_bytes()).str_err()?;
    let is_private = cert.keys().secret().next().is_some();
    serde_json::to_string(&extract_key_info(&cert, is_private)).str_err()
}

/// Hard cap on the rows `parse_key_details` returns. Real certs carry a
/// handful of subkeys; a crafted cert can carry thousands, and each row
/// costs a `with_policy` evaluation here plus a DOM node in the side
/// panel. Excess rows are dropped and flagged via `truncated`.
const MAX_DETAIL_ROWS: usize = 100;

/// Cap and clean an attacker-controlled string before it crosses to the
/// UI: drop control characters and Unicode bidi overrides (which could
/// visually reorder surrounding UI text), then truncate to `max` chars.
fn sanitize_untrusted(s: &str, max: usize) -> String {
    let mut out = String::new();
    let cleaned = s.chars().filter(|c| {
        !c.is_control() && !matches!(*c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    });
    for (i, c) in cleaned.enumerate() {
        if i == max {
            out.push('…');
            break;
        }
        out.push(c);
    }
    out
}

/// Human-readable reason from a *verified* revocation, or `None` when
/// not revoked. `CouldBe` (unverifiable third-party sig) is deliberately
/// not treated as revoked, matching sequoia/GnuPG semantics.
fn verified_revocation_reason(status: &RevocationStatus) -> Option<String> {
    let RevocationStatus::Revoked(sigs) = status else {
        return None;
    };
    Some(
        sigs.first()
            .and_then(|s| s.reason_for_revocation())
            .map(|(code, msg)| {
                let msg = String::from_utf8_lossy(msg);
                if msg.is_empty() {
                    code.to_string()
                } else {
                    format!("{code}: {msg}")
                }
            })
            .map(|reason| sanitize_untrusted(&reason, 300))
            .unwrap_or_else(|| "No reason given".to_string()),
    )
}

/// Per-component-key breakdown of a certificate: the primary key plus
/// every subkey, each with capability flags and lifecycle status.
/// Returns JSON `{ keys: SubkeyDetail[], truncated: bool }`, primary
/// key first, in cert order. Accepts public or private armor (secret
/// material is dropped at end of call, as in `parse_key`).
///
/// Unlike `ValidCert::keys()`, this walks `cert.keys()` so that keys
/// whose binding signature fails our `policy()` still get a row
/// (status "invalid") -- the whole point of the details view is to
/// show the user the dead weight, not silently hide it.
#[wasm_bindgen(js_name = "parseKeyDetails")]
pub fn parse_key_details(armored: &str) -> Result<String, String> {
    let cert = openpgp::Cert::from_bytes(armored.as_bytes()).str_err()?;
    let primary_fp = cert.fingerprint();

    // Cert-level lifecycle, computed once. A subkey cannot outlive its
    // certificate: if the primary key is revoked or expired, every
    // subkey is dead with it, even though the subkey's own binding
    // signature and revocation status look clean. Without this, a
    // fully revoked cert would show green "active" encryption subkeys.
    let (cert_revoked_reason, cert_expiry_if_expired) = match cert.with_policy(policy(), None) {
        Ok(vc) => {
            let revoked = verified_revocation_reason(&vc.revocation_status());
            let expired = if revoked.is_none() && vc.alive().is_err() {
                Some(vc.primary_key().key_expiration_time().map(system_time_to_millis))
            } else {
                None
            };
            (revoked, expired)
        }
        Err(_) => (None, None),
    };

    let truncated = cert.keys().count() > MAX_DETAIL_ROWS;
    let mut keys = Vec::new();
    for ka in cert.keys().take(MAX_DETAIL_ROWS) {
        let key = ka.key();
        let fingerprint = key.fingerprint();
        let is_primary = fingerprint == primary_fp;
        let mut detail = SubkeyDetail {
            fingerprint: fingerprint.to_hex(),
            key_id: key.keyid().to_hex(),
            algorithm: key.pk_algo().to_string(),
            bits: key.mpis().bits(),
            created_at: system_time_to_millis(key.creation_time()),
            expires_at: None,
            is_primary,
            can_sign: false,
            can_encrypt: false,
            can_certify: false,
            can_authenticate: false,
            status: "invalid".to_string(),
            revocation_reason: None,
            policy_error: None,
        };

        match ka.with_policy(policy(), None) {
            Ok(vka) => {
                let flags = vka.key_flags().unwrap_or_else(KeyFlags::empty);
                detail.can_sign = flags.for_signing();
                detail.can_encrypt =
                    flags.for_transport_encryption() || flags.for_storage_encryption();
                detail.can_certify = flags.for_certification();
                detail.can_authenticate = flags.for_authentication();
                detail.expires_at = vka.key_expiration_time().map(system_time_to_millis);

                if let Some(reason) = verified_revocation_reason(&vka.revocation_status()) {
                    detail.status = "revoked".to_string();
                    detail.revocation_reason = Some(reason);
                } else if let Some(reason) = &cert_revoked_reason {
                    // Own status clean, but the whole cert is revoked.
                    detail.status = "revoked".to_string();
                    if !is_primary {
                        detail.revocation_reason =
                            Some(format!("Certificate revoked: {reason}"));
                    }
                } else if vka.alive().is_err() || cert_expiry_if_expired.is_some() {
                    detail.status = "expired".to_string();
                    if detail.expires_at.is_none() {
                        detail.expires_at = cert_expiry_if_expired.flatten();
                    }
                } else {
                    detail.status = "active".to_string();
                }
            }
            Err(e) => {
                detail.policy_error =
                    Some(sanitize_untrusted(&humanize_policy_error(&e.to_string()), 300));
            }
        }
        keys.push(detail);
    }
    serde_json::to_string(&serde_json::json!({ "keys": keys, "truncated": truncated }))
        .str_err()
}

/// A single cert extracted from a (possibly multi-cert) armored blob,
/// paired with its own re-armored form so callers can store/encrypt
/// against exactly that cert rather than the whole blob.
#[derive(Serialize)]
struct ParsedCert {
    #[serde(rename = "keyInfo")]
    key_info: KeyInfo,
    armored: String,
}

/// Parse one *or more* concatenated certificates from an armored blob.
///
/// Some publishers ship a single `.asc` containing several
/// yearly-rotated certificates (e.g. CTIR Gov). `Cert::from_bytes` only
/// ever sees the first -- typically the oldest, long-expired -- cert, so
/// the live key in the bundle is never imported and (worse) storing the
/// whole blob would make us encrypt against the dead first cert. This
/// splits the blob with `CertParser` and returns every cert with its own
/// re-armored public key and `KeyInfo`, so the caller can keep the
/// usable ones and drop the expired rotations.
#[wasm_bindgen(js_name = "parseKeys")]
pub fn parse_keys(armored: &str) -> Result<String, String> {
    let parser = CertParser::from_bytes(armored.as_bytes()).str_err()?;
    let mut out = Vec::new();
    for cert in parser {
        let cert = cert.str_err()?;
        let is_private = cert.keys().secret().next().is_some();
        let key_info = extract_key_info(&cert, is_private);
        let armored = armor_cert(&cert, is_private)?;
        out.push(ParsedCert { key_info, armored });
    }
    if out.is_empty() {
        return Err("No OpenPGP certificate found".to_string());
    }
    serde_json::to_string(&out).str_err()
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
    // Optional, OWNED, and bytes -- the same three properties
    // `decrypt_with_password` takes them with, for the same reasons. See
    // `T-SYMMETRIC-ENCRYPT-PASSWORD` for what this password is and is not
    // worth.
    //
    // THE S2K IS SEQUOIA'S DEFAULT and is deliberately not overridden:
    // SHA-256 iterated at count 0x3e00000, which is the LARGEST the
    // OpenPGP wire format can represent (~354ms to derive on a moderate
    // CPU). There is no stronger value to choose, so this app is taking
    // the format's maximum rather than picking a number on the user's
    // behalf. The stream API exposes no setter for it in any case.
    password: Option<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    // Wrapped at the boundary, before anything can return early, so the
    // marshalled copy is scrubbed on every path including the error ones.
    let password = password.map(Zeroizing::new);
    let signer_cert = signing_key_armored
        .as_deref()
        .map(|armor| openpgp::Cert::from_bytes(armor.as_bytes()).str_err())
        .transpose()?;
    encrypt_impl(plaintext, recipient_keys_json, signer_cert.as_ref(), password)
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
        signature_status: "unsigned",
        signer_key_id: None,
    };

    let mut verifier = VerifierBuilder::from_bytes(signed_message.as_bytes())
        .str_err()?
        .with_policy(policy(), None, helper)
        .str_err()?;

    let content = read_capped(&mut verifier, MAX_VERIFIED_BYTES, "signed message")?;
    let helper = verifier.into_helper();

    serde_json::to_string(&VerifyResult {
        text: String::from_utf8(content).str_err()?,
        signature_valid: helper.signature_status == "valid",
        signature_status: helper.signature_status.to_string(),
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
    KEY_STORE.with(|store| store.remove(handle));
    Ok(())
}

/// Encrypt + sign using a stored signing key handle.
#[wasm_bindgen(js_name = "encryptWithSigningHandle")]
pub fn encrypt_with_signing_handle(
    plaintext: &[u8],
    recipient_keys_json: &str,
    signing_key_handle: u32,
    password: Option<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let password = password.map(Zeroizing::new);
    let signer_cert = get_cert_from_handle(signing_key_handle)?;
    encrypt_impl(
        plaintext,
        recipient_keys_json,
        Some(&signer_cert),
        password,
    )
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
        signature_status: "unsigned",
        signer_key_id: None,
    };

    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
        .str_err()?
        .with_policy(policy(), None, helper)
        .str_err()?;

    let plaintext = read_capped(&mut decryptor, decrypt_limit(ciphertext.len()), "message")?;
    let helper = decryptor.into_helper();

    Ok(pack_decrypt_result(
        helper.signature_status,
        helper.signer_key_id,
        plaintext,
    ))
}

/// `[4-byte LE sig_json_len][sig_json][plaintext]`.
///
/// Shared by both decrypt entry points so the packed layout is defined
/// once. The packing is what makes the return ATOMIC: signature status
/// and plaintext cross the wasm boundary together, so no caller can
/// render the plaintext against a signature verdict read separately (the
/// TOCTOU the original comment names). A second hand-rolled copy of this
/// layout would be free to disagree with `unpackDecryptResult` in JS.
fn pack_decrypt_result(
    signature_status: &str,
    signer_key_id: Option<String>,
    plaintext: Vec<u8>,
) -> Vec<u8> {
    let sig_json = serde_json::json!({
        "signatureValid": signature_status == "valid",
        "signatureStatus": signature_status,
        "signerKeyId": signer_key_id,
    })
    .to_string();
    let sig_bytes = sig_json.as_bytes();
    let sig_len = (sig_bytes.len() as u32).to_le_bytes();

    let mut result = Vec::with_capacity(4 + sig_bytes.len() + plaintext.len());
    result.extend_from_slice(&sig_len);
    result.extend_from_slice(sig_bytes);
    result.extend_from_slice(&plaintext);
    result
}

/// Decrypt a message that was encrypted to a PASSWORD (`gpg --symmetric`).
///
/// Returns the same packed binary as [`decrypt_with_handle`], so the
/// caller unpacks one shape whichever way the message was opened.
///
/// NO KEY IS INVOLVED, and that is the whole difference: this works with
/// an empty keyring, and it never touches `KEY_STORE`. Signature
/// verification still runs -- a symmetric message can be signed -- against
/// whatever public keys the caller passes.
///
/// ON THE ERROR IT RETURNS: a wrong password is not reliably detectable
/// at the point the password is used. A v4 SKESK unwraps the session key
/// with no integrity check, so a wrong password produces a plausible
/// session key and fails much later as an MDC mismatch inside the reader.
/// Rather than pretend to tell "wrong password" from "corrupt message"
/// apart, every failure in the parse comes back under one leading phrase
/// the JS classifies on, with the underlying error kept after it for the
/// technical-details line.
#[wasm_bindgen(js_name = "decryptWithPassword")]
pub fn decrypt_with_password(
    ciphertext: &[u8],
    // BYTES, not a `&str`, and OWNED, not borrowed.
    //
    // Bytes for the reason the whole of `lib/pgp/wasm-secrets.ts` exists:
    // a JS string is immutable and unzeroizable, so a password that
    // crosses as one is left in the JS heap for the collector to deal
    // with whenever it feels like it. The caller hands over a
    // `Uint8Array` and `.fill(0)`s it in a `finally`.
    //
    // Owned so this side can scrub too. `unlock_with_password` and its
    // siblings borrow `&[u8]`, which means wasm-bindgen frees its
    // marshalled copy un-scrubbed and only the DERIVED key is zeroized --
    // the known gap `T-UNLOCK-PARAM-NOT-OWNED` records. Taking `Vec<u8>`
    // here means there is something to wrap, so this export does not
    // widen that gap and needs no exemption in
    // `scripts/audit-invariants.mjs`.
    password: Vec<u8>,
    verification_keys_json: Option<String>,
) -> Result<Vec<u8>, String> {
    // Wrapped FIRST, before anything can return early: the `Drop` is what
    // scrubs the marshalled copy, and an error path that returns above
    // this line would skip it.
    let password = Zeroizing::new(password);
    let verification_certs = match verification_keys_json {
        Some(ref json) => parse_armored_certs(json)?,
        None => Vec::new(),
    };

    let helper = PasswordDecryptHelper {
        password: password.as_slice().into(),
        verification_certs,
        signature_status: "unsigned",
        signer_key_id: None,
    };

    // The unreadable-FORMAT case, separated from the wrong-PASSWORD case
    // before the password is even used. Sequoia's policy rejects the
    // draft AEAD packet, and that failure arrives as "Policy rejected
    // packet type" -- which, folded into the message below, would tell a
    // user with a perfectly good password to go and check their password.
    // They would never get anywhere: no password opens this.
    if scan_session_packets(ciphertext)?.2 == Container::Aed {
        return Err(
            "This message uses the older AEAD (OCB) encrypted-data format, which this app cannot read. Ask the sender to re-encrypt it without --force-ocb."
                .to_string(),
        );
    }

    decrypt_with_password_inner(ciphertext, helper)
        .map_err(|e| format!("Wrong password, or this message is damaged: {e}"))
}

/// The fallible half, split out so ONE `map_err` covers the whole parse
/// -- builder, policy check, session-key unwrap and the reader's MDC
/// check are all "the password did not work" from the caller's side, and
/// a wrapper applied per-step would inevitably miss one.
fn decrypt_with_password_inner(
    ciphertext: &[u8],
    helper: PasswordDecryptHelper,
) -> Result<Vec<u8>, String> {
    let mut decryptor = DecryptorBuilder::from_bytes(ciphertext)
        .str_err()?
        .with_policy(policy(), None, helper)
        .str_err()?;

    let plaintext = read_capped(&mut decryptor, decrypt_limit(ciphertext.len()), "message")?;
    let helper = decryptor.into_helper();

    Ok(pack_decrypt_result(
        helper.signature_status,
        helper.signer_key_id,
        plaintext,
    ))
}

/// The encrypted container a message uses, which decides whether we can
/// read it at all.
#[derive(PartialEq)]
enum Container {
    /// `SEIP` -- v1 (CFB + MDC) or v2 (RFC 9580 AEAD). Both supported.
    Seip,
    /// `AED`, tag 20: the pre-RFC-9580 draft AEAD packet that GnuPG
    /// writes under `--force-ocb` and that LibrePGP kept. Sequoia's
    /// StandardPolicy rejects it, so we cannot read it -- and the point of
    /// naming it here is that the failure must not be reported as a wrong
    /// password. See `decrypt_with_password`.
    Aed,
    /// No encrypted container found (not an encrypted message).
    None,
}

/// What the session-key packets in FRONT of the encrypted container say.
///
/// Matched on the packet TAG rather than on the parsed `Packet` variant,
/// and that is load-bearing rather than stylistic: Sequoia yields
/// `Packet::Unknown` for a packet VERSION it does not implement, while
/// still reporting the original tag. GnuPG's `--force-ocb` SKESK is
/// exactly such a packet, and a `Packet::SKESK(_)` match reported that
/// message as having no password at all -- sending the UI to ask for a
/// key for a message that never wanted one. The tag is what the format
/// guarantees; the variant is what our parser happened to manage.
fn scan_session_packets(ciphertext: &[u8]) -> Result<(bool, bool, Container), String> {
    use openpgp::packet::Tag;
    use openpgp::parse::{PacketParser, PacketParserResult};

    let mut password = false;
    let mut public_key = false;
    let mut container = Container::None;
    let mut ppr = PacketParser::from_bytes(ciphertext).str_err()?;
    while let PacketParserResult::Some(pp) = ppr {
        match pp.packet.tag() {
            Tag::SKESK => password = true,
            Tag::PKESK => public_key = true,
            // The session-key packets all precede the encrypted
            // container; once we reach it there is nothing further to
            // learn, and descending into it would mean decrypting.
            Tag::SEIP => {
                container = Container::Seip;
                break;
            }
            Tag::AED => {
                container = Container::Aed;
                break;
            }
            _ => {}
        }
        let (_packet, next) = pp.next().str_err()?;
        ppr = next;
    }
    Ok((password, public_key, container))
}

/// How a message can be opened, as JSON: `{"password":bool,"publicKey":bool}`.
///
/// Shape only -- it reads the session-key packets that precede the
/// encrypted container and says which KINDS are present. It does not and
/// cannot say whether any particular password or key will work.
///
/// The UI needs this to decide what to ASK FOR before it asks: without
/// it, a `gpg -c` message reaches the key path and comes back "no
/// suitable decryption key found", which is true and useless -- the
/// message never wanted a key. Both flags can be true at once (a message
/// encrypted to a password AND to recipients); the caller decides which
/// to use, and `useWorkspaceOperations` prefers the key when one of the
/// user's own matches.
#[wasm_bindgen(js_name = "messageEncryption")]
pub fn message_encryption(ciphertext: &[u8]) -> Result<String, String> {
    let (password, public_key, _container) = scan_session_packets(ciphertext)?;
    Ok(serde_json::json!({ "password": password, "publicKey": public_key }).to_string())
}

/// Collect the recipient key handles referenced by a message's public-key
/// encrypted session-key (PKESK) packets. Anonymous/wildcard recipients carry
/// no key handle and are skipped (they can't be matched to a specific key).
fn recipient_handles(ciphertext: &[u8]) -> Result<Vec<openpgp::KeyHandle>, String> {
    use openpgp::parse::{PacketParser, PacketParserResult};
    let mut handles = Vec::new();
    let mut ppr = PacketParser::from_bytes(ciphertext).str_err()?;
    while let PacketParserResult::Some(pp) = ppr {
        match &pp.packet {
            openpgp::Packet::PKESK(pkesk) => {
                if let Some(handle) = pkesk.recipient() {
                    handles.push(handle);
                }
            }
            // Session-key packets precede the encrypted container; once we
            // reach it there are no further recipients to discover.
            openpgp::Packet::SEIP(_) => break,
            _ => {}
        }
        let (_packet, next) = pp.next().str_err()?;
        ppr = next;
    }
    Ok(handles)
}

/// Pick which of the caller's public keys should decrypt `ciphertext`, by
/// matching the message's recipient key IDs against each candidate cert's
/// (sub)keys. Returns JSON: the matching primary fingerprint hex (same form
/// as `KeyInfo.keyId`), or `null` when nothing matches.
///
/// This lets the UI default-select the correct decryption key up front,
/// without unlocking every candidate and trial-decrypting.
#[wasm_bindgen(js_name = "selectDecryptionKey")]
pub fn select_decryption_key(
    ciphertext: &[u8],
    candidate_pubkeys_json: &str,
) -> Result<String, String> {
    let recipients = recipient_handles(ciphertext)?;
    let candidates: Vec<String> =
        serde_json::from_str(candidate_pubkeys_json).str_err()?;

    let matched: Option<String> = if recipients.is_empty() {
        None
    } else {
        candidates.iter().find_map(|armored| {
            let cert = openpgp::Cert::from_bytes(armored.as_bytes()).ok()?;
            // `aliases` matches regardless of whether the recipient was named
            // by fingerprint or by (shorter) key id.
            let owns = cert.keys().any(|ka| {
                let kh = ka.key().key_handle();
                recipients.iter().any(|r| r.aliases(&kh))
            });
            owns.then(|| cert.fingerprint().to_hex())
        })
    };

    serde_json::to_string(&matched).str_err()
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

/// Mint an armored revocation certificate for a stored (unlocked) key.
/// Backfills what generation already provides: imported keys arrive
/// without one, but we hold the primary secret, so we can self-sign a
/// revocation on demand. Returns only a public signature packet -- no
/// secret material crosses the boundary.
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
    // "Unspecified" matches gpg's own pre-generated certificates: the
    // cert is minted long before the reason (loss, compromise) is known.
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

/// Serialize the metadata and pack it ahead of the protection blob as
/// `[u32_le json_len][json][blob]` -- see `protected::pack_meta_blob`, which
/// the CRX protect paths share.
fn pack_protect_result(meta: &ProtectResultMeta, blob: &[u8]) -> Result<Vec<u8>, String> {
    let json = serde_json::to_string(meta).str_err()?;
    Ok(protected::pack_meta_blob(&json, blob))
}

/// Encrypt a cert's secret material under an Argon2id-derived AES-GCM key.
/// Returns `[16-byte salt][12-byte iv][ciphertext]`.
/// AAD is bound to the cert's fingerprint so the blob can't be swapped
/// between key entries, and prefixed with `PASSWORD_AAD_PREFIX` so it can't
/// be swapped with a CRX blob either.
fn encrypt_cert_with_password(
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

/// Encrypt a cert's secret material under a HKDF(PRF, storedSecret)-derived
/// AES-GCM key. Returns `[12-byte iv][ciphertext]`.
fn encrypt_cert_with_prf(
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

/// Decrypt one S2K-protected component key, falling back to a manual
/// path that tolerates GnuPG's fixed-width ECC secret MPIs (see
/// `decrypt_gpg_padded_secret`).
fn decrypt_key_secret<R>(
    key: openpgp::packet::Key<openpgp::packet::key::SecretParts, R>,
    password: &openpgp::crypto::Password,
) -> Result<openpgp::packet::Key<openpgp::packet::key::SecretParts, R>, String>
where
    R: openpgp::packet::key::KeyRole,
{
    match key.clone().decrypt_secret(password) {
        Ok(k) => Ok(k),
        Err(e) => decrypt_gpg_padded_secret(key, password, &e),
    }
}

/// Was a `decrypt_secret` failure the one the manual fallback exists
/// for -- Sequoia's strict secret-MPI parser refusing GnuPG's padded
/// scalar?
///
/// What this *can* distinguish: `Error::MalformedMPI` from every other
/// error kind. In particular Sequoia rejects protection schemes RFC 9580
/// forbids (Argon2 without AEAD, implicit/simple S2K on a v6 key,
/// malleable CFB on a v6 key) with `InvalidOperation` *before* touching
/// the ciphertext -- and our manual path does not re-implement those
/// checks, so routing those errors here would have been a genuine
/// validation downgrade. They no longer reach it.
///
/// It also excludes the "checksum wrong" MalformedMPI: that one means
/// the decrypted MPIs parsed cleanly and only the trailing checksum
/// failed, i.e. the plaintext was well-formed and the passphrase is
/// simply wrong. Matching on the message is unpleasant, but Sequoia
/// gives both failures the same variant, so the message is the only
/// signal there is; if it ever stops matching we fall back more often,
/// never less safely.
///
/// What this *cannot* distinguish: a padded-MPI parse failure from a
/// wrong-passphrase parse failure. Sequoia deliberately collapses every
/// secret-MPI parse error into a single uniform
/// `MalformedMPI("Details omitted, parsing secret")` so the error kind
/// cannot leak anything about the secret, so both land in this arm. The
/// manual path re-verifies the checksum itself, so a wrong passphrase
/// still ends as "Incorrect passphrase" -- it just costs one more S2K +
/// CFB pass to get there.
fn is_padded_mpi_failure(e: &anyhow::Error) -> bool {
    match e.downcast_ref::<openpgp::Error>() {
        Some(openpgp::Error::MalformedMPI(msg)) => !msg.contains("checksum"),
        _ => false,
    }
}

/// GnuPG (libgcrypt) serializes protected ECC secret scalars as
/// fixed-width MPIs padded to the field size: a 253-bit Ed25519 scalar
/// is declared as 256 bits with leading zero bits. Sequoia's strict
/// secret-MPI parser rejects the non-minimal encoding, which makes
/// roughly half of all `gpg --export-secret-keys` ECC keys (top scalar
/// bit clear) fail `decrypt_secret` with "Malformed MPI". Redo the
/// decryption by hand -- S2K, CFB, checksum -- and re-encode the scalar
/// minimally so Sequoia accepts it.
fn decrypt_gpg_padded_secret<R>(
    key: openpgp::packet::Key<openpgp::packet::key::SecretParts, R>,
    password: &openpgp::crypto::Password,
    sequoia_err: &anyhow::Error,
) -> Result<openpgp::packet::Key<openpgp::packet::key::SecretParts, R>, String>
where
    R: openpgp::packet::key::KeyRole,
{
    use openpgp::crypto::mpi;
    use openpgp::crypto::S2K;
    use openpgp::types::PublicKeyAlgorithm;

    const WRONG: &str = "Incorrect passphrase";

    // Only the single-scalar ECC algorithms need this: libgcrypt encodes
    // RSA/DSA/ElGamal secrets minimally, so for those a Sequoia failure
    // really does mean a wrong passphrase.
    let pk_algo = key.pk_algo();
    if !matches!(
        pk_algo,
        PublicKeyAlgorithm::EdDSA | PublicKeyAlgorithm::ECDSA | PublicKeyAlgorithm::ECDH
    ) {
        return Err(WRONG.into());
    }

    let openpgp::packet::key::SecretKeyMaterial::Encrypted(e) = key.secret() else {
        return Err(WRONG.into());
    };
    // `gpg --export-secret-subkeys` stubs the primary with a GNU-dummy
    // S2K (private type 101): there is no secret to decrypt at all.
    if let S2K::Private { tag: 101, .. } = e.s2k() {
        return Err(
            "This key's primary secret is a stub (offline primary key). \
             Import a full export (gpg --export-secret-keys) instead."
                .into(),
        );
    }
    if e.aead_algo().is_some() {
        return Err(WRONG.into());
    }

    // Everything above is diagnosis, not decryption: it decides which
    // message the user sees and touches no ciphertext. Only here do we
    // commit to redoing the crypto by hand, and only for the failure
    // this function was written for -- see `is_padded_mpi_failure`.
    // Anything else (a protection scheme Sequoia refused outright, a
    // truncated packet) is not something a second, less strict attempt
    // should be given a chance at.
    if !is_padded_mpi_failure(sequoia_err) {
        return Err(WRONG.into());
    }

    let sym = e.algo();
    let key_size = sym.key_size().map_err(|_| WRONG.to_string())?;
    let block_size = sym.block_size().map_err(|_| WRONG.to_string())?;
    let derived = e
        .s2k()
        .derive_key(password, key_size)
        .map_err(|_| WRONG.to_string())?;
    // Sequoia stores the packet's IV prepended to the ciphertext.
    let ct = e.ciphertext().map_err(|_| WRONG.to_string())?;
    if ct.len() < block_size + 3 {
        return Err(WRONG.into());
    }
    let (iv, data) = ct.split_at(block_size);
    let plaintext = Zeroizing::new(cfb_decrypt(sym, &derived, iv, data)?);

    // Split off and verify the trailing checksum; a mismatch means the
    // passphrase really is wrong.
    let body = match e.checksum().unwrap_or_default() {
        mpi::SecretKeyChecksum::SHA1 => {
            let split = plaintext.len().checked_sub(20).ok_or(WRONG)?;
            let (body, want) = plaintext.split_at(split);
            let mut ctx = HashAlgorithm::SHA1
                .context()
                .map_err(|_| WRONG.to_string())?
                .for_digest();
            ctx.update(body);
            let got = ctx.into_digest().map_err(|_| WRONG.to_string())?;
            // Constant-time: this comparison *is* the passphrase check,
            // so a variable-time `!=` would leak how many leading bytes
            // of a guess were right. `ct_eq` on slices also yields a
            // false `Choice` (not a panic) on a length mismatch.
            if !bool::from(got.as_slice().ct_eq(want)) {
                return Err(WRONG.into());
            }
            body
        }
        mpi::SecretKeyChecksum::Sum16 => {
            let split = plaintext.len().checked_sub(2).ok_or(WRONG)?;
            let (body, want) = plaintext.split_at(split);
            let got = body
                .iter()
                .fold(0u16, |acc, b| acc.wrapping_add(*b as u16));
            // Constant-time for the same reason as the SHA-1 arm above.
            if !bool::from(got.to_be_bytes().ct_eq(want)) {
                return Err(WRONG.into());
            }
            body
        }
    };

    // One scalar MPI: 2-byte declared bit length + (possibly padded)
    // value. `ProtectedMPI::from` re-encodes with leading zeros trimmed.
    if body.len() < 2 {
        return Err(WRONG.into());
    }
    let declared_bits = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() != 2 + declared_bits.div_ceil(8) {
        return Err(WRONG.into());
    }
    let scalar: mpi::ProtectedMPI = (&body[2..]).into();
    let material = match pk_algo {
        PublicKeyAlgorithm::EdDSA => mpi::SecretKeyMaterial::EdDSA { scalar },
        PublicKeyAlgorithm::ECDSA => mpi::SecretKeyMaterial::ECDSA { scalar },
        _ => mpi::SecretKeyMaterial::ECDH { scalar },
    };
    Ok(key.parts_into_public().add_secret(material.into()).0)
}

/// CFB-128 decryption (OpenPGP's secret-key protection mode) for the
/// AES family. Used only by the gpg-padded fallback above; the checksum
/// verified afterwards authenticates the result.
///
/// The mode itself comes from RustCrypto's `cfb-mode` -- crypto is never
/// implemented in-house here. That is not just hygiene: a hostile key
/// file chooses the cipher, the IV and the ciphertext length, and the
/// hand-rolled feedback loop this replaced was panic-free only because
/// its caller happened never to pass an 8-byte-block cipher or an empty
/// IV. `new_from_slices` turns every such size mismatch into an `Err`,
/// and a partial trailing block is the library's problem rather than
/// ours. A panic here would not be a failed import: `panic = abort`
/// semantics in wasm tear the whole module down, side panel and
/// unlocked keys included.
///
/// The AES-only restriction stays, but it is now a policy choice about
/// what we accept from an untrusted key file rather than the thing
/// keeping the code memory-safe.
fn cfb_decrypt(
    sym: SymmetricAlgorithm,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    use cfb_mode::cipher::{AsyncStreamCipher, BlockCipher, BlockEncryptMut, KeyIvInit};

    fn run<C>(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String>
    where
        C: BlockEncryptMut + BlockCipher + aes::cipher::KeyInit,
    {
        let mut buf = ciphertext.to_vec();
        cfb_mode::Decryptor::<C>::new_from_slices(key, iv)
            .map_err(|_| {
                "This key's protection header is malformed (bad key or IV size)".to_string()
            })?
            .decrypt(&mut buf);
        Ok(buf)
    }

    match sym {
        SymmetricAlgorithm::AES128 => run::<aes::Aes128>(key, iv, ciphertext),
        SymmetricAlgorithm::AES192 => run::<aes::Aes192>(key, iv, ciphertext),
        SymmetricAlgorithm::AES256 => run::<aes::Aes256>(key, iv, ciphertext),
        _ => Err(format!(
            "This key is protected with an unsupported legacy cipher ({sym}). \
             Re-export it with: gpg --export-secret-keys --s2k-cipher-algo AES256"
        )),
    }
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
        decrypt_key_secret(primary_key, &password)?
    } else {
        primary_key
    };

    let mut packets: Vec<openpgp::Packet> = vec![primary.role_into_primary().into()];
    for subkey in cert.keys().subkeys().secret() {
        let key = subkey.key().clone();
        let decrypted = if key.secret().is_encrypted() {
            decrypt_key_secret(key, &password)?
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

/// Derive a 32-byte AES key from a password using Argon2id (JS entry point).
///
/// Parameters are chosen for browser use: 64MB memory, 3 iterations,
/// parallelism 1 (WASM is single-threaded). This makes GPU brute-force
/// impractical for passwords with reasonable entropy.
///
/// Owned, not `&[u8]`: with a borrowed param the wasm-bindgen glue frees
/// its marshalled copy of the password without clearing it, leaving the
/// plaintext in linear memory. Owning it lets Zeroizing scrub on exit.
/// See SECURITY.md §8.4 and T-UNLOCK-PARAM-NOT-OWNED.
///
/// The derivation itself lives in `argon2_derive`, which stays borrowing:
/// its in-crate callers (`protected`, `crx`) already hold the password in a
/// `Zeroizing` of their own, and taking it by value there would add an
/// un-scrubbed copy rather than remove one. Ownership is required at the
/// ABI boundary, which is exactly here.
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

/// In-crate Argon2id derivation. Not a wasm export -- see
/// `argon2_derive_owned` for the JS entry point and why the split exists.
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
    password: Vec<u8>,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<u32, String> {
    // Owned, not `&[u8]`: with a borrowed param the wasm-bindgen glue frees
    // its marshalled copy of the password without clearing it, leaving the
    // plaintext in linear memory. Owning it lets Zeroizing scrub on exit.
    // See SECURITY.md §8.4 and T-UNLOCK-PARAM-NOT-OWNED.
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

/// Unlock a passkey-protected key entirely in WASM. Returns a key handle.
///
/// Flow: HKDF(prfOutput, storedSecret) -> AES key -> AES-GCM decrypt -> parse Cert -> store
/// JS calls WebAuthn to get the PRF output, passes it here as raw bytes.
/// The decrypted private key never enters the JS heap.
#[wasm_bindgen(js_name = "unlockWithPrf")]
pub fn unlock_with_prf(
    ciphertext: &[u8],
    iv: &[u8],
    prf_output: Vec<u8>,
    stored_secret: Vec<u8>,
    key_id: &str,
) -> Result<u32, String> {
    // Owned + Zeroizing for the same reason as unlock_with_password, and
    // matching generate_protected_with_prf, which already takes both owned.
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

// =====================================================================
// Shared helpers
// =====================================================================

/// AAD prefixes for per-key protection (also used by the JS side in
/// `encrypt-private-key.ts` -- keep in sync). Distinct from the
/// `gpg-tools:crx-*` prefixes in `crx.rs`, so an OpenPGP blob and a CRX blob
/// can never be opened as each other.
const PASSWORD_AAD_PREFIX: &str = "gpg-tools:password:";
const PASSKEY_AAD_PREFIX: &str = "gpg-tools:passkey:";
/// HKDF info string for the PRF-derived AES key protecting an OpenPGP cert.
/// Distinct from `crx.rs`'s `CRX_PRF_HKDF_INFO`: the same authenticator PRF
/// output must never derive the same key for two key types.
const PASSKEY_HKDF_INFO: &[u8] = b"gpg-tools-prf-v1";

/// Parse a decrypted private key, zeroize the plaintext, and store it.
///
/// The plaintext arrives in `Zeroizing` from `protected::open_*` and is
/// dropped (wiped) as soon as the cert is parsed, before it reaches the
/// store -- so the serialized copy exists in only one place at a time.
fn parse_and_store_private_key(plaintext: Zeroizing<Vec<u8>>) -> Result<u32, String> {
    let result = openpgp::Cert::from_bytes(&plaintext).str_err();
    drop(plaintext);
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
    rng::fill(&mut key)?;
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

// ── Per-store envelope (v1): domain-separated key AND AAD ───────────
//
// Every store sealed under the master session (keyring, contacts,
// settings, CRX keys, each history segment) gets its OWN AES key and its
// OWN AAD, both derived from a caller-supplied `domain` string. The JS
// side always passes the chrome.storage key the blob lives under
// (`pgp_keyring`, `pgp_public_contacts`, `pgp_settings`, `pgp_crx_keys`,
// `pgp_history_seg_<n>`), so a sealed blob is bound to the exact slot it
// was written to.
//
// Why this exists: the legacy scheme below (`encrypt_contacts` /
// `decrypt_contacts`) sealed EVERY store under the same key and the same
// fixed `CONTACTS_AAD`, so nothing in the sealed data named the store or
// the segment. Anyone able to write chrome.storage -- with no knowledge
// of the vault key -- could replay one store's blob into another slot and
// the AEAD would accept it. Binding the domain into both the subkey and
// the AAD makes any such move fail the tag check.
//
// Two independent bindings on purpose: the AAD alone would be enough for
// a correct AEAD, but deriving a distinct key means even a future bug
// that drops or mismatches the AAD cannot cross a domain boundary.
const STORE_SUBKEY_INFO_PREFIX: &str = "gpg-tools:store-subkey:v1:";
const STORE_AAD_PREFIX: &str = "gpg-tools:store:v1:";

/// HKDF-Expand the contacts session key into a 32-byte subkey unique to
/// `domain`. The subkey is `Zeroizing`, so it is scrubbed when the
/// enclosing call returns.
///
/// NOTE on lifetimes: the subkey is derived FROM the contacts session
/// key, so it inherits that key's lifetime exactly -- this buys domain
/// separation, not an independent unlock window. See
/// `T-HISTORY-KEY-COUPLING`.
fn derive_store_subkey(domain: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    if domain.is_empty() {
        return Err("Store domain must not be empty".to_string());
    }
    let info = format!("{STORE_SUBKEY_INFO_PREFIX}{domain}");
    with_contacts_key(|key| {
        // The session key is already a 32-byte HKDF output, so Extract is
        // a formality; keep it for a conventional HKDF construction.
        let hk = Hkdf::<Sha256>::new(None, key);
        let mut subkey = Zeroizing::new(vec![0u8; 32]);
        hk.expand(info.as_bytes(), subkey.as_mut_slice())
            .map_err(|e| format!("HKDF failed: {e}"))?;
        Ok(subkey)
    })?
}

/// Seal `plaintext` for `domain`. Returns `[12-byte IV][ciphertext]`.
/// Plaintext is taken by value and wrapped in `Zeroizing` so the copy
/// wasm-bindgen marshalled in is scrubbed at function exit -- up to
/// 64 KB of user message content per history segment write.
#[wasm_bindgen(js_name = "encryptStore")]
pub fn encrypt_store(domain: &str, plaintext: Vec<u8>) -> Result<Vec<u8>, String> {
    let plaintext = Zeroizing::new(plaintext);
    let subkey = derive_store_subkey(domain)?;
    let aad = format!("{STORE_AAD_PREFIX}{domain}");
    aes_gcm_encrypt(&subkey, &plaintext, aad.as_bytes())
}

/// Open a blob sealed by `encrypt_store` for the SAME `domain`. Any other
/// domain fails the tag check.
#[wasm_bindgen(js_name = "decryptStore")]
pub fn decrypt_store(domain: &str, ciphertext: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    let subkey = derive_store_subkey(domain)?;
    let aad = format!("{STORE_AAD_PREFIX}{domain}");
    aes_gcm_decrypt(&subkey, iv, ciphertext, aad.as_bytes())
}

// ── Legacy (pre-v1) shared envelope ─────────────────────────────────
//
// The scheme every store used before `encrypt_store`: the raw contacts
// session key with the shared `CONTACTS_AAD`. RETAINED, not dead:
//   - `decrypt_contacts` is the migration read path. Blobs written by
//     shipped versions are still on real users' disks and must keep
//     opening; the JS side (`lib/storage/envelope.ts`) tries the
//     domain-bound scheme first and falls back to this.
//   - `encrypt_contacts` is how the tests (here and in
//     `lib/storage/*.test.ts`, via the same packing contract) synthesise
//     a legacy blob to prove that fallback works. Production code no
//     longer writes this format.
// Do NOT reintroduce either as a production write path.

/// Encrypt under the legacy shared envelope. See the note above.
/// Plaintext is owned + `Zeroizing` for the same reason as
/// `encrypt_store`.
#[wasm_bindgen(js_name = "encryptContacts")]
pub fn encrypt_contacts(plaintext: Vec<u8>) -> Result<Vec<u8>, String> {
    let plaintext = Zeroizing::new(plaintext);
    with_contacts_key(|key| aes_gcm_encrypt(key, &plaintext, CONTACTS_AAD))?
}

/// Decrypt a legacy shared-envelope blob. See the note above.
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
    password: Vec<u8>,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    // Owned, not `&[u8]`: with a borrowed param the wasm-bindgen glue frees
    // its marshalled copy of the password without clearing it, leaving the
    // plaintext in linear memory. Owning it lets Zeroizing scrub on exit.
    // This is the onboarding path, so the secret here is the master password
    // that gates the whole vault. See SECURITY.md §8.4 and
    // T-UNLOCK-PARAM-NOT-OWNED.
    let password = Zeroizing::new(password);
    let mut key =
        derive_contacts_key_from_password(&password, salt, memory_kib, iterations, parallelism)?;
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
    password: Vec<u8>,
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<bool, String> {
    // Owned, not `&[u8]`: with a borrowed param the wasm-bindgen glue frees
    // its marshalled copy of the password without clearing it, leaving the
    // plaintext in linear memory. Owning it lets Zeroizing scrub on exit --
    // including on the wrong-password branch, which is the one an attacker
    // gets to trigger repeatedly. This is the master-unlock path. See
    // SECURITY.md §8.4 and T-UNLOCK-PARAM-NOT-OWNED.
    let password = Zeroizing::new(password);
    let mut key =
        derive_contacts_key_from_password(&password, salt, memory_kib, iterations, parallelism)?;
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

/// The at-rest key-protection envelope (Argon2id / PRF -> AES-256-GCM, the
/// handle store, and the packed meta+blob wire format), shared by every key
/// type the vault holds. See the module header for what is parameterised and
/// why it must stay that way.
mod protected;

/// CRX (Chrome extension) signing & verification. Reuses this module's
/// vault/unlock/zeroize machinery for an RSA-2048 signing key; see the
/// module header for why CRX3 is not OpenPGP.
mod crx;

/// age encryption to imported SSH keys (`ssh-ed25519`, `ssh-rsa`). Reuses
/// this module's vault/unlock/zeroize machinery for the identity; see the
/// module header for why `ssh-key` is needed and where age's own randomness
/// stays out of reach.
mod age;

/// The crate's CSPRNG: a ChaCha20 stream seeded once from
/// `crypto.getRandomValues`. See the module header for what it does and
/// does not buy against T-ENTROPY-POISON.
mod rng;

#[cfg(test)]
mod tests;
