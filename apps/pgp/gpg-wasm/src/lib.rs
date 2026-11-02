//! # GPG Tools - Sequoia-PGP WASM Module
//!
//! The WASM/Rust trust boundary: every cryptographic operation lives in this
//! crate. Auditors start at `apps/pgp/SECURITY.md`. JS reaches it only through
//! `lib/pgp/wasm-public.ts` (no secrets) and `lib/pgp/wasm-secrets.ts` (secrets,
//! per-function zeroize contracts).
//!
//! Invariants:
//! - Private keys live in WASM memory (`KEY_STORE`, zeroized on drop); JS holds
//!   only integer handles.
//! - `KEY_STORE` is populated **only** by the unlock paths (`unlockWithPassword`,
//!   `unlockWithPrf`). Generate/import hold the plaintext cert for one call and
//!   return a protected blob; it never enters the store.
//! - Sign/encrypt/decrypt rematerialize a transient `Cert` per call.
//! - Armored secret material crosses to JS only via `getKeyArmored` (destructive
//!   export UI).
//! - Verification never aborts: every signature is classified and a bad one
//!   anywhere yields "invalid", so the UI withholds the plaintext.
//! - Constant-time caveat: WASM needs `allow-variable-time-crypto`; browser
//!   sandboxing is the mitigation.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;
use std::io::Write;
use std::time::{Duration, SystemTime};

/// Zeroize-on-free global allocator.
///
/// Freed WASM memory is not cleared, so plaintext freed across the
/// wasm-bindgen ABI (where `Drop`/`Zeroizing` can't reach, e.g. a returned
/// `Vec<u8>` freed by `__wbindgen_free`) would linger. Wiping every block on
/// `dealloc` covers that without relying on each call site. `realloc` stays
/// the trait default (alloc + copy + dealloc) so a moved block is wiped too.
struct ZeroizeOnFree;

unsafe impl GlobalAlloc for ZeroizeOnFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        #[cfg(test)]
        alloc_meter::track(layout.size() as isize);
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        #[cfg(test)]
        alloc_meter::track(layout.size() as isize);
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        #[cfg(test)]
        alloc_meter::track(-(layout.size() as isize));
        std::ptr::write_bytes(ptr, 0, layout.size());
        System.dealloc(ptr, layout);
    }
}

/// Test-only per-thread peak-live-heap meter, to bound Sequoia's read-ahead.
/// Const-initialised cells with no destructor: touching them must not
/// allocate (that would recurse into the allocator).
#[cfg(test)]
mod alloc_meter {
    use std::cell::Cell;

    thread_local! {
        static LIVE: Cell<isize> = const { Cell::new(0) };
        static PEAK: Cell<isize> = const { Cell::new(0) };
    }

    pub(crate) fn track(delta: isize) {
        let _ = LIVE.try_with(|live| {
            let now = live.get() + delta;
            live.set(now);
            let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
        });
    }

    /// Run `f`, returning its result and the most it held live at once
    /// above what was live when it started.
    pub(crate) fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
        let base = LIVE.with(Cell::get);
        PEAK.with(|peak| peak.set(base));
        let out = f();
        (out, (PEAK.with(Cell::get) - base).max(0) as usize)
    }
}

#[global_allocator]
static GLOBAL: ZeroizeOnFree = ZeroizeOnFree;

use aes_gcm::aead::{Aead, Nonce, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
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

/// The policy gating every key operation: `StandardPolicy` relaxed only to
/// accept SHA-1 in *binding* signatures, which need second-preimage
/// resistance (still intact) rather than collision resistance (broken).
/// Data signatures and certifications stay on the hardened default. Keys
/// that rely on it get a `securityWarning` (see `strict_policy`).
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

/// Sequoia's hardened defaults. Only used to *detect* weak crypto for a
/// warning -- never to gate an operation.
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

// ---- Types (serialized to/from JS via JSON) ----

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
    /// `policy()` accepts an alive, non-revoked encryption-capable key.
    #[serde(rename = "usableForEncryption")]
    pub usable_for_encryption: bool,
    /// `policy()` accepts an alive, non-revoked signing-capable key.
    #[serde(rename = "usableForSigning")]
    pub usable_for_signing: bool,
    /// Why the cert is unusable; set only when neither capability is usable
    /// because of a policy rejection.
    #[serde(rename = "policyError", skip_serializing_if = "Option::is_none")]
    pub policy_error: Option<String>,
    /// Non-blocking: usable only thanks to the relaxed policy (e.g. SHA-1
    /// binding). Mutually exclusive with `policy_error`.
    #[serde(rename = "securityWarning", skip_serializing_if = "Option::is_none")]
    pub security_warning: Option<String>,
    /// Verified whole-cert revocation. Still stored (so the revocation reaches
    /// it) but never encrypted to.
    pub revoked: bool,
    /// A User ID mixes lookalike alphabets; also explained in `security_warning`.
    pub lookalike: bool,
}

/// One row of `parse_key_details` (primary first): a component key's
/// capabilities and lifecycle status.
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
    /// "active" | "expired" | "revoked" | "invalid". "invalid" = binding fails
    /// `policy()`; capability flags are then all-false.
    pub status: String,
    #[serde(rename = "revocationReason", skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<String>,
    #[serde(rename = "policyError", skip_serializing_if = "Option::is_none")]
    pub policy_error: Option<String>,
}

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

#[derive(Serialize)]
pub struct VerifyResult {
    pub text: String,
    #[serde(flatten)]
    signatures: SignatureReport,
}

#[derive(Serialize)]
struct SignatureReport {
    #[serde(rename = "signatureValid")]
    signature_valid: bool,
    /// "valid" | "invalid" | "unknown_key" | "unsigned".
    #[serde(rename = "signatureStatus")]
    signature_status: &'static str,
    #[serde(rename = "signerKeyId")]
    signer_key_id: Option<String>,
    /// Signer-chosen creation time (ms since epoch); Sequoia judges the key as
    /// of this moment, so it is shown, never trusted.
    #[serde(rename = "signedAt")]
    signed_at: Option<f64>,
    /// Signing key is alive and unrevoked TODAY -- an expired or superseded key
    /// still verifies a signature dated inside its old validity.
    #[serde(rename = "signerKeyCurrent")]
    signer_key_current: bool,
    /// Further good signers beyond `signer_key_id`, by fingerprint.
    #[serde(rename = "otherSignerKeyIds")]
    other_signer_key_ids: Vec<String>,
    /// Signatures from keys we don't hold, alongside a good one.
    #[serde(rename = "unverifiedSignatures")]
    unverified_signatures: u32,
    /// Intended-recipient fingerprints. Sequoia enforces these only when
    /// decrypting with a key; for password decrypt or verify the UI checks them.
    #[serde(rename = "intendedRecipients")]
    intended_recipients: Vec<String>,
}

impl SignatureReport {
    fn unsigned() -> Self {
        Self::with_status("unsigned", None)
    }

    fn with_status(status: &'static str, signer_key_id: Option<String>) -> Self {
        SignatureReport {
            signature_valid: status == "valid",
            signature_status: status,
            signer_key_id,
            signed_at: None,
            signer_key_current: false,
            other_signer_key_ids: Vec::new(),
            unverified_signatures: 0,
            intended_recipients: Vec::new(),
        }
    }
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

// ---- Internal helpers ----

fn system_time_to_millis(t: SystemTime) -> f64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as f64
}

fn extract_key_info(cert: &openpgp::Cert, is_private: bool) -> KeyInfo {
    let key_id = cert.fingerprint().to_hex();
    let user_ids = bound_user_ids(cert);
    let algorithm = cert.primary_key().key().pk_algo().to_string();
    let created_at = system_time_to_millis(cert.primary_key().key().creation_time());

    let (expires_at, usable_for_encryption, usable_for_signing, policy_error, security_warning) =
        match cert.with_policy(policy(), None) {
            Ok(vc) => {
                let expires_at = vc.primary_key().key_expiration_time().map(system_time_to_millis);
                let (has_enc, has_sig) = usable_keys(&vc);
                let policy_error = if !has_enc && !has_sig {
                    // Revocation is the one cause the user can't fix by waiting.
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
                // Usable only via the relaxed policy? Name the key that leans on it.
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

    let revoked = cert
        .with_policy(policy(), None)
        .is_ok_and(|vc| matches!(vc.revocation_status(), RevocationStatus::Revoked(_)));
    let lookalike = user_ids.iter().any(|u| mixes_scripts(u));
    // Say both when both apply: neither warning may hide the other.
    let security_warning = match (lookalike, security_warning) {
        (false, w) => w,
        (true, w) => Some(
            [
                Some(
                    "This key's name or email mixes letters from different \
                     alphabets (for example Latin and Cyrillic) in one word, a \
                     common way to imitate someone else's name. Check the \
                     fingerprint with its owner."
                        .to_string(),
                ),
                w,
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" "),
        ),
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
        revoked,
        lookalike,
    }
}

/// User IDs the owner actually bound (self-signed under policy, not
/// revoked), primary first, sanitized. `Cert::userids()` also yields
/// unbound UIDs anyone can append, and the UI names a contact by its first.
fn bound_user_ids(cert: &openpgp::Cert) -> Vec<String> {
    // Attacker-controlled: strip control/bidi/invisible chars (a U+202E in a
    // UID reverses the displayed email) and cap length.
    let clean =
        |u: &openpgp::packet::UserID| sanitize_untrusted(&String::from_utf8_lossy(u.value()), 300);

    let bound: Vec<openpgp::packet::UserID> = match cert.with_policy(policy(), None) {
        Ok(vc) => {
            let primary = vc.primary_userid().ok().map(|u| u.userid().clone());
            let mut ids: Vec<_> = vc
                .userids()
                .filter(|u| !matches!(u.revocation_status(), RevocationStatus::Revoked(_)))
                .map(|u| u.userid().clone())
                .collect();
            if let Some(i) = primary.and_then(|p| ids.iter().position(|u| *u == p)) {
                let p = ids.remove(i);
                ids.insert(0, p);
            }
            ids
        }
        Err(_) => Vec::new(),
    };
    if !bound.is_empty() {
        return bound.iter().map(clean).collect();
    }
    // No usable binding today: still only names its owner once self-signed.
    cert.userids()
        .filter(|u| u.self_signatures().next().is_some())
        .map(|u| clean(u.userid()))
        .collect()
}

/// A word whose letters mix scripts that imitate each other ("Аlice" with a
/// Cyrillic А). Judged per word, so a Cyrillic name with a Latin address is
/// fine; an email address is one word, so a mixed-script domain counts.
fn mixes_scripts(s: &str) -> bool {
    let script = |c: char| match c as u32 {
        0x41..=0x5a | 0x61..=0x7a | 0xc0..=0x24f | 0x1e00..=0x1eff => Some(0),
        0x370..=0x3ff | 0x1f00..=0x1fff => Some(1),
        0x400..=0x52f | 0x1c80..=0x1c8f | 0x2de0..=0x2dff | 0xa640..=0xa69f => Some(2),
        0x530..=0x58f => Some(3),
        // Letters that pass for Latin ones without being them: fullwidth,
        // letterlike and mathematical forms (Ａ, K Kelvin, 𝐀); IPA, phonetic
        // and extended Latin (ɑ, ᴀ); Cherokee and Lisu (Ꭺ, ꓮ).
        0xff21..=0xff3a | 0xff41..=0xff5a | 0x2100..=0x214f | 0x1d400..=0x1d7ff => Some(4),
        0x250..=0x2af | 0x1d00..=0x1dbf | 0xa720..=0xa7ff => Some(5),
        0x13a0..=0x13ff | 0xab70..=0xabbf | 0xa4d0..=0xa4ff => Some(6),
        _ => None,
    };
    s.split(|c: char| c.is_whitespace() || "<>()\"',;:".contains(c))
        .any(|word| {
            let mut seen = None;
            for k in word.chars().filter_map(script) {
                match seen {
                    None => seen = Some(k),
                    Some(prev) if prev != k => return true,
                    _ => {}
                }
            }
            false
        })
}

/// (encryption usable, signing usable) for a validated cert.
fn usable_keys(vc: &openpgp::cert::ValidCert) -> (bool, bool) {
    // A whole-cert revocation doesn't mark component keys revoked in Sequoia,
    // so without this a revoked cert would still report usable subkeys.
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

/// Warning for a cert usable under `policy()` but not `strict_policy()`.
/// The only difference is SHA-1 binding acceptance, so name which binding
/// leans on it. `None` when the hardened policy accepts everything we use.
fn security_warning(cert: &openpgp::Cert, has_enc: bool, has_sig: bool) -> Option<String> {
    // Hardened policy rejects the whole cert: the weak link is the primary binding.
    let (strict_enc, strict_sig) = match cert.with_policy(strict_policy(), None) {
        Ok(vc) => usable_keys(&vc),
        Err(_) => return Some(sha1_warning("primary self-signature", false)),
    };

    // Otherwise a subkey binding is the weak link; flag exactly what it affects.
    match (has_enc && !strict_enc, has_sig && !strict_sig) {
        (true, true) => Some(sha1_warning("encryption and signing subkeys", true)),
        (true, false) => Some(sha1_warning("encryption subkey", false)),
        (false, true) => Some(sha1_warning("signing subkey", false)),
        (false, false) => None,
    }
}

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

/// Turn a raw Sequoia policy rejection into something a non-cryptographer
/// can act on (most often a SHA-1 self-signature).
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
    // Pre-size (base64 ~1.4x + framing) so the private branch never reallocs
    // and leaves partial-secret copies behind.
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

/// Parse a JSON array of armored keys, skipping any that fail.
fn parse_armored_certs(json: &str) -> Result<Vec<openpgp::Cert>, String> {
    let armors: Vec<String> = serde_json::from_str(json).str_err()?;
    Ok(armors
        .iter()
        .filter_map(|a| openpgp::Cert::from_bytes(a.as_bytes()).ok())
        .collect())
}

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
fn aes_gcm_decrypt(
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
        .encrypt(&Nonce::<Aes256Gcm>::from(iv), Payload { msg: plaintext, aad })
        .map_err(|_| "Encryption failed".to_string());
    zeroize_cipher(&mut cipher);

    let ct = ciphertext?;
    let mut result = Vec::with_capacity(12 + ct.len());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ct);
    Ok(result)
}

// ---- Shared crypto operations ----

/// Encrypt to recipients (and/or a password), optionally signing.
fn encrypt_impl(
    plaintext: &[u8],
    recipient_keys_json: &str,
    signer_cert: Option<&openpgp::Cert>,
    // Already `Zeroizing`: the exports own and wrap it (where the wasm-bindgen
    // allocation lands and audit-invariants.mjs checks); moved, never copied.
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
        let before = recipient_keys.len();
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
        // EVERY recipient must contribute a key or the operation is refused: the
        // `.alive().revoked(false)` filters fail silently, producing a message the
        // expired key's owner (including self) cannot read. Whole-cert revocation
        // is checked separately because Sequoia doesn't propagate it per key.
        let cert_revoked = verified_revocation_reason(&vc.revocation_status());
        if cert_revoked.is_some() || recipient_keys.len() == before {
            return Err(unusable_recipient_reason(&vc, cert_revoked));
        }
    }

    // A message must be openable by SOMEONE: no recipients and no password
    // would "succeed" with an undecryptable message.
    if recipient_keys.is_empty() && password.is_none() {
        return Err("No recipients and no password: nothing could open this message".to_string());
    }

    let mut sink = Vec::new();
    let message = Armorer::new(Message::new(&mut sink)).build().str_err()?;

    let mut builder = Encryptor::for_recipients(message, recipient_keys)
        // PINNED, not inherited: a changing default would be an unreviewed cipher
        // change. The S2K can't be pinned via the stream API (see
        // `encrypt_with_password`).
        .symmetric_algo(SymmetricAlgorithm::AES256);
    if let Some(ref pw) = password {
        // ADDITIVE: an SKESK alongside the PKESKs; either opens the message.
        builder = builder.add_passwords(vec![openpgp::crypto::Password::from(
            pw.as_slice(),
        )]);
    }
    let encryptor = builder.build().str_err()?;

    let inner: Message = if let Some(cert) = signer_cert {
        let keypair = signing_keypair(cert)?;
        // Intended Recipient Fingerprints (RFC 9580 5.2.3.36): stops a recipient
        // re-encrypting the signed message to a third party where it would verify
        // as if addressed to them. Sequoia enforces the list on decrypt.
        let mut signer = Signer::new(encryptor, keypair).str_err()?;
        for recipient in &recipients {
            signer = signer.add_intended_recipient(recipient);
        }
        signer.build().str_err()?
    } else {
        encryptor
    };
    let mut literal = LiteralWriter::new(inner).build().str_err()?;
    literal.write_all(plaintext).str_err()?;
    literal.finalize().str_err()?;

    Ok(sink)
}

/// User-facing reason a recipient contributed no encryption key, naming it
/// by its (sanitized, attacker-controlled) first User ID, in actionable
/// order: revoked, expired, no encryption subkey.
fn unusable_recipient_reason(
    vc: &openpgp::cert::ValidCert,
    cert_revoked: Option<String>,
) -> String {
    let label = vc
        .userids()
        .next()
        .map(|u| sanitize_untrusted(&String::from_utf8_lossy(u.userid().value()), 120))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| vc.fingerprint().to_hex());

    if let Some(reason) = cert_revoked {
        return coded(
            ErrorCode::KeyRevoked,
            &format!(
                "Can't encrypt to {label}: the key has been revoked by its owner ({reason}). \
                 Ask them for their current key."
            ),
        );
    }
    // Primary key past its expiry: nothing under it is alive.
    if vc.alive().is_err() {
        return coded(
            ErrorCode::KeyExpired,
            &format!("Can't encrypt to {label}: the key has expired. Ask them for a renewed key."),
        );
    }
    let any_encryption_capable = vc
        .keys()
        .for_transport_encryption()
        .chain(vc.keys().for_storage_encryption())
        .next()
        .is_some();
    if any_encryption_capable {
        // Live primary, but every encryption subkey is expired, revoked, or of
        // an algorithm this build can't encrypt with.
        return coded(
            ErrorCode::KeyExpired,
            &format!(
                "Can't encrypt to {label}: its encryption subkey has expired, been revoked, \
                 or uses an unsupported algorithm. Ask them for a renewed key."
            ),
        );
    }
    format!(
        "Can't encrypt to {label}: the key has no encryption subkey (it can only sign)."
    )
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

/// Best-effort issuer key id (hex), to name a signer whose key we lack.
fn issuer_hex(sig: &openpgp::packet::Signature) -> Option<String> {
    sig.get_issuers().into_iter().next().map(|kh| match kh {
        openpgp::KeyHandle::Fingerprint(fp) => fp.to_hex(),
        openpgp::KeyHandle::KeyID(kid) => kid.to_hex(),
    })
}

/// Is the good signature's key still alive and unrevoked now? Sequoia only
/// checked it as of the signer-chosen signature time.
fn signing_key_current(cert: &openpgp::Cert, key: &openpgp::Fingerprint) -> bool {
    let Ok(vc) = cert.with_policy(policy(), None) else {
        return false;
    };
    vc.alive().is_ok()
        && !matches!(vc.revocation_status(), RevocationStatus::Revoked(_))
        && vc
            .keys()
            .key_handle(key.clone())
            .alive()
            .revoked(false)
            .next()
            .is_some()
}

/// Classify a message's signatures WITHOUT ever failing: decryption and
/// verification are separate, so a message still decrypts when the signer
/// is unknown. "valid" | "invalid" (had the key, failed: tamper signal) |
/// "unknown_key" | "unsigned".
///
/// A bad signature anywhere makes the whole message "invalid", even next to
/// a good one (GnuPG reports BAD too). `UnboundKey` (key not valid at the
/// claimed time, e.g. backdated) is a forgery signal, not an unknown signer.
fn process_signatures(structure: MessageStructure) -> SignatureReport {
    let mut good: Vec<(String, Option<f64>, bool, Vec<String>)> = Vec::new();
    let mut missing: Vec<Option<String>> = Vec::new();
    let mut bad = false;

    for layer in structure {
        if let MessageLayer::SignatureGroup { results } = layer {
            for result in results {
                match result {
                    Ok(GoodChecksum { sig, ka }) => {
                        let fpr = ka.cert().fingerprint().to_hex();
                        if !good.iter().any(|(f, ..)| *f == fpr) {
                            good.push((
                                fpr,
                                sig.signature_creation_time().map(system_time_to_millis),
                                signing_key_current(ka.cert(), &ka.key().fingerprint()),
                                sig.intended_recipients().map(|f| f.to_hex()).collect(),
                            ));
                        }
                    }
                    // Signer's public key was not supplied -> cannot verify.
                    Err(VerificationError::MissingKey { sig }) => missing.push(issuer_hex(sig)),
                    Err(_) => bad = true,
                }
            }
        }
    }

    if bad {
        return SignatureReport::with_status("invalid", None);
    }
    let mut good = good.into_iter();
    match good.next() {
        Some((fpr, signed_at, current, intended)) => SignatureReport {
            signed_at,
            signer_key_current: current,
            other_signer_key_ids: good.map(|(f, ..)| f).collect(),
            unverified_signatures: missing.len() as u32,
            intended_recipients: intended,
            ..SignatureReport::with_status("valid", Some(fpr))
        },
        None => match missing.into_iter().next() {
            Some(issuer) => SignatureReport::with_status("unknown_key", issuer),
            None => SignatureReport::unsigned(),
        },
    }
}

// ---- Private key store (keys live in WASM linear memory, never in JS) ----

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

/// Test-only shims to mint a cert and a handle without a full
/// protect + unlock round trip (keys otherwise enter `KEY_STORE` only via unlock).
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


// ---- Output size caps ----

/// Absolute ceiling on a decrypted message: wasm32 can't address more than
/// 4 GiB. `u64` because 4 GiB overflows a wasm32 `usize` by one byte.
const MAX_DECRYPTED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Max decrypted/ciphertext ratio. A ratio, not a flat number, is what
/// separates a big file from a bomb: real files decrypt to ~their own size,
/// a measured decompression bomb is 754x.
const MAX_EXPANSION_RATIO: u64 = 4;

/// Flat allowance below which the ratio doesn't bind (small messages
/// legitimately exceed 4x once packet framing comes off).
const MIN_EXPANSION_ALLOWANCE: u64 = 64 * 1024 * 1024;

/// Ceiling on verified cleartext. Much tighter because `verify_message`
/// returns it JSON-escaped (6 bytes per NUL) in one `String` in a 32-bit
/// address space; 16 MiB is ~ten thousand pages.
const MAX_VERIFIED_BYTES: u64 = 16 * 1024 * 1024;

/// Ceiling on `verify_message` input (fits anything under
/// `MAX_VERIFIED_BYTES` once armored). Checked first, because framing walks
/// the input line by line before the output cap applies.
const MAX_SIGNED_INPUT_BYTES: usize = 24 * 1024 * 1024;

/// Ceiling on lines in a signed message: the framing check keeps one entry
/// per line, and 200 MB of newlines exhausted wasm memory.
const MAX_SIGNED_LINES: usize = 2_000_000;

/// Output ceiling for a ciphertext: generous, but tied to input size.
fn decrypt_limit(ciphertext_len: usize) -> u64 {
    (ciphertext_len as u64)
        .saturating_mul(MAX_EXPANSION_RATIO)
        .clamp(MIN_EXPANSION_ALLOWANCE, MAX_DECRYPTED_BYTES)
}

/// Error for a read past the engine ceiling, coded `TooLarge`. Callers that
/// wrap errors (`decrypt_with_password` -> "Wrong password") must let it
/// through by code, or a correct password on a big file reads as wrong.
const TOO_LARGE_TO_OPEN: &str = "This message is too large to open here.";

fn too_large_to_open() -> String {
    coded(ErrorCode::TooLarge, TOO_LARGE_TO_OPEN)
}

fn read_capped<R: std::io::Read>(reader: R, limit: u64) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    std::io::copy(&mut reader.take(limit + 1), &mut out).str_err()?;

    if out.len() as u64 > limit {
        out.zeroize();
        return Err(too_large_to_open());
    }
    Ok(out)
}

/// Error for a read stopped by the caller's `max_output` (unattended
/// auto-decrypt). Not a failure: JS recognises it by value
/// ([`output_cap_reached_message`]) and waits for the user's click.
const OUTPUT_CAP_REACHED: &str =
    "This message is too large to open automatically. Press the button to open it.";

/// The exact capped-read error, so JS matches by value rather than prose.
/// No secret.
#[wasm_bindgen(js_name = "outputCapReachedMessage")]
pub fn output_cap_reached_message() -> String {
    OUTPUT_CAP_REACHED.to_string()
}

/// [`read_capped`] plus the caller's tighter `max_output` (unattended runs):
/// reads at most one byte past it, wipes what it took, and returns
/// [`OUTPUT_CAP_REACHED`]. Sequoia's own read-ahead isn't bounded here, so
/// every entry point taking `max_output` also uses [`stream_buffer`].
fn read_within<R: std::io::Read>(
    reader: R,
    limit: u64,
    max_output: Option<u32>,
) -> Result<Vec<u8>, String> {
    let cap = match max_output.map(u64::from) {
        Some(cap) if cap < limit => cap,
        _ => return read_capped(reader, limit),
    };
    let mut out = Vec::new();
    std::io::copy(&mut reader.take(cap + 1), &mut out).str_err()?;
    if out.len() as u64 > cap {
        out.zeroize();
        return Err(OUTPUT_CAP_REACHED.into());
    }
    Ok(out)
}

/// Decryptor/Verifier `buffer_size` keeping Sequoia's read-ahead (default
/// 25 MiB, inflated, before we see a byte) inside `max_output`. `cap + 1`
/// still verifies an in-cap message before release. `None` keeps the default.
fn stream_buffer(max_output: Option<u32>, limit: u64) -> Option<usize> {
    match max_output.map(u64::from) {
        Some(cap) if cap < limit => Some(cap as usize + 1),
        _ => None,
    }
}

// ---- Sequoia verification/decryption helpers ----

struct DecryptHelper {
    decryption_cert: openpgp::Cert,
    verification_certs: Vec<openpgp::Cert>,
    signatures: SignatureReport,
    /// The message had an encryption layer -- see [`was_encrypted`].
    encrypted: bool,
}

/// Did the message actually have an encryption layer? Sequoia's `Decryptor`
/// also reads unencrypted signed/literal messages, so without this anything
/// Alice ever signed publicly "decrypts" as a private verified message from
/// her. This closes only the unencrypted variant; a re-encrypted forward is
/// caught (when present) by Intended Recipient Fingerprints -- T-SIG-FORWARDED.
fn was_encrypted(structure: &MessageStructure) -> bool {
    structure
        .iter()
        .any(|layer| matches!(layer, MessageLayer::Encryption { .. }))
}

/// Decrypt-path error for a message with no encryption layer. The UI checks
/// first (`messageEncryption`/`openUnencrypted`); this is the backstop.
const NOT_ENCRYPTED: &str =
    "This message is not encrypted. It may be signed, but it was readable on the way and anyone could have sent this copy.";

fn not_encrypted() -> String {
    coded(ErrorCode::NotEncrypted, NOT_ENCRYPTED)
}

/// Refuse, before any key or password is used, a message with no encrypted
/// container and no session-key packet.
fn refuse_unencrypted(ciphertext: &[u8]) -> Result<(), String> {
    match scan_session_packets(ciphertext)? {
        (false, false, Container::None) => Err(not_encrypted()),
        _ => Ok(()),
    }
}

impl VerificationHelper for DecryptHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(self.verification_certs.clone())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        // Signature classification must never abort decryption: status, not error.
        self.encrypted = was_encrypted(&structure);
        self.signatures = process_signatures(structure);
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
        // Expired and revoked subkeys are tried too: those tell OTHERS to stop
        // encrypting, they don't lock the owner out of old mail (GnuPG agrees).
        // Policy still applies.
        for pkesk in pkesks {
            for key in vc
                .keys()
                .secret()
                .for_transport_encryption()
                .chain(vc.keys().secret().for_storage_encryption())
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
        Err(anyhow::anyhow!(coded(ErrorCode::NoDecryptionKey, "No suitable decryption key found")))
    }
}

/// Opens a password-encrypted (`gpg -c`) message. Deliberately separate from
/// [`DecryptHelper`]: a message may carry SKESKs and PKESKs, and which one is
/// used must be the caller's explicit choice, never a silent fallback. This
/// ignores `pkesks`; `DecryptHelper` ignores `skesks`.
struct PasswordDecryptHelper {
    /// Sequoia `Password`: protected memory, zeroized on drop.
    password: openpgp::crypto::Password,
    verification_certs: Vec<openpgp::Cert>,
    signatures: SignatureReport,
    /// The message had an encryption layer -- see [`was_encrypted`].
    encrypted: bool,
}

impl VerificationHelper for PasswordDecryptHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(self.verification_certs.clone())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        // As on the key path, signature classification never aborts decryption.
        self.encrypted = was_encrypted(&structure);
        self.signatures = process_signatures(structure);
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
        // Try every SKESK (the format allows several). A v4 SKESK "decrypts" under
        // a WRONG password too (no integrity check) and fails later at the MDC, so
        // the entry point treats any parse failure as "password did not work".
        // v5/v6 SKESKs are AEAD and fail here; both end in the same message.
        for skesk in skesks {
            if let Ok((algo, session_key)) = skesk.decrypt(&self.password) {
                if decrypt(algo, &session_key) {
                    // No cert was involved: don't report a fingerprint that decrypted nothing.
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
    signatures: SignatureReport,
}

impl VerificationHelper for VerifyHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(self.certs.clone())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        self.signatures = process_signatures(structure);
        Ok(())
    }
}

// ---- Public WASM API (called from JavaScript via wasm-bindgen) ----

#[wasm_bindgen(js_name = "ping")]
pub fn ping() -> String {
    "gpg-wasm ok".to_string()
}

/// Parse an armored key -> JSON `KeyInfo`. Only the *first* cert; use
/// `parseKeys` for bundles.
#[wasm_bindgen(js_name = "parseKey")]
pub fn parse_key(armored: &str) -> Result<String, String> {
    let cert = openpgp::Cert::from_bytes(armored.as_bytes()).str_err()?;
    let is_private = cert.keys().secret().next().is_some();
    serde_json::to_string(&extract_key_info(&cert, is_private)).str_err()
}

/// Cap on `parse_key_details` rows: a crafted cert can carry thousands of
/// subkeys, each a `with_policy` evaluation and a DOM node. Excess is
/// dropped and flagged via `truncated`.
const MAX_DETAIL_ROWS: usize = 100;

/// Characters that change how a string displays without showing
/// themselves (inclusive ranges): every `Default_Ignorable_Code_Point` and
/// `Cf` character (Unicode 16), line/paragraph separators, and the visible
/// characters that draw as blank (BLANK below). Each lets two different
/// User IDs look identical. Spelled out rather than a dependency so it can
/// be audited; `lib/utils/lookalike.ts` mirrors it and `lookalike.test.ts`
/// reads this table to keep them equal. Dropping ZWJ/emoji selectors only
/// unjoins emoji, a cosmetic cost in a User ID.
const INVISIBLE_RANGES: &[(u32, u32)] = &[
    (0x00AD, 0x00AD),   // soft hyphen
    (0x034F, 0x034F),   // combining grapheme joiner
    (0x0600, 0x0605),   // Arabic number signs (Cf)
    (0x061C, 0x061C),   // Arabic letter mark
    (0x06DD, 0x06DD),   // Arabic end of ayah (Cf)
    (0x070F, 0x070F),   // Syriac abbreviation mark (Cf)
    (0x0890, 0x0891),   // Arabic pound/piastre marks above (Cf)
    (0x08E2, 0x08E2),   // Arabic disputed end of ayah (Cf)
    (0x115F, 0x1160),   // Hangul choseong/jungseong fillers
    (0x17B4, 0x17B5),   // Khmer inherent vowels
    (0x180B, 0x180F),   // Mongolian variation selectors, vowel separator
    (0x200B, 0x200F),   // zero-width space/non-joiner/joiner, LRM, RLM
    (0x2028, 0x202E),   // line/paragraph separators, bidi embeddings and overrides
    (0x2060, 0x206F),   // word joiner, invisible operators, isolates, deprecated controls
    (0x2800, 0x2800),   // BLANK: Braille pattern blank (So)
    (0x3164, 0x3164),   // Hangul filler
    (0xFE00, 0xFE0F),   // variation selectors
    (0xFEFF, 0xFEFF),   // zero-width no-break space (BOM)
    (0xFFA0, 0xFFA0),   // halfwidth Hangul filler
    (0xFFF0, 0xFFFB),   // unassigned ignorables, interlinear annotation controls
    (0xFFFC, 0xFFFC),   // BLANK: object replacement character (So)
    (0x110BD, 0x110BD), // Kaithi number sign (Cf)
    (0x110CD, 0x110CD), // Kaithi number sign above (Cf)
    (0x13430, 0x1343F), // Egyptian hieroglyph format controls (Cf)
    (0x1BCA0, 0x1BCA3), // shorthand format controls
    (0x1D159, 0x1D159), // BLANK: musical symbol null notehead (So)
    (0x1D173, 0x1D17A), // musical symbol format controls
    (0xE0000, 0xE0FFF), // tags, variation selectors supplement, reserved ignorables
];

fn is_invisible(c: char) -> bool {
    let c = c as u32;
    INVISIBLE_RANGES.iter().any(|&(lo, hi)| (lo..=hi).contains(&c))
}

/// Clean an attacker-controlled string before it reaches the UI: drop
/// control and `INVISIBLE_RANGES` characters, truncate to `max` chars.
fn sanitize_untrusted(s: &str, max: usize) -> String {
    let mut out = String::new();
    let cleaned = s.chars().filter(|&c| !c.is_control() && !is_invisible(c));
    for (i, c) in cleaned.enumerate() {
        if i == max {
            out.push('…');
            break;
        }
        out.push(c);
    }
    out
}

/// Reason from a *verified* revocation, else `None`. `CouldBe`
/// (unverifiable third-party sig) is deliberately not revoked (as sequoia/GnuPG).
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

/// Per-component-key breakdown -> JSON `{ keys: SubkeyDetail[], truncated }`,
/// primary first. Walks `cert.keys()` (not `ValidCert::keys()`) so
/// policy-rejected keys still get an "invalid" row: the view exists to show
/// dead weight, not hide it.
#[wasm_bindgen(js_name = "parseKeyDetails")]
pub fn parse_key_details(armored: &str) -> Result<String, String> {
    let cert = openpgp::Cert::from_bytes(armored.as_bytes()).str_err()?;
    let primary_fp = cert.fingerprint();

    // A subkey can't outlive its cert: a revoked or expired primary kills every
    // subkey even if its own binding looks clean.
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

/// One cert from a multi-cert blob, with its own re-armored form so callers
/// store/encrypt against exactly that cert.
#[derive(Serialize)]
struct ParsedCert {
    #[serde(rename = "keyInfo")]
    key_info: KeyInfo,
    armored: String,
}

/// Parse one *or more* concatenated certs. Some publishers ship yearly
/// rotations in one `.asc`; `Cert::from_bytes` sees only the first (often
/// expired) cert, and storing the whole blob would encrypt to the dead one.
#[wasm_bindgen(js_name = "parseKeys")]
pub fn parse_keys(armored: &str) -> Result<String, String> {
    let parser = CertParser::from_bytes(armored.as_bytes()).str_err()?;
    let mut out = Vec::new();
    for cert in parser {
        let cert = cert.str_err()?;
        let is_private = cert.keys().secret().next().is_some();
        let cert = if is_private { cert } else { strip_third_party(cert).str_err()? };
        let key_info = extract_key_info(&cert, is_private);
        let armored = armor_cert(&cert, is_private)?;
        out.push(ParsedCert { key_info, armored });
    }
    if out.is_empty() {
        return Err(coded(ErrorCode::NotPgpData, "No OpenPGP certificate found"));
    }
    serde_json::to_string(&out).str_err()
}

/// Drop third-party certifications (no web of trust here; flooded certs
/// carry tens of thousands, re-parsed on every verify). Kept: signatures by
/// keys the owner actually BOUND, revocations by a designated revoker, and
/// issuer-less ones (Sequoia handles those). Non-verifying ones are dropped.
fn strip_third_party(cert: openpgp::Cert) -> openpgp::Result<openpgp::Cert> {
    use openpgp::types::SignatureType;
    use openpgp::Packet;

    let own: Vec<openpgp::KeyHandle> = match cert.with_policy(policy(), None) {
        Ok(vc) => vc.keys().map(|k| k.key().key_handle()).collect(),
        Err(_) => vec![cert.primary_key().key().key_handle()],
    };
    let revokers: Vec<openpgp::KeyHandle> = cert
        .revocation_keys(policy())
        .map(|rk| rk.revoker().1.clone().into())
        .collect();
    // A set: a hostile key file can carry thousands of bad signatures, and a
    // list lookup per packet made this quadratic.
    #[allow(clippy::mutable_key_type)] // Signature's caches never change its Eq/Hash.
    let bad: std::collections::HashSet<openpgp::packet::Signature> =
        cert.bad_signatures().cloned().collect();

    let packets: Vec<Packet> = cert
        .into_packets()
        .filter(|p| match p {
            Packet::Signature(sig) => {
                if bad.contains(sig) {
                    return false;
                }
                let issuers = sig.get_issuers();
                let by = |keys: &[openpgp::KeyHandle]| {
                    issuers.iter().any(|i| keys.iter().any(|k| k.aliases(i)))
                };
                issuers.is_empty()
                    || by(&own)
                    || (sig.typ() == SignatureType::KeyRevocation && by(&revokers))
            }
            _ => true,
        })
        .collect();
    openpgp::Cert::from_packets(packets.into_iter())
}

/// Merge an imported copy into the stored cert, so an import can only ADD
/// what the owner signed (revocations, subkeys, expiry), never roll a
/// contact back. `incoming` may be a bare revocation certificate; Sequoia
/// checks its signature on insert, so a forged one is ignored. Returns the
/// merged public cert, armored, third-party certifications stripped.
#[wasm_bindgen(js_name = "mergePublicKey")]
pub fn merge_public_key(stored_armored: &str, incoming_armored: &str) -> Result<String, String> {
    let stored = openpgp::Cert::from_bytes(stored_armored.as_bytes()).str_err()?;
    let merged = match openpgp::Cert::from_bytes(incoming_armored.as_bytes()) {
        Ok(incoming) => {
            if incoming.fingerprint() != stored.fingerprint() {
                return Err("That key is a different key from the stored contact".into());
            }
            stored.merge_public(incoming).str_err()?
        }
        Err(_) => {
            let sigs = revocation_signatures(incoming_armored)?;
            stored.insert_packets(sigs).str_err()?.0
        }
    };
    armor_cert(&strip_third_party(merged.strip_secret_key_material()).str_err()?, false)
}

/// The key revocations in a bare revocation certificate.
fn revocation_signatures(armored: &str) -> Result<Vec<openpgp::packet::Signature>, String> {
    use openpgp::types::SignatureType;
    use openpgp::Packet;

    let pile = openpgp::PacketPile::from_bytes(armored.as_bytes()).str_err()?;
    let sigs: Vec<_> = pile
        .into_children()
        .filter_map(|p| match p {
            Packet::Signature(sig) if sig.typ() == SignatureType::KeyRevocation => Some(sig),
            _ => None,
        })
        .collect();
    if sigs.is_empty() {
        return Err(coded(ErrorCode::NotPgpData, "No OpenPGP certificate found"));
    }
    Ok(sigs)
}

/// Fingerprints / key IDs a bare revocation certificate names as issuer, to
/// find the contact it revokes. Errs on anything else.
#[wasm_bindgen(js_name = "revocationIssuers")]
pub fn revocation_issuers(armored: &str) -> Result<String, String> {
    let issuers: Vec<String> = revocation_signatures(armored)?
        .iter()
        .flat_map(|sig| sig.get_issuers())
        .map(|kh| kh.to_hex())
        .collect();
    serde_json::to_string(&issuers).str_err()
}

/// Build a new cert + its armored revocation cert from `GenerateKeyOptions` JSON.
fn build_cert_from_options(
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
    // Optional and OWNED bytes, like `decrypt_with_password`
    // (T-SYMMETRIC-ENCRYPT-PASSWORD). The S2K is deliberately Sequoia's default:
    // iterated SHA-256 at 0x3e00000, the largest count the format can express.
    password: Option<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    // Wrapped before anything can return, so every path scrubs the copy.
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

const CLEARTEXT_BEGIN: &str = "-----BEGIN PGP SIGNED MESSAGE-----";
const CLEARTEXT_SIG_BEGIN: &str = "-----BEGIN PGP SIGNATURE-----";
const CLEARTEXT_SIG_END: &str = "-----END PGP SIGNATURE-----";
const MESSAGE_BEGIN: &str = "-----BEGIN PGP MESSAGE-----";
const MESSAGE_END: &str = "-----END PGP MESSAGE-----";

const OUTSIDE_SIGNED: &str =
    "This message has text outside the signed part, which the signature does not cover";

fn outside_signed() -> String {
    coded(ErrorCode::TextOutsideSignature, OUTSIDE_SIGNED)
}

/// What `check_signed_framing` found: for cleartext, the body as shown
/// (dash-escaping undone), to compare with what Sequoia verified.
enum SignedFraming {
    Cleartext(String),
    Inline,
}

fn too_large_to_verify() -> String {
    coded(
        ErrorCode::TooLarge,
        &format!(
            "This signed message is too large to verify here (limit {} MiB).",
            MAX_SIGNED_INPUT_BYTES / (1024 * 1024),
        ),
    )
}

/// Refuse a signed message that shows the user anything the signature
/// doesn't cover. Sequoia tolerates text around the block, prose in armor
/// headers, a whitespace quote prefix -- and the user reads the paste, not
/// the hash. So rather than predict its tolerances, accept one strict shape
/// (BEGIN at column 0, real `Hash:` names, closed header set, base64, END
/// last, only blank lines around); `check_cleartext_body` then requires the
/// shown body to equal the verified text.
fn check_signed_framing(signed_message: &str) -> Result<SignedFraming, String> {
    const HASHES: &[&str] = &[
        "MD5", "SHA1", "RIPEMD160", "SHA224", "SHA256", "SHA384", "SHA512", "SHA3-256",
        "SHA3-512",
    ];

    if !signed_message.contains(CLEARTEXT_BEGIN) && !signed_message.contains(MESSAGE_BEGIN) {
        // No block at all is a different mistake from text around one.
        return Err(coded(ErrorCode::NotPgpData, "No armored data found"));
    }

    // Line breaks other readers honour but `\n`-splitting wouldn't could hide a
    // line from the checks below.
    let msg = signed_message;
    if msg.bytes().filter(|&b| b == b'\n').count() > MAX_SIGNED_LINES {
        return Err("This signed message has too many lines to verify here.".into());
    }
    if msg.contains(['\u{2028}', '\u{2029}', '\u{85}', '\u{b}', '\u{c}']) {
        return Err(outside_signed());
    }
    let mut lines: Vec<&str> = Vec::new();
    for line in msg.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.contains('\r') {
            return Err(outside_signed());
        }
        lines.push(line);
    }
    let blank = |l: &&str| l.trim().is_empty();
    let first = lines.iter().position(|l| !blank(l)).unwrap_or(lines.len());
    let last = lines.iter().rposition(|l| !blank(l)).map_or(first, |i| i + 1);
    let lines = &lines[first..last];

    // Structural lines may carry trailing spaces, never leading ones.
    let tidy = |l: &str| l.trim_end_matches([' ', '\t']).to_owned();
    let hash_ok = |l: &str| {
        l.strip_prefix("Hash: ")
            .is_some_and(|v| v.split(',').all(|h| HASHES.contains(&h.trim())))
    };
    // Armor header values are unsigned text. `Charset` must be one token;
    // `Version`/`Comment` stay free (tool names, URLs) -- the UI shows the
    // signed text apart from the paste for exactly this.
    let header_ok = |l: &str| {
        let printable = |v: &str| v.chars().all(|c| c.is_ascii_graphic() || c == ' ');
        let token = |v: &str| {
            !v.is_empty()
                && v.len() <= 40
                && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
        };
        l.strip_prefix("Charset: ")
            .map(token)
            .or_else(|| l.strip_prefix("Version: ").map(printable))
            .or_else(|| l.strip_prefix("Comment: ").map(printable))
            .unwrap_or(false)
    };
    let base64_ok = |l: &str| {
        !l.is_empty()
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    };
    // BEGIN line, optional armor headers, blank line, base64, END last.
    let armored_ok = |rest: &[&str], end: &str| {
        let Some((last, body)) = rest.split_last() else { return false };
        let n = body.iter().take_while(|l| header_ok(&tidy(l))).count();
        let body = &body[n..];
        let body = match body.split_first() {
            Some((sep, rest)) if tidy(sep).is_empty() => rest,
            _ if n == 0 => body,
            _ => return false,
        };
        tidy(last) == end && !body.is_empty() && body.iter().all(|l| base64_ok(&tidy(l)))
    };

    match lines.split_first() {
        Some((begin, rest)) if tidy(begin) == MESSAGE_BEGIN => {
            if armored_ok(rest, MESSAGE_END) {
                Ok(SignedFraming::Inline)
            } else {
                Err(outside_signed())
            }
        }
        Some((begin, rest)) if tidy(begin) == CLEARTEXT_BEGIN => {
            let n = rest.iter().take_while(|l| hash_ok(&tidy(l))).count();
            let Some((sep, rest)) = rest[n..].split_first() else {
                return Err(outside_signed());
            };
            let Some(sig) = rest.iter().position(|l| tidy(l) == CLEARTEXT_SIG_BEGIN) else {
                return Err(outside_signed());
            };
            if !tidy(sep).is_empty() || !armored_ok(&rest[sig + 1..], CLEARTEXT_SIG_END) {
                return Err(outside_signed());
            }
            // A signed line starting with a dash is always escaped "- "; a bare one may
            // be read as a marker.
            let mut body = Vec::with_capacity(sig);
            for line in &rest[..sig] {
                match line.strip_prefix("- ") {
                    Some(unescaped) => body.push(unescaped),
                    None if line.starts_with('-') => return Err(outside_signed()),
                    None => body.push(line),
                }
            }
            Ok(SignedFraming::Cleartext(body.join("\n")))
        }
        _ => Err(outside_signed()),
    }
}

/// The shown cleartext body must equal the verified text. Trailing
/// whitespace and final newlines aren't hashed (RFC 9580 7.2), so both drop them.
fn check_cleartext_body(shown: &str, verified: &str) -> Result<(), String> {
    let normal = |s: &str| {
        s.split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l).trim_end_matches([' ', '\t']))
            .collect::<Vec<_>>()
            .join("\n")
            .trim_end_matches('\n')
            .to_owned()
    };
    if normal(shown) == normal(verified) {
        Ok(())
    } else {
        Err(outside_signed())
    }
}

/// Verify a cleartext-signed message -> JSON `VerifyResult`. `max_output`:
/// unattended-run ceiling (see [`read_within`]); `None` when user-started.
#[wasm_bindgen(js_name = "verify")]
pub fn verify_message(
    signed_message: &str,
    verification_keys_json: &str,
    max_output: Option<u32>,
) -> Result<String, String> {
    // A file saved on Windows can lead with a BOM, which Sequoia refuses.
    let signed_message = signed_message.strip_prefix('\u{feff}').unwrap_or(signed_message);
    if signed_message.len() > MAX_SIGNED_INPUT_BYTES {
        return Err(too_large_to_verify());
    }
    let framing = check_signed_framing(signed_message)?;
    let certs = parse_armored_certs(verification_keys_json)?;

    let helper = VerifyHelper {
        certs,
        signatures: SignatureReport::unsigned(),
    };

    let mut builder = VerifierBuilder::from_bytes(signed_message.as_bytes()).str_err()?;
    if let Some(size) = stream_buffer(max_output, MAX_VERIFIED_BYTES) {
        builder = builder.buffer_size(size);
    }
    let mut verifier = builder.with_policy(policy(), None, helper).str_err()?;

    let content = read_within(&mut verifier, MAX_VERIFIED_BYTES, max_output)?;
    let text = String::from_utf8(content).str_err()?;
    if let SignedFraming::Cleartext(shown) = &framing {
        check_cleartext_body(shown, &text)?;
    }
    let helper = verifier.into_helper();

    serde_json::to_string(&VerifyResult {
        text,
        signatures: helper.signatures,
    })
    .str_err()
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

/// Decrypt with a stored key handle -> `[4-byte LE sig_json_len][sig_json][plaintext]`.
#[wasm_bindgen(js_name = "decryptWithHandle")]
pub fn decrypt_with_handle(
    ciphertext: &[u8],
    key_handle: u32,
    verification_keys_json: Option<String>,
    // Unattended-run plaintext ceiling (see `read_within`); `None` keeps `decrypt_limit`.
    max_output: Option<u32>,
) -> Result<Vec<u8>, String> {
    refuse_unencrypted(ciphertext)?;
    let decryption_cert = get_cert_from_handle(key_handle)?;

    let verification_certs = match verification_keys_json {
        Some(ref json) => parse_armored_certs(json)?,
        None => Vec::new(),
    };

    let helper = DecryptHelper {
        decryption_cert,
        verification_certs,
        signatures: SignatureReport::unsigned(),
        encrypted: false,
    };

    let limit = decrypt_limit(ciphertext.len());
    let mut builder = DecryptorBuilder::from_bytes(ciphertext).str_err()?;
    if let Some(size) = stream_buffer(max_output, limit) {
        builder = builder.buffer_size(size);
    }
    let mut decryptor = builder.with_policy(policy(), None, helper).str_err()?;

    let mut plaintext = read_within(&mut decryptor, limit, max_output)?;
    let helper = decryptor.into_helper();
    // The header scan saw only what precedes the first container; this is the
    // parse that produced the plaintext.
    if !helper.encrypted {
        plaintext.zeroize();
        return Err(not_encrypted());
    }

    Ok(pack_decrypt_result(&helper.signatures, plaintext))
}

/// `[4-byte LE sig_json_len][sig_json][plaintext]`, the one definition of
/// the layout. Packing makes signature status and plaintext cross the
/// boundary atomically, so no caller renders plaintext against a verdict
/// read separately (TOCTOU).
fn pack_decrypt_result(signatures: &SignatureReport, plaintext: Vec<u8>) -> Vec<u8> {
    let sig_json = serde_json::to_string(signatures).expect("a SignatureReport serializes");
    let sig_bytes = sig_json.as_bytes();
    let sig_len = (sig_bytes.len() as u32).to_le_bytes();

    let mut result = Vec::with_capacity(4 + sig_bytes.len() + plaintext.len());
    result.extend_from_slice(&sig_len);
    result.extend_from_slice(sig_bytes);
    result.extend_from_slice(&plaintext);
    result
}

/// Decrypt a password-encrypted message (`gpg --symmetric`); same packed
/// result as [`decrypt_with_handle`]. Never touches `KEY_STORE`; signatures
/// are still checked against the passed public keys. Every parse failure is
/// `SymmetricWrongPassword` (a v4 SKESK can't tell wrong password from
/// corruption), with the underlying error kept for technical details.
#[wasm_bindgen(js_name = "decryptWithPassword")]
pub fn decrypt_with_password(
    ciphertext: &[u8],
    // BYTES and OWNED: a JS string can't be zeroized (the caller passes a
    // `Uint8Array` and `.fill(0)`s it), and owning it lets this side scrub the
    // marshalled copy too (T-UNLOCK-PARAM-NOT-OWNED; audit-invariants.mjs).
    password: Vec<u8>,
    verification_keys_json: Option<String>,
    // Same ceiling as `decrypt_with_handle`'s.
    max_output: Option<u32>,
) -> Result<Vec<u8>, String> {
    // Wrapped FIRST: an early return above this line would skip the scrub.
    let password = Zeroizing::new(password);
    let verification_certs = match verification_keys_json {
        Some(ref json) => parse_armored_certs(json)?,
        None => Vec::new(),
    };

    // Before the password is used and outside the "wrong password" wrapping:
    // nothing-to-decrypt is not a password problem.
    refuse_unencrypted(ciphertext)?;

    let helper = PasswordDecryptHelper {
        password: password.as_slice().into(),
        verification_certs,
        signatures: SignatureReport::unsigned(),
        encrypted: false,
    };

    // Unreadable FORMAT (draft AEAD, policy-rejected) is reported before the
    // password is used, so a good password isn't blamed for it.
    if scan_session_packets(ciphertext)?.2 == Container::Aed {
        return Err(coded(
            ErrorCode::OcbUnsupported,
            "This message uses the older AEAD (OCB) encrypted-data format, which this app cannot read. Ask the sender to re-encrypt it without --force-ocb.",
        ));
    }

    let (helper, mut plaintext) = decrypt_with_password_inner(ciphertext, helper, max_output)
        .map_err(|e| {
            // Held back for size / past the engine limit: not a password problem (the
            // password may well be right), so both cross unwrapped.
            if e == OUTPUT_CAP_REACHED || error_code::error_code(&e) == Some(ErrorCode::TooLarge) {
                e
            } else {
                coded(
                    ErrorCode::SymmetricWrongPassword,
                    &format!(
                        "Wrong password, or this message is damaged: {}",
                        error_code::message(&e)
                    ),
                )
            }
        })?;
    // See `decrypt_with_handle`: the parse, not the header scan, decides.
    if !helper.encrypted {
        plaintext.zeroize();
        return Err(not_encrypted());
    }
    Ok(pack_decrypt_result(&helper.signatures, plaintext))
}

/// The fallible half, so ONE `map_err` covers the whole parse (builder,
/// policy, session-key unwrap, MDC) -- a per-step wrapper would miss one.
fn decrypt_with_password_inner(
    ciphertext: &[u8],
    helper: PasswordDecryptHelper,
    max_output: Option<u32>,
) -> Result<(PasswordDecryptHelper, Vec<u8>), String> {
    let limit = decrypt_limit(ciphertext.len());
    let mut builder = DecryptorBuilder::from_bytes(ciphertext).str_err()?;
    if let Some(size) = stream_buffer(max_output, limit) {
        builder = builder.buffer_size(size);
    }
    let mut decryptor = builder.with_policy(policy(), None, helper).str_err()?;

    let plaintext = read_within(&mut decryptor, limit, max_output)?;
    Ok((decryptor.into_helper(), plaintext))
}

/// The message's encrypted container, which decides whether we can read it.
#[derive(PartialEq)]
enum Container {
    /// `SEIP` -- v1 (CFB + MDC) or v2 (RFC 9580 AEAD). Both supported.
    Seip,
    /// `AED` (tag 20): pre-RFC-9580 draft AEAD (GnuPG `--force-ocb`, LibrePGP).
    /// Rejected by Sequoia's policy; named so the failure isn't reported as a
    /// wrong password.
    Aed,
    /// No encrypted container found (not an encrypted message).
    None,
}

/// What the session-key packets in FRONT of the encrypted container say.
/// Matched on TAG, not `Packet` variant (load-bearing): Sequoia yields
/// `Packet::Unknown` for unimplemented versions such as GnuPG's
/// `--force-ocb` SKESK, which a variant match misreported as "no password".
fn scan_session_packets(ciphertext: &[u8]) -> Result<(bool, bool, Container), String> {
    use openpgp::packet::Tag;

    let mut password = false;
    let mut public_key = false;
    let mut container = Container::None;
    walk_message_header(ciphertext, |packet| {
        match packet.tag() {
            Tag::SKESK => password = true,
            Tag::PKESK => public_key = true,
            // Session-key packets precede the container; descending would mean decrypting.
            Tag::SEIP => {
                container = Container::Seip;
                return false;
            }
            Tag::AED => {
                container = Container::Aed;
                return false;
            }
            _ => {}
        }
        true
    })?;
    Ok((password, public_key, container))
}

/// Walk a message's leading packets, calling `visit` until it returns false,
/// descending INTO Compressed packets (RFC 9580 allows `Compressed{PKESK,
/// SEIPD}`, which Sequoia opens; skipping it misreported it as unencrypted).
/// Inside one, stop at the first non-session-key/non-container packet:
/// stepping over it would mean INFLATING it (compression bomb).
fn walk_message_header(
    message: &[u8],
    mut visit: impl FnMut(&openpgp::Packet) -> bool,
) -> Result<(), String> {
    use openpgp::packet::Tag;
    use openpgp::parse::{PacketParser, PacketParserResult};

    let mut ppr = PacketParser::from_bytes(message).str_err()?;
    while let PacketParserResult::Some(pp) = ppr {
        if !visit(&pp.packet) {
            break;
        }
        let tag = pp.packet.tag();
        let inside = pp.recursion_depth() > 0;
        if inside && !matches!(tag, Tag::SKESK | Tag::PKESK | Tag::Marker | Tag::CompressedData) {
            break;
        }
        let (_packet, next) = if tag == Tag::CompressedData {
            pp.recurse().str_err()?
        } else {
            pp.next().str_err()?
        };
        ppr = next;
    }
    Ok(())
}

/// How a message can be opened -> `{"password","publicKey","encrypted"}`.
/// Shape only: which KINDS of session-key packets exist, not whether any
/// key or password works. Lets the UI ask for the right thing (a `gpg -c`
/// message must not hit the key path). Both may be true; the caller picks
/// (`workspace-operations.ts` prefers a matching own key). `encrypted`
/// false -> UI uses `openUnencrypted`.
#[wasm_bindgen(js_name = "messageEncryption")]
pub fn message_encryption(ciphertext: &[u8]) -> Result<String, String> {
    let (password, public_key, container) = scan_session_packets(ciphertext)?;
    let encrypted = password || public_key || container != Container::None;
    Ok(serde_json::json!({
        "password": password,
        "publicKey": public_key,
        "encrypted": encrypted,
    })
    .to_string())
}

/// Read a message that is NOT encrypted (inline-signed or bare literal) ->
/// same packed `[len][sig_json][content]` as decrypt, no key or password.
/// Refuses encrypted input, so it can't stand in for a decrypt. Any valid
/// UTF-8 containing an armor line gets `verify`'s strict framing check
/// (decided by content, not lead byte: prose starting with a curly quote
/// once skipped it); binary packets are in practice never valid UTF-8.
#[wasm_bindgen(js_name = "openUnencrypted")]
pub fn open_unencrypted(
    message: &[u8],
    verification_keys_json: Option<String>,
    // The auto-run reaches this too; same ceiling as the decrypts.
    max_output: Option<u32>,
) -> Result<Vec<u8>, String> {
    let message = message.strip_prefix(b"\xef\xbb\xbf").unwrap_or(message);
    if !matches!(scan_session_packets(message)?, (false, false, Container::None)) {
        return Err("This message is encrypted; decrypt it instead.".into());
    }
    const ARMOR_LINE: &str = "-----BEGIN PGP";
    let framing = match std::str::from_utf8(message) {
        Ok(text) if text.contains(ARMOR_LINE) => {
            if message.len() > MAX_SIGNED_INPUT_BYTES {
                return Err(too_large_to_verify());
            }
            Some(check_signed_framing(text)?)
        }
        // Not UTF-8 but holding an armor line (e.g. Latin-1 prose around a block):
        // Sequoia would find the block and skip the prose check. Only binary passes.
        Err(_)
            if message.windows(ARMOR_LINE.len()).any(|w| w == ARMOR_LINE.as_bytes())
                && !reads_as_binary(message) =>
        {
            return Err(outside_signed());
        }
        _ => None,
    };
    let certs = match verification_keys_json {
        Some(ref json) => parse_armored_certs(json)?,
        None => Vec::new(),
    };

    let helper = VerifyHelper {
        certs,
        signatures: SignatureReport::unsigned(),
    };
    let limit = decrypt_limit(message.len());
    let mut builder = VerifierBuilder::from_bytes(message).str_err()?;
    if let Some(size) = stream_buffer(max_output, limit) {
        builder = builder.buffer_size(size);
    }
    let mut verifier = builder.with_policy(policy(), None, helper).str_err()?;
    let content = read_within(&mut verifier, limit, max_output)?;
    if let Some(SignedFraming::Cleartext(shown)) = &framing {
        check_cleartext_body(shown, std::str::from_utf8(&content).str_err()?)?;
    }
    let helper = verifier.into_helper();

    Ok(pack_decrypt_result(&helper.signatures, content))
}

/// `message` is, top to bottom, binary packets this parser knows (armor
/// detection OFF). Containers are stepped over, not opened.
fn reads_as_binary(message: &[u8]) -> bool {
    use openpgp::parse::{Dearmor, PacketParserBuilder, PacketParserResult};
    let Ok(builder) = PacketParserBuilder::from_bytes(message) else { return false };
    let Ok(mut ppr) = builder.dearmor(Dearmor::Disabled).build() else { return false };
    let mut packets = 0;
    loop {
        match ppr {
            PacketParserResult::Some(pp) => {
                if matches!(pp.packet, openpgp::Packet::Unknown(_)) {
                    return false;
                }
                packets += 1;
                match pp.next() {
                    Ok((_, next)) => ppr = next,
                    Err(_) => return false,
                }
            }
            PacketParserResult::EOF(_) => return packets > 0,
        }
    }
}

/// Recipient key handles from a message's PKESKs; anonymous recipients are skipped.
fn recipient_handles(ciphertext: &[u8]) -> Result<Vec<openpgp::KeyHandle>, String> {
    let mut handles = Vec::new();
    // Same walk as `scan_session_packets`, so `Compressed{PKESK, SEIPD}` works too.
    walk_message_header(ciphertext, |packet| match packet {
        openpgp::Packet::PKESK(pkesk) => {
            if let Some(handle) = pkesk.recipient() {
                handles.push(handle);
            }
            true
        }
        openpgp::Packet::SEIP(_) => false,
        _ => true,
    })?;
    Ok(handles)
}

/// Which of the caller's public keys decrypts `ciphertext`, by recipient
/// key ID -> JSON primary fingerprint hex, or `null`. Lets the UI preselect
/// without unlocking and trial-decrypting every candidate.
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
            // `aliases` matches whether the recipient is named by fingerprint or key id.
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

/// True if the armored key has any passphrase-protected secret material.
#[wasm_bindgen(js_name = "isSecretEncrypted")]
pub fn is_secret_encrypted(armored: &str) -> Result<bool, String> {
    let cert = openpgp::Cert::from_bytes(armored.as_bytes()).str_err()?;
    Ok(cert
        .keys()
        .secret()
        .any(|ka| ka.key().secret().is_encrypted()))
}

/// Serialize a cert with secrets (binary) into a `Zeroizing` buffer.
/// `to_vec()` pre-sizes, so no realloc leaves partial copies behind.
fn serialize_secret_cert(cert: &openpgp::Cert) -> Result<Zeroizing<Vec<u8>>, String> {
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

/// Encrypt a cert's secrets under HKDF(PRF, storedSecret) AES-GCM ->
/// `[12-byte iv][ciphertext]`.
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

/// Decrypt one S2K-protected component key, falling back to
/// `decrypt_gpg_padded_secret` for GnuPG's fixed-width ECC MPIs.
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

/// Is this `decrypt_secret` failure Sequoia's strict MPI parser refusing
/// GnuPG's padded scalar? Only `MalformedMPI` qualifies: `InvalidOperation`
/// (schemes RFC 9580 forbids) must never reach the manual path, which
/// doesn't re-check them -- that would be a validation downgrade. The
/// "checksum wrong" MalformedMPI is excluded by message (the only signal;
/// a mismatch just means falling back more, never less safely). A wrong
/// passphrase can't be told apart here, but the manual path re-checks the
/// checksum, so it still ends as "Incorrect passphrase".
fn is_padded_mpi_failure(e: &anyhow::Error) -> bool {
    match e.downcast_ref::<openpgp::Error>() {
        Some(openpgp::Error::MalformedMPI(msg)) => !msg.contains("checksum"),
        _ => false,
    }
}

/// GnuPG serializes protected ECC secret scalars as fixed-width MPIs
/// (leading zero bits), which Sequoia's strict parser rejects -- about half
/// of exported ECC keys. Redo S2K + CFB + checksum by hand and re-encode
/// the scalar minimally.
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

    let wrong = || coded(ErrorCode::WrongPassphrase, "Incorrect passphrase");

    // Only single-scalar ECC needs this; libgcrypt encodes RSA/DSA/ElGamal
    // minimally, so a failure there really is a wrong passphrase.
    let pk_algo = key.pk_algo();
    if !matches!(
        pk_algo,
        PublicKeyAlgorithm::EdDSA | PublicKeyAlgorithm::ECDSA | PublicKeyAlgorithm::ECDH
    ) {
        return Err(wrong());
    }

    let openpgp::packet::key::SecretKeyMaterial::Encrypted(e) = key.secret() else {
        return Err(wrong());
    };
    // GNU-dummy S2K (type 101) from `--export-secret-subkeys`: no secret at all.
    if let S2K::Private { tag: 101, .. } = e.s2k() {
        return Err(
            "This key's primary secret is a stub (offline primary key). \
             Import a full export (gpg --export-secret-keys) instead."
                .into(),
        );
    }
    if e.aead_algo().is_some() {
        return Err(wrong());
    }

    // Everything above is diagnosis only. Redo the crypto by hand ONLY for the
    // padded-MPI failure; a scheme Sequoia refused or a truncated packet gets
    // no second, less strict attempt.
    if !is_padded_mpi_failure(sequoia_err) {
        return Err(wrong());
    }

    let sym = e.algo();
    let key_size = sym.key_size().map_err(|_| wrong())?;
    let block_size = sym.block_size().map_err(|_| wrong())?;
    let derived = e
        .s2k()
        .derive_key(password, key_size)
        .map_err(|_| wrong())?;
    // Sequoia stores the packet's IV prepended to the ciphertext.
    let ct = e.ciphertext().map_err(|_| wrong())?;
    if ct.len() < block_size + 3 {
        return Err(wrong());
    }
    let (iv, data) = ct.split_at(block_size);
    let plaintext = Zeroizing::new(cfb_decrypt(sym, &derived, iv, data)?);

    // Verify the trailing checksum; a mismatch means a wrong passphrase.
    let body = match e.checksum().unwrap_or_default() {
        mpi::SecretKeyChecksum::SHA1 => {
            let split = plaintext.len().checked_sub(20).ok_or_else(wrong)?;
            let (body, want) = plaintext.split_at(split);
            let mut ctx = HashAlgorithm::SHA1
                .context()
                .map_err(|_| wrong())?
                .for_digest();
            ctx.update(body);
            let got = ctx.into_digest().map_err(|_| wrong())?;
            // Constant-time: this IS the passphrase check, so `!=` would leak how many
            // leading bytes matched. Slice `ct_eq` is false (not a panic) on length mismatch.
            if !bool::from(got.as_slice().ct_eq(want)) {
                return Err(wrong());
            }
            body
        }
        mpi::SecretKeyChecksum::Sum16 => {
            let split = plaintext.len().checked_sub(2).ok_or_else(wrong)?;
            let (body, want) = plaintext.split_at(split);
            let got = body
                .iter()
                .fold(0u16, |acc, b| acc.wrapping_add(*b as u16));
            // Constant-time, as the SHA-1 arm.
            if !bool::from(got.to_be_bytes().ct_eq(want)) {
                return Err(wrong());
            }
            body
        }
    };

    // One scalar MPI: 2-byte bit length + (possibly padded) value;
    // `ProtectedMPI::from` trims the leading zeros.
    if body.len() < 2 {
        return Err(wrong());
    }
    let declared_bits = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() != 2 + declared_bits.div_ceil(8) {
        return Err(wrong());
    }
    let scalar: mpi::ProtectedMPI = (&body[2..]).into();
    let material = match pk_algo {
        PublicKeyAlgorithm::EdDSA => mpi::SecretKeyMaterial::EdDSA { scalar },
        PublicKeyAlgorithm::ECDSA => mpi::SecretKeyMaterial::ECDSA { scalar },
        _ => mpi::SecretKeyMaterial::ECDH { scalar },
    };
    Ok(key.parts_into_public().add_secret(material.into()).0)
}

/// CFB-128 decrypt (AES family only) for the padded fallback; the checksum
/// afterwards authenticates it. The mode is RustCrypto's `cfb-mode`, never
/// hand-rolled: a hostile key file picks cipher, IV and length, and
/// `new_from_slices` turns every size mismatch into an `Err` -- a panic
/// would abort the whole wasm module, unlocked keys included. AES-only is a
/// policy choice about untrusted input.
fn cfb_decrypt(
    sym: SymmetricAlgorithm,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    use cfb_mode::cipher::{BlockCipherEncrypt, KeyInit, KeyIvInit};

    fn run<C>(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String>
    where
        C: BlockCipherEncrypt + KeyInit,
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

/// Strip S2K passphrase protection from any encrypted secret packets
/// (returns `cert` unchanged if none are encrypted).
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

// ---- Shared helpers ----

/// Per-key protection AAD prefixes (mirrored in `encrypt-private-key.ts`).
/// Distinct from crx.rs's `gpg-tools:crx-*`, so the blobs can't be swapped.
const PASSWORD_AAD_PREFIX: &str = "gpg-tools:password:";
const PASSKEY_AAD_PREFIX: &str = "gpg-tools:passkey:";
/// HKDF info for the PRF-derived OpenPGP key. Distinct from crx.rs's: one
/// PRF output must never derive the same key for two key types.
const PASSKEY_HKDF_INFO: &[u8] = b"gpg-tools-prf-v1";

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

// ---- Contacts session: derived key in WASM memory, set by the master
// unlock, independent of key handles. ----

const CONTACTS_AAD: &[u8] = b"gpg-tools:contacts:master";
const CONTACTS_HKDF_INFO: &[u8] = b"gpg-tools-contacts-v1";
const CANARY_PLAINTEXT: &[u8] = b"pgp-tools-master-v1";
/// The canary's own AAD. Canaries sealed under `CONTACTS_AAD` were blobs
/// the legacy store fallback would accept if planted in a store slot; a
/// separate label keeps them out. Old canaries still verify.
const CANARY_AAD: &[u8] = b"gpg-tools:master-canary:v1";

thread_local! {
    static CONTACTS_KEY: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
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
fn derive_contacts_key(ikm: &[u8], hkdf_salt: &[u8]) -> Result<Vec<u8>, String> {
    let hk = Hkdf::<Sha256>::new(Some(hkdf_salt), ikm);
    let mut key = vec![0u8; 32];
    if let Err(e) = hk.expand(CONTACTS_HKDF_INFO, &mut key) {
        key.zeroize();
        return Err(format!("HKDF failed: {e}"));
    }
    Ok(key)
}

/// Argon2id + HKDF contacts key; zeroizes the Argon2id output.
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

fn with_draft_key<T>(f: impl FnOnce(&[u8]) -> T) -> Result<T, String> {
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
fn derive_store_subkey(domain: &str) -> Result<Zeroizing<Vec<u8>>, String> {
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

/// At-rest key-protection envelope shared by every key type (see module header).
mod protected;

/// CRX signing & verification; see the module header for why CRX3 isn't OpenPGP.
mod crx;

/// age encryption to imported SSH keys; see the module header.
mod age;

/// Stable codes on the errors the UI tells apart.
mod error_code;
use error_code::{coded, ErrorCode};

/// ChaCha20 CSPRNG seeded once from `crypto.getRandomValues` (T-ENTROPY-POISON).
mod rng;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod kat_tests;

#[cfg(test)]
mod trust_tests;
