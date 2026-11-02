//! Public-cert inspection and upkeep: parse, per-key details, multi-cert
//! bundles, merge and revocation, and the SHA-1 policy warnings.

use std::time::SystemTime;

use openpgp::cert::amalgamation::{ValidAmalgamation, ValidateAmalgamation};
use openpgp::cert::CertParser;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize as _;
use openpgp::serialize::SerializeInto as _;
use openpgp::types::{KeyFlags, RevocationStatus};
use sequoia_openpgp as openpgp;
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::{coded, mixes_scripts, policy, sanitize_untrusted, strict_policy, ErrorCode, StrErr};

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

pub(crate) fn system_time_to_millis(t: SystemTime) -> f64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as f64
}

pub(crate) fn extract_key_info(cert: &openpgp::Cert, is_private: bool) -> KeyInfo {
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

pub(crate) fn armor_cert(cert: &openpgp::Cert, is_private: bool) -> Result<String, String> {
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
pub(crate) fn parse_armored_certs(json: &str) -> Result<Vec<openpgp::Cert>, String> {
    let armors: Vec<String> = serde_json::from_str(json).str_err()?;
    Ok(armors
        .iter()
        .filter_map(|a| openpgp::Cert::from_bytes(a.as_bytes()).ok())
        .collect())
}

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

/// Reason from a *verified* revocation, else `None`. `CouldBe`
/// (unverifiable third-party sig) is deliberately not revoked (as sequoia/GnuPG).
pub(crate) fn verified_revocation_reason(status: &RevocationStatus) -> Option<String> {
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
pub(crate) fn strip_third_party(cert: openpgp::Cert) -> openpgp::Result<openpgp::Cert> {
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
pub(crate) fn revocation_signatures(armored: &str) -> Result<Vec<openpgp::packet::Signature>, String> {
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

/// Extract the public key from an armored private key.
#[wasm_bindgen(js_name = "extractPublicKey")]
pub fn extract_public_key(armored_private_key: &str) -> Result<String, String> {
    let cert = openpgp::Cert::from_bytes(armored_private_key.as_bytes()).str_err()?;
    armor_cert(&cert, false)
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
