//! Encryption to recipients and/or a password, optionally signed.

use std::io::Write;

use openpgp::parse::Parse;
use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message, Signer};
use openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp as openpgp;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::{
    coded, get_cert_from_handle, policy, sanitize_untrusted, signing_keypair,
    verified_revocation_reason, ErrorCode, StrErr,
};

/// Encrypt to recipients (and/or a password), optionally signing.
pub(crate) fn encrypt_impl(
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
