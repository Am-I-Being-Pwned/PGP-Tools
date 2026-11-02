//! Signing, verification, cleartext framing checks, and signature classification.

use std::io::Write;

use openpgp::parse::stream::{
    GoodChecksum, MessageLayer, MessageStructure, VerificationError, VerificationHelper,
    VerifierBuilder,
};
use openpgp::parse::Parse;
use openpgp::serialize::stream::{Message, Signer};
use openpgp::types::RevocationStatus;
use sequoia_openpgp as openpgp;
use serde::Serialize;
use wasm_bindgen::prelude::*;

use crate::{
    coded, get_cert_from_handle, parse_armored_certs, policy, read_within, stream_buffer,
    system_time_to_millis, ErrorCode, StrErr, MAX_SIGNED_INPUT_BYTES, MAX_SIGNED_LINES,
    MAX_VERIFIED_BYTES,
};

#[derive(Serialize)]
pub struct VerifyResult {
    pub text: String,
    #[serde(flatten)]
    signatures: SignatureReport,
}

#[derive(Serialize)]
pub(crate) struct SignatureReport {
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
    pub(crate) fn unsigned() -> Self {
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

/// Extract the first valid signing keypair from a cert.
pub(crate) fn signing_keypair(cert: &openpgp::Cert) -> Result<openpgp::crypto::KeyPair, String> {
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
pub(crate) fn cleartext_sign(text: &str, cert: &openpgp::Cert) -> Result<String, String> {
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
pub(crate) fn process_signatures(structure: MessageStructure) -> SignatureReport {
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

pub(crate) struct VerifyHelper {
    pub(crate) certs: Vec<openpgp::Cert>,
    pub(crate) signatures: SignatureReport,
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

pub(crate) fn outside_signed() -> String {
    coded(ErrorCode::TextOutsideSignature, OUTSIDE_SIGNED)
}

/// What `check_signed_framing` found: for cleartext, the body as shown
/// (dash-escaping undone), to compare with what Sequoia verified.
pub(crate) enum SignedFraming {
    Cleartext(String),
    Inline,
}

pub(crate) fn too_large_to_verify() -> String {
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
pub(crate) fn check_signed_framing(signed_message: &str) -> Result<SignedFraming, String> {
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
pub(crate) fn check_cleartext_body(shown: &str, verified: &str) -> Result<(), String> {
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

/// Sign using a stored key handle.
#[wasm_bindgen(js_name = "signWithHandle")]
pub fn sign_with_handle(text: &str, key_handle: u32) -> Result<String, String> {
    cleartext_sign(text, &get_cert_from_handle(key_handle)?)
}
