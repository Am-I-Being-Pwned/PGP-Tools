//! Decryption (key handle or password), unencrypted messages, and the
//! session-key packet scans that decide which path a message takes.

use openpgp::crypto::SessionKey;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, MessageLayer, MessageStructure, VerificationHelper,
    VerifierBuilder,
};
use openpgp::parse::Parse;
use openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp as openpgp;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    check_cleartext_body, check_signed_framing, coded, decrypt_limit, error_code,
    get_cert_from_handle, outside_signed, parse_armored_certs, policy, process_signatures,
    read_within, stream_buffer, too_large_to_verify, ErrorCode, SignatureReport, SignedFraming,
    StrErr, VerifyHelper, MAX_SIGNED_INPUT_BYTES, OUTPUT_CAP_REACHED,
};

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

pub(crate) fn not_encrypted() -> String {
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
