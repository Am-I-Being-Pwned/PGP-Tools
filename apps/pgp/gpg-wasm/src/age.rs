//! # age encryption to SSH recipients
//!
//! Encrypt/decrypt with an SSH key the user already has (`ssh-ed25519`,
//! `ssh-rsa`), sealed by the same vault machinery as PGP/CRX keys
//! (`protected::seal_with_*`, identity bound into the AAD). Trust boundary:
//! `lib.rs` header and `apps/pgp/SECURITY.md`.
//!
//! Scope: import only (no `generate*`), encrypt/decrypt only (age has no
//! signing), SSH keys only -- native age keys would be new arms at the
//! "extension point" seams.
//!
//! ## Why `ssh-key` is a dependency
//!
//! age 0.12 cannot unwrap a passphrase-protected SSH key into reusable
//! material (`UnencryptedKey` is unexported; `Callbacks::request_passphrase`
//! is synchronous, unusable from a browser). So, as with OpenPGP, the source
//! passphrase is stripped at import with `ssh-key` and the *unencrypted*
//! OpenSSH key is resealed under our envelope; at unlock it goes straight to
//! `age::ssh::Identity::from_buffer`. After import the original SSH
//! passphrase protects nothing here, which is why it is zeroized right after use.
//!
//! ## Randomness
//!
//! Salts, nonces and the [`validate_identity`] probe use `crate::rng`. age's
//! own file key, nonces and ephemeral/OAEP randomness use `OsRng` with no
//! injection point, so they stay exposed to `T-ENTROPY-POISON` /
//! SECURITY.md §8.10 -- an unclosable gap, recorded.
//!
//! ## Cross-tool compatibility
//!
//! The ssh stanzas are not in the C2SP spec; Go/Rust age agreement is the
//! spec, so tests decrypt real `age` CLI (Go) ciphertexts. Rust age caps
//! `ssh-rsa` at 4096 bits (Go does not; GitLab issues 8192-bit keys), which
//! gets its own message.

use std::io::{Read, Write};

use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::STANDARD_NO_PAD as B64_NO_PAD;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use wasm_bindgen::prelude::*;

use crate::protected;
use crate::rng;
use crate::StrErr;

// Domain separation. Distinct from -- and never a string-prefix of -- every
// other AAD prefix: the identity is appended, so a prefix-of-a-prefix could
// collide across key types. Pinned by `lib/protection/aad-prefixes.test.ts`.

const SSH_PASSWORD_AAD_PREFIX: &str = "gpg-tools:ssh-password:";
const SSH_PASSKEY_AAD_PREFIX: &str = "gpg-tools:ssh-passkey:";
/// Distinct per key type: one PRF output must not derive the same AES key for
/// two key types.
const SSH_PRF_HKDF_INFO: &[u8] = b"gpg-tools-ssh-prf-v1";

/// AAD identity: the `ssh-keygen -l` SHA-256 fingerprint (`SHA256:<b64>`).
const FINGERPRINT_PREFIX: &str = "SHA256:";

/// Longest key comment handed to the UI, in characters.
const SSH_COMMENT_MAX: usize = 120;

/// The comment is attacker-supplied text that becomes the contact's name, so
/// it gets exactly the User ID treatment (bidi/invisible strip + cap) via the
/// SAME function, so the two can never drift.
fn sanitize_comment(comment: &str) -> String {
    crate::sanitize_untrusted(comment, SSH_COMMENT_MAX)
        .trim()
        .to_string()
}

/// age's binary header magic, and the first line of its armored form.
const AGE_BINARY_MAGIC: &[u8] = b"age-encryption.org/v1";
const AGE_ARMOR_BEGIN: &str = "-----BEGIN AGE ENCRYPTED FILE-----";

/// Lower bound is age's weak-RSA refusal; upper is `rsa::RsaPublicKey::MAX_SIZE`.
const RSA_MIN_BITS: u32 = 2048;
const RSA_MAX_BITS: u32 = 4096;

/// Stanza recipient tag: first 4 bytes of SHA-256(public blob), base64. Public
/// material only, which is what makes [`select_age_decryption_key`] possible.
const AGE_SSH_TAG_LEN: usize = 4;

/// Header scan cap: thousands of recipients, but keeps off the payload.
const AGE_HEADER_SCAN_LIMIT: u64 = 64 * 1024;

// Shown verbatim in the UI: each names why and what to do, never "invalid key".

const MSG_ECDSA: &str = "ECDSA SSH keys can't be used for encryption — age only supports ssh-ed25519 and ssh-rsa. Generate an Ed25519 key with `ssh-keygen -t ed25519`.";
// Says nothing about passphrases: FIDO has no encryption operation, so a
// retry would be a dead end.
const MSG_FIDO: &str = "FIDO/hardware-backed SSH keys can't be used for encryption — the FIDO protocol has no encryption operation. Use a software Ed25519 key.";
const MSG_DSA: &str = "DSA keys are obsolete (removed from OpenSSH 10.0, rejected by GitHub since 2022) and unsupported. Generate an Ed25519 key.";
const MSG_LEGACY_PEM: &str = "This key uses the insecure legacy PEM encryption format. Convert it with `ssh-keygen -p -f <key>`, then try again.";
// Not a refusal: the UI matches this programmatically
// (`sshPassphraseRequiredMessage`) to reveal its passphrase field.
const MSG_PASSPHRASE_REQUIRED: &str =
    "This SSH key is passphrase-protected. Enter its passphrase to import it.";
const MSG_PKCS8: &str = "PKCS#8 keys aren't supported. Convert with `ssh-keygen -p -f <key>`.";
const MSG_PPK: &str = "PuTTY .ppk files aren't supported. Export with PuTTYgen → Conversions → Export OpenSSH key.";

fn msg_rsa_too_small(bits: u32) -> String {
    format!("This RSA key is only {bits} bits. age requires at least 2048 bits.")
}

fn msg_rsa_too_large(bits: u32) -> String {
    format!("This RSA key is {bits} bits; we support up to 4096. Note the age CLI accepts larger keys, so a file encrypted elsewhere to this key may not decrypt here.")
}

// Minimal SSH wire-format reader (RFC 4251 §5). Hand-rolled because the
// rejection messages must name the key type, and `ssh-key` erases the type of
// keys whose feature is off (`dsa`).

struct SshReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> SshReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        SshReader { buf, pos: 0 }
    }

    fn u32(&mut self) -> Result<u32, String> {
        let end = self.pos.checked_add(4).ok_or("SSH wire: offset overflow")?;
        let b = self.buf.get(self.pos..end).ok_or("SSH wire: truncated")?;
        self.pos = end;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Length checked against the remaining input *before* the usize cast,
    /// which would truncate on wasm32.
    fn string(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()? as u64;
        if len > self.buf.len() as u64 {
            return Err("SSH wire: string length exceeds input".to_string());
        }
        let len = len as usize;
        let end = self
            .pos
            .checked_add(len)
            .ok_or("SSH wire: length overflow")?;
        let s = self
            .buf
            .get(self.pos..end)
            .ok_or("SSH wire: string truncated")?;
        self.pos = end;
        Ok(s)
    }
}

/// The key-type string at the head of an SSH public-key blob.
fn blob_key_type(blob: &[u8]) -> Result<String, String> {
    let ty = SshReader::new(blob).string()?;
    std::str::from_utf8(ty)
        .map(|s| s.to_string())
        .map_err(|_| "SSH wire: key type is not UTF-8".to_string())
}

/// Bit length of an RFC 4251 `mpint`, ignoring the sign-padding zero byte.
fn mpint_bits(mpint: &[u8]) -> u32 {
    let significant = mpint.iter().position(|b| *b != 0);
    match significant {
        None => 0,
        Some(i) => {
            let rest = &mpint[i..];
            let leading = rest[0].leading_zeros();
            (rest.len() as u32) * 8 - leading
        }
    }
}

/// The AAD identity. Public, which is why [`validate_identity`] exists:
/// binding to it proves nothing on its own.
fn fingerprint(blob: &[u8]) -> String {
    format!(
        "{FINGERPRINT_PREFIX}{}",
        B64_NO_PAD.encode(Sha256::digest(blob))
    )
}

/// The age stanza recipient tag for this blob. NOT a prefix of
/// [`fingerprint`]: truncated digest and truncated base64 diverge at byte 4.
fn age_ssh_tag(blob: &[u8]) -> String {
    B64_NO_PAD.encode(&Sha256::digest(blob)[..AGE_SSH_TAG_LEN])
}

// ── Key-type classification ──

/// Map an SSH key type we deliberately refuse onto its message.
fn rejection_for_key_type(key_type: &str) -> Option<&'static str> {
    if key_type.starts_with("sk-") {
        // Before the ecdsa arm: an sk-ecdsa key is FIDO, the actionable reason.
        return Some(MSG_FIDO);
    }
    if key_type.starts_with("ecdsa-sha2-") {
        return Some(MSG_ECDSA);
    }
    if key_type == "ssh-dss" {
        return Some(MSG_DSA);
    }
    None
}

struct SshPublicKey {
    /// Comment stripped; fed to `age::ssh::Recipient::from_str`.
    recipient: String,
    algorithm: String,
    fingerprint: String,
    comment: String,
}

/// Accept a public-key blob only if age can actually encrypt to it, with a
/// specific reason when it cannot.
fn check_supported_blob(blob: &[u8]) -> Result<String, String> {
    let key_type = blob_key_type(blob)?;
    if let Some(msg) = rejection_for_key_type(&key_type) {
        return Err(msg.to_string());
    }
    match key_type.as_str() {
        "ssh-ed25519" => Ok(key_type),
        "ssh-rsa" => {
            let mut r = SshReader::new(blob);
            r.string()?; // key type, re-read positionally
            r.string()?; // public exponent e
            let n = r.string()?; // modulus n
            let bits = mpint_bits(n);
            if bits < RSA_MIN_BITS {
                return Err(msg_rsa_too_small(bits));
            }
            if bits > RSA_MAX_BITS {
                return Err(msg_rsa_too_large(bits));
            }
            Ok(key_type)
        }
        other => Err(format!(
            "`{other}` SSH keys can't be used for encryption — age only supports ssh-ed25519 and ssh-rsa."
        )),
    }
}

/// Parse an `authorized_keys`-style line: `<type> <base64> [comment]`. The
/// comment is parsed here because age's `Display` drops it.
fn parse_public_key_line(line: &str) -> Result<SshPublicKey, String> {
    let line = line.trim();
    if line.starts_with("-----BEGIN") {
        return Err(
            "That looks like a private key. Paste the public key line (the `.pub` file)."
                .to_string(),
        );
    }
    let mut parts = line.splitn(3, char::is_whitespace);
    let key_type = parts.next().unwrap_or("");
    let encoded = parts.next().unwrap_or("").trim();
    // Sanitized here, where a pasted or fetched comment enters the app.
    let comment = sanitize_comment(parts.next().unwrap_or(""));

    if key_type.is_empty() || encoded.is_empty() {
        return Err("Not an SSH public key (expected `<type> <base64> [comment]`)".to_string());
    }
    let blob = B64
        .decode(encoded)
        .map_err(|_| "Not an SSH public key (the base64 body is malformed)".to_string())?;

    // OpenSSH treats the in-blob type as authoritative; requiring agreement
    // stops a key being classified as one type and used as another.
    let inner = blob_key_type(&blob)?;
    if inner != key_type {
        return Err(format!(
            "SSH public key is inconsistent: labelled `{key_type}` but contains `{inner}`"
        ));
    }
    let algorithm = check_supported_blob(&blob)?;

    Ok(SshPublicKey {
        recipient: format!("{key_type} {encoded}"),
        algorithm,
        fingerprint: fingerprint(&blob),
        comment,
    })
}

/// Extension point: a native `age1…` recipient would be a second arm here.
fn age_recipient(line: &str) -> Result<::age::ssh::Recipient, String> {
    // Ours first, so age's coarse errors arrive as our specific messages.
    let parsed = parse_public_key_line(line)?;
    parsed
        .recipient
        .parse::<::age::ssh::Recipient>()
        .map_err(|e| format!("age rejected this SSH recipient: {e:?}"))
}

// Import-time normalization: whatever the input, what gets sealed is an
// *unencrypted* OpenSSH key, the one form `from_buffer` uses without callbacks.

struct NormalizedIdentity {
    /// Unencrypted OpenSSH private key, PEM text. Secret.
    plaintext: Zeroizing<Vec<u8>>,
    public: SshPublicKey,
}

const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";
const OPENSSH_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const OPENSSH_END: &str = "-----END OPENSSH PRIVATE KEY-----";

/// The cleartext public blob of an OpenSSH private key, read *without*
/// decrypting, so the type is classified before asking for a passphrase.
fn openssh_public_blob(pem: &str) -> Result<Vec<u8>, String> {
    let body: String = pem
        .lines()
        .skip_while(|l| l.trim() != OPENSSH_BEGIN)
        .skip(1)
        .take_while(|l| l.trim() != OPENSSH_END)
        .flat_map(|l| l.trim().chars())
        .collect();
    let raw = B64
        .decode(body)
        .map_err(|_| "OpenSSH private key: malformed base64 body".to_string())?;
    if !raw.starts_with(OPENSSH_MAGIC) {
        return Err("OpenSSH private key: missing `openssh-key-v1` magic".to_string());
    }
    let mut r = SshReader::new(&raw[OPENSSH_MAGIC.len()..]);
    r.string()?; // ciphername
    r.string()?; // kdfname
    r.string()?; // kdfoptions
    let nkeys = r.u32()?;
    if nkeys == 0 {
        return Err("OpenSSH private key: file contains no keys".to_string());
    }
    Ok(r.string()?.to_vec())
}

/// Classify a pasted/uploaded private key file that is *not* an OpenSSH v1
/// key, so each foreign format gets its own actionable message.
fn reject_foreign_private_key_format(text: &str) -> Option<&'static str> {
    let trimmed = text.trim_start();
    if trimmed.starts_with("PuTTY-User-Key-File") {
        return Some(MSG_PPK);
    }
    // Before the PKCS#8 arm: `Proc-Type` can sit under several BEGIN lines.
    if text.contains("Proc-Type: 4,ENCRYPTED") {
        return Some(MSG_LEGACY_PEM);
    }
    if trimmed.starts_with("-----BEGIN PRIVATE KEY-----")
        || trimmed.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----")
    {
        return Some(MSG_PKCS8);
    }
    None
}

/// Parse an OpenSSH private key, strip its passphrase, re-emit unencrypted.
/// `source_passphrase` (empty if none) is caller-owned in `Zeroizing`.
fn normalize_openssh_identity(
    key_file: &[u8],
    source_passphrase: &[u8],
) -> Result<NormalizedIdentity, String> {
    let text = std::str::from_utf8(key_file)
        .map_err(|_| "Not an OpenSSH private key (the file is not text)".to_string())?;

    if let Some(msg) = reject_foreign_private_key_format(text) {
        return Err(msg.to_string());
    }
    if !text.contains(OPENSSH_BEGIN) {
        return Err(
            "Not an OpenSSH private key (expected `-----BEGIN OPENSSH PRIVATE KEY-----`)"
                .to_string(),
        );
    }

    // Classify the cleartext public half first: FIDO/ECDSA are refused even
    // when protected, without asking for the passphrase.
    let blob = openssh_public_blob(text)?;
    check_supported_blob(&blob)?;

    let key = ssh_key::PrivateKey::from_openssh(text)
        .map_err(|e| format!("Could not read this OpenSSH private key: {e}"))?;

    let key = if key.is_encrypted() {
        if source_passphrase.is_empty() {
            return Err(MSG_PASSPHRASE_REQUIRED.to_string());
        }
        key.decrypt(source_passphrase)
            .map_err(|_| "Wrong passphrase for this SSH key.".to_string())?
    } else {
        key
    };

    // Both the `Zeroizing<String>` and its `Vec<u8>` copy are wiped.
    let pem = key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| format!("Could not normalize this OpenSSH private key: {e}"))?;
    let plaintext = Zeroizing::new(pem.as_bytes().to_vec());

    // Re-derive from the normalized bytes so what we fingerprint is what we seal.
    let public = public_key_of_normalized(&plaintext)?;
    let comment = sanitize_comment(key.comment());

    // Final gate: age must accept the bytes now, not at the first decrypt.
    match ::age::ssh::Identity::from_buffer(plaintext.as_slice(), None) {
        Ok(::age::ssh::Identity::Unencrypted(_)) => {}
        Ok(::age::ssh::Identity::Encrypted(_)) => {
            return Err("Internal error: the normalized SSH key is still encrypted".to_string());
        }
        Ok(::age::ssh::Identity::Unsupported(_)) => {
            return Err(format!(
                "`{}` SSH keys can't be used for encryption — age only supports ssh-ed25519 and ssh-rsa.",
                public.algorithm
            ));
        }
        Err(e) => return Err(format!("age could not read this SSH key: {e}")),
    }

    Ok(NormalizedIdentity {
        plaintext,
        public: SshPublicKey { comment, ..public },
    })
}

/// Comment is left empty; callers fill it in.
fn public_key_of_normalized(plaintext: &[u8]) -> Result<SshPublicKey, String> {
    let text = std::str::from_utf8(plaintext)
        .map_err(|_| "Stored SSH key is not text".to_string())?;
    let blob = openssh_public_blob(text)?;
    let algorithm = check_supported_blob(&blob)?;
    Ok(SshPublicKey {
        recipient: format!("{algorithm} {}", B64.encode(&blob)),
        algorithm,
        fingerprint: fingerprint(&blob),
        comment: String::new(),
    })
}

// ── Identity store ──

// Separate from `KEY_STORE` so "KEY_STORE is OpenPGP-only and filled only by
// unlockWith*" (SECURITY.md §4) holds. Handles come from the crate-wide
// `next_handle`, so no two stores issue the same one.
thread_local! {
    static SSH_KEY_STORE: protected::HandleStore = protected::HandleStore::new();
}

/// Assert decrypted plaintext is the key its AAD claims, then store it.
///
/// Fingerprints are public, so anyone can seal their own key under a victim's
/// and the tag verifies. Both checks are needed: (1) the embedded public blob
/// hashes to the bound fingerprint; (2) a live round-trip to that public key
/// decrypts with the identity. Rejected payloads are zeroized in
/// `insert_validated`. Precedent: `crx.rs::store_decrypted_der`.
fn store_normalized_identity(
    plaintext: Zeroizing<Vec<u8>>,
    expected_fingerprint: &str,
) -> Result<u32, String> {
    SSH_KEY_STORE.with(|store| {
        store.insert_validated(plaintext, |bytes| validate_identity(bytes, expected_fingerprint))
    })
}

fn validate_identity(plaintext: &[u8], expected_fingerprint: &str) -> Result<(), String> {
    let public = public_key_of_normalized(plaintext)
        .map_err(|_| "Decrypted data is not a usable SSH private key".to_string())?;
    if public.fingerprint != expected_fingerprint {
        return Err("Decrypted key does not match this SSH key's fingerprint".to_string());
    }

    let identity = ::age::ssh::Identity::from_buffer(plaintext, None)
        .map_err(|_| "Decrypted data is not a usable SSH private key".to_string())?;
    if !matches!(identity, ::age::ssh::Identity::Unencrypted(_)) {
        return Err("Decrypted data is not a usable SSH private key".to_string());
    }
    let recipient = age_recipient(&public.recipient)?;

    // Random so a replayed/precomputed ciphertext proves nothing.
    let mut probe = Zeroizing::new(vec![0u8; 32]);
    rng::fill(probe.as_mut_slice())?;
    let sealed = age_encrypt(&probe, &[recipient], false)?;
    let opened = age_decrypt(&sealed, &identity)
        .map_err(|_| "Decrypted key does not match this SSH key's fingerprint".to_string())?;
    if opened.as_slice() != probe.as_slice() {
        return Err("Decrypted key does not match this SSH key's fingerprint".to_string());
    }
    Ok(())
}

// ── age encrypt / decrypt ──

fn age_encrypt(
    plaintext: &[u8],
    recipients: &[::age::ssh::Recipient],
    armor: bool,
) -> Result<Vec<u8>, String> {
    if recipients.is_empty() {
        return Err("No recipients: an age file needs at least one SSH public key".to_string());
    }
    let refs: Vec<&dyn ::age::Recipient> = recipients
        .iter()
        .map(|r| r as &dyn ::age::Recipient)
        .collect();
    let encryptor = ::age::Encryptor::with_recipients(refs.into_iter())
        .map_err(|e| format!("age encryption failed: {e}"))?;

    let mut out = Vec::new();
    if armor {
        let armored =
            ::age::armor::ArmoredWriter::wrap_output(&mut out, ::age::armor::Format::AsciiArmor)
                .str_err()?;
        let mut writer = encryptor.wrap_output(armored).str_err()?;
        writer.write_all(plaintext).str_err()?;
        writer.finish().str_err()?.finish().str_err()?;
    } else {
        let mut writer = encryptor.wrap_output(&mut out).str_err()?;
        writer.write_all(plaintext).str_err()?;
        writer.finish().str_err()?;
    }
    Ok(out)
}

/// Decrypt an age file, binary or armored (`ArmoredReader` sniffs the marker).
fn age_decrypt(
    ciphertext: &[u8],
    identity: &::age::ssh::Identity,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let reader = ::age::armor::ArmoredReader::new(ciphertext);
    let decryptor =
        ::age::Decryptor::new(reader).map_err(|e| format!("Not a valid age file: {e}"))?;
    let mut stream = decryptor
        .decrypt(std::iter::once(identity as &dyn ::age::Identity))
        .map_err(|e| match e {
            ::age::DecryptError::NoMatchingKeys => {
                "This age file was not encrypted to this SSH key".to_string()
            }
            other => format!("age decryption failed: {other}"),
        })?;
    let mut plaintext = Zeroizing::new(Vec::new());
    stream
        .read_to_end(&mut plaintext)
        .map_err(|e| format!("age decryption failed: {e}"))?;
    Ok(plaintext)
}

// ── WASM exports: public / no secret material ──

/// Parse an SSH public key line into `{ recipient, algorithm, fingerprint,
/// comment }`. `recipient` is the comment-stripped form
/// [`encrypt_age_to_recipients`] expects back.
#[wasm_bindgen(js_name = "parseSshRecipient")]
pub fn parse_ssh_recipient(line: &str) -> Result<String, String> {
    let key = parse_public_key_line(line)?;
    Ok(serde_json::json!({
        "recipient": key.recipient,
        "algorithm": key.algorithm,
        "fingerprint": key.fingerprint,
        "comment": key.comment,
    })
    .to_string())
}

/// Encrypt to SSH recipients (`recipients_json`: array of public-key lines).
/// One bad key fails the whole call rather than silently dropping a recipient.
#[wasm_bindgen(js_name = "encryptAgeToRecipients")]
pub fn encrypt_age_to_recipients(
    plaintext: &[u8],
    recipients_json: &str,
    armor: bool,
) -> Result<Vec<u8>, String> {
    let lines: Vec<String> = serde_json::from_str(recipients_json)
        .map_err(|e| format!("Invalid recipients JSON: {e}"))?;
    let recipients = lines
        .iter()
        .map(|l| age_recipient(l.as_str()))
        .collect::<Result<Vec<_>, _>>()?;
    age_encrypt(plaintext, &recipients, armor)
}

/// Cheap sniff for routing (binary header or armor marker), not validation.
#[wasm_bindgen(js_name = "isAgeMessage")]
pub fn is_age_message(data: &[u8]) -> bool {
    if data.starts_with(AGE_BINARY_MAGIC) {
        return true;
    }
    let head = &data[..data.len().min(256)];
    match std::str::from_utf8(head) {
        Ok(text) => text.trim_start().starts_with(AGE_ARMOR_BEGIN),
        // A partial UTF-8 sequence at the 256-byte cut is not armor.
        Err(_) => false,
    }
}

/// The `(stanza tag, first argument)` pairs in an age file's header; needs no
/// key. Stops at the `---` MAC line so the payload is never read as text; past
/// [`AGE_HEADER_SCAN_LIMIT`] it truncates, which can only lose stanzas, never
/// invent one.
fn age_header_stanzas(ciphertext: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut head = Vec::new();
    ::age::armor::ArmoredReader::new(ciphertext)
        .take(AGE_HEADER_SCAN_LIMIT)
        .read_to_end(&mut head)
        .map_err(|e| format!("Not a valid age file: {e}"))?;

    let text = String::from_utf8_lossy(&head);
    let mut lines = text.lines();
    if lines.next().map(str::as_bytes) != Some(AGE_BINARY_MAGIC) {
        return Err("Not a valid age file: missing the version line".to_string());
    }

    let mut stanzas = Vec::new();
    for line in lines {
        if line.starts_with("---") {
            break;
        }
        if let Some(rest) = line.strip_prefix("-> ") {
            let mut args = rest.split(' ');
            if let (Some(tag), Some(arg)) = (args.next(), args.next()) {
                stanzas.push((tag.to_string(), arg.to_string()));
            }
        }
    }
    Ok(stanzas)
}

/// Index into `candidates_json` of the SSH key whose stanza tag matches, or
/// `null` -- the age twin of `selectDecryptionKey`; nothing secret involved.
/// Stanza type must equal the algorithm too, so a 4-byte tag collision cannot
/// cross `ssh-rsa` and `ssh-ed25519`.
#[wasm_bindgen(js_name = "selectAgeDecryptionKey")]
pub fn select_age_decryption_key(
    ciphertext: &[u8],
    candidates_json: &str,
) -> Result<String, String> {
    let stanzas = age_header_stanzas(ciphertext)?;
    let candidates: Vec<String> = serde_json::from_str(candidates_json).str_err()?;

    let matched = candidates.iter().position(|line| {
        let Ok(key) = parse_public_key_line(line) else {
            return false;
        };
        // Canonical `<type> <base64>`: the body is exactly the tagged blob.
        let Some((_, encoded)) = key.recipient.split_once(' ') else {
            return false;
        };
        let Ok(blob) = B64.decode(encoded) else {
            return false;
        };
        let tag = age_ssh_tag(&blob);
        stanzas
            .iter()
            .any(|(stanza_tag, arg)| *stanza_tag == key.algorithm && *arg == tag)
    });

    serde_json::to_string(&matched).str_err()
}

/// The exact message `protectSshIdentityWith*` returns when the key needs
/// its passphrase. JS compares against this value rather than matching prose:
/// a transcribed copy drifts silently and protected keys become unimportable.
#[wasm_bindgen(js_name = "sshPassphraseRequiredMessage")]
pub fn ssh_passphrase_required_message() -> String {
    MSG_PASSPHRASE_REQUIRED.to_string()
}

/// JSON: the curated message for a private-key format we recognise but refuse
/// (`.ppk`, PKCS#8, legacy PEM), or `null` -- named at import, before any
/// passphrase is asked. `key_file` is owned and wiped on return.
#[wasm_bindgen(js_name = "sshPrivateKeyFormatRejection")]
pub fn ssh_private_key_format_rejection(key_file: Vec<u8>) -> Result<String, String> {
    let key_file = Zeroizing::new(key_file);
    let rejection = std::str::from_utf8(&key_file)
        .ok()
        .and_then(reject_foreign_private_key_format);
    serde_json::to_string(&rejection).str_err()
}

// ── WASM exports: secret-side ──
//
// @secret-handling (mirrors the convention documented in
// `lib/pgp/wasm-secrets.ts`)
//
// Every secret param is taken by value and wrapped in `Zeroizing` on the first
// line, so the marshalled copy is wiped on every exit path
// (`T-UNLOCK-PARAM-NOT-OWNED`).
// No export returns a private key; only `decryptAgeWithHandle`'s plaintext
// leaves, which is the point of the call.

/// Metadata packed ahead of the protection blob. Public values only.
fn protect_meta_json(public: &SshPublicKey) -> String {
    serde_json::json!({
        "fingerprint": public.fingerprint,
        "recipient": public.recipient,
        "algorithm": public.algorithm,
        "comment": public.comment,
    })
    .to_string()
}

/// Import an OpenSSH private key and protect it with a password.
///
/// @secret-handling
///   in:  `key_file` (private key bytes), `source_passphrase` (the
///        passphrase on the file, empty when it has none), `password` (the
///        vault password)
///   out: encrypted blob + public-only metadata
///
/// Returns packed `[u32_le json_len][json][blob]`; `blob` is
/// `[16 salt][12 iv][ct]`. The sealed payload is the key normalized to
/// unencrypted OpenSSH form.
#[wasm_bindgen(js_name = "protectSshIdentityWithPassword")]
pub fn protect_ssh_identity_with_password(
    key_file: Vec<u8>,
    source_passphrase: Vec<u8>,
    password: Vec<u8>,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    let key_file = Zeroizing::new(key_file);
    let source_passphrase = Zeroizing::new(source_passphrase);
    let password = Zeroizing::new(password);

    let normalized = normalize_openssh_identity(&key_file, &source_passphrase)?;
    let blob = protected::seal_with_password(
        &normalized.plaintext,
        &normalized.public.fingerprint,
        SSH_PASSWORD_AAD_PREFIX,
        &password,
        memory_kib,
        iterations,
        parallelism,
    )?;
    Ok(protected::pack_meta_blob(
        &protect_meta_json(&normalized.public),
        &blob,
    ))
}

/// Import an OpenSSH private key and protect it with a passkey (WebAuthn PRF).
///
/// @secret-handling
///   in:  `key_file`, `source_passphrase`, `prf_output`
///   out: encrypted blob + public-only metadata
///   note: `stored_secret` is the persisted HKDF salt, not a secret in
///         itself; it is taken by value for symmetry and wiped anyway.
///
/// Returns packed `[u32_le json_len][json][blob]`; `blob` is `[12 iv][ct]`.
#[wasm_bindgen(js_name = "protectSshIdentityWithPrf")]
pub fn protect_ssh_identity_with_prf(
    key_file: Vec<u8>,
    source_passphrase: Vec<u8>,
    prf_output: Vec<u8>,
    stored_secret: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let key_file = Zeroizing::new(key_file);
    let source_passphrase = Zeroizing::new(source_passphrase);
    let prf_output = Zeroizing::new(prf_output);
    let stored_secret = Zeroizing::new(stored_secret);

    let normalized = normalize_openssh_identity(&key_file, &source_passphrase)?;
    let blob = protected::seal_with_prf(
        &normalized.plaintext,
        &normalized.public.fingerprint,
        SSH_PASSKEY_AAD_PREFIX,
        SSH_PRF_HKDF_INFO,
        &prf_output,
        &stored_secret,
    )?;
    Ok(protected::pack_meta_blob(
        &protect_meta_json(&normalized.public),
        &blob,
    ))
}

/// Unlock a password-protected SSH identity into `SSH_KEY_STORE`.
///
/// @secret-handling
///   in:  `password`
///   out: an opaque `u32` handle -- no key material crosses to JS
///   contract: the plaintext key is validated against `fingerprint` before it
///             becomes reachable (see [`store_normalized_identity`]).
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = "unlockSshIdentityWithPassword")]
pub fn unlock_ssh_identity_with_password(
    ciphertext: &[u8],
    iv: &[u8],
    salt: &[u8],
    fingerprint: &str,
    password: Vec<u8>,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<u32, String> {
    let password = Zeroizing::new(password);
    let plaintext = protected::open_with_password(
        ciphertext,
        iv,
        salt,
        fingerprint,
        SSH_PASSWORD_AAD_PREFIX,
        &password,
        memory_kib,
        iterations,
        parallelism,
    )?;
    store_normalized_identity(plaintext, fingerprint)
}

/// Unlock a passkey-protected SSH identity into `SSH_KEY_STORE`.
///
/// @secret-handling
///   in:  `prf_output`
///   out: an opaque `u32` handle -- no key material crosses to JS
#[wasm_bindgen(js_name = "unlockSshIdentityWithPrf")]
pub fn unlock_ssh_identity_with_prf(
    ciphertext: &[u8],
    iv: &[u8],
    prf_output: Vec<u8>,
    stored_secret: Vec<u8>,
    fingerprint: &str,
) -> Result<u32, String> {
    let prf_output = Zeroizing::new(prf_output);
    let stored_secret = Zeroizing::new(stored_secret);
    let plaintext = protected::open_with_prf(
        ciphertext,
        iv,
        fingerprint,
        SSH_PASSKEY_AAD_PREFIX,
        SSH_PRF_HKDF_INFO,
        &prf_output,
        &stored_secret,
    )?;
    store_normalized_identity(plaintext, fingerprint)
}

/// Re-seal an unlocked SSH identity under a NEW PRF output without the
/// plaintext leaving WASM (twin of `key_store.rs::reprotect_key_with_prf`). The
/// AAD identity is re-derived from the stored key, never taken from JS, and
/// returned as `{"keyId": ...}` before `[12 iv][ct]` so JS can refuse to
/// overwrite a different keyring entry.
///
/// @secret-handling
///   in:  `prf_output`; `stored_secret` is the persisted HKDF salt
///   out: ciphertext + public fingerprint (not secret)
#[wasm_bindgen(js_name = "reprotectSshIdentityWithPrf")]
pub fn reprotect_ssh_identity_with_prf(
    handle: u32,
    prf_output: Vec<u8>,
    stored_secret: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let prf_output = Zeroizing::new(prf_output);
    let stored_secret = Zeroizing::new(stored_secret);
    SSH_KEY_STORE
        .with(|store| {
            store.with(handle, |plaintext| {
                let public = public_key_of_normalized(plaintext)?;
                let blob = protected::seal_with_prf(
                    plaintext,
                    &public.fingerprint,
                    SSH_PASSKEY_AAD_PREFIX,
                    SSH_PRF_HKDF_INFO,
                    &prf_output,
                    &stored_secret,
                )?;
                let meta = serde_json::json!({ "keyId": public.fingerprint });
                Ok(protected::pack_meta_blob(&meta.to_string(), &blob))
            })
        })
        .ok_or("SSH key handle not found - key may have been locked")?
}

/// Decrypt an age file (binary or armored) with an unlocked handle.
///
/// @secret-handling
///   out: the decrypted plaintext, which crosses to JS. wasm-bindgen copies
///        it across the ABI; the crate's zeroize-on-free allocator wipes the
///        Rust-side buffer when that copy is freed. The JS caller owns
///        scrubbing its own copy.
#[wasm_bindgen(js_name = "decryptAgeWithHandle")]
pub fn decrypt_age_with_handle(ciphertext: &[u8], handle: u32) -> Result<Vec<u8>, String> {
    SSH_KEY_STORE
        .with(|store| {
            store.with(handle, |plaintext| {
                let identity = ::age::ssh::Identity::from_buffer(plaintext, None)
                    .map_err(|e| format!("Stored SSH key is unusable: {e}"))?;
                age_decrypt(ciphertext, &identity).map(|p| p.to_vec())
            })
        })
        .ok_or("SSH key handle not found - key may have been locked")?
}

/// Drop (and zeroize) an unlocked SSH identity handle.
#[wasm_bindgen(js_name = "dropSshIdentity")]
pub fn drop_ssh_identity(handle: u32) -> Result<(), String> {
    SSH_KEY_STORE.with(|store| store.remove(handle));
    Ok(())
}

// ── Tests (native `cargo test`) ──



#[cfg(test)]
#[path = "age_tests.rs"]
mod age_tests;
