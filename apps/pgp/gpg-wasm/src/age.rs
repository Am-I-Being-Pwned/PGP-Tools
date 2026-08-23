//! # age encryption to SSH recipients
//!
//! Part of the WASM/Rust trust boundary -- see the header of `lib.rs` and
//! `apps/pgp/SECURITY.md`. This module lets a user encrypt and decrypt with
//! an **SSH key they already have** (`ssh-ed25519`, `ssh-rsa`), using the
//! age file format, while the key itself is held by the *same* vault
//! machinery as their PGP and CRX keys: Argon2id or WebAuthn-PRF ->
//! AES-256-GCM with the key's identity bound into the AAD
//! (`protected::seal_with_*` / `protected::open_*`).
//!
//! Scope, deliberately narrow:
//!
//! - **Import only.** The app never generates an SSH key; there is no
//!   `generate*` export here. `ssh-keygen` is the generator.
//! - **Encrypt and decrypt only.** age has no signing operation, so there is
//!   nothing sign-shaped to expose.
//! - **SSH keys only.** Native age keys (`age1…` recipients,
//!   `AGE-SECRET-KEY-1…` identities) are *not* implemented. The seams for
//!   them are marked "extension point" below; adding them is new arms on
//!   existing functions, not a rewrite.
//!
//! ## Why `ssh-key` is a dependency (the crux of the design)
//!
//! age 0.12 has no way to unwrap a passphrase-protected SSH key into
//! reusable material. `age::ssh::EncryptedKey::decrypt()` returns
//! `age::ssh::identity::UnencryptedKey`, but that module is `pub(crate)` and
//! the type is unexported -- it cannot be named, stored, or re-sealed. The
//! only public path is `Identity::with_callbacks()`, whose `Callbacks`
//! trait is `Send + Sync + 'static` with a *synchronous*
//! `request_passphrase` -- unusable from a browser, where the prompt is an
//! async round-trip to the UI thread.
//!
//! This app's model is the same one the OpenPGP path uses: **strip the
//! source passphrase at import and reseal under our own envelope.** So the
//! RustCrypto `ssh-key` crate parses the OpenSSH file, decrypts it with the
//! user-supplied passphrase (bcrypt-pbkdf + the OpenSSH cipher), and
//! re-emits an *unencrypted* OpenSSH key; those bytes are what
//! `protected::seal_with_*` seals. At unlock, `protected::open_*` hands the
//! plaintext straight to `age::ssh::Identity::from_buffer`, which yields an
//! `Identity::Unencrypted` that implements `age::Identity` directly. No
//! callback ever runs.
//!
//! Consequence worth stating plainly: after import, the user's original SSH
//! passphrase protects nothing here. The vault password / passkey is the
//! only thing standing between an attacker with the blob and the key. That
//! is the same trade the PGP path makes, and it is why the source
//! passphrase is zeroized the instant it has been used.
//!
//! ## Randomness
//!
//! Everything this module controls draws from `crate::rng` (the crate's
//! ChaCha20 CSPRNG): the Argon2id salts and GCM nonces inside
//! `protected::`, and the probe plaintext in [`validate_identity`].
//!
//! It does **not** cover the randomness age uses internally. `age::Encryptor`
//! calls `new_file_key()` and `Nonce::random()`, and
//! `<age::ssh::Recipient as age::Recipient>::wrap_file_key` constructs its
//! own `OsRng` for the ephemeral X25519 secret (ssh-ed25519) and for
//! RSA-OAEP (ssh-rsa). None of these take an RNG argument, so -- exactly as
//! with Sequoia's key generation in `src/rng.rs` -- there is no injection
//! point short of patching the dependency, and that is not attempted. On
//! `wasm32-unknown-unknown` those `OsRng` draws resolve
//! `crypto.getRandomValues` per call, so they remain exposed to
//! `T-ENTROPY-POISON` / SECURITY.md §8.10 in full. This is an unclosable
//! gap, recorded rather than papered over.
//!
//! ## Cross-tool compatibility
//!
//! The `ssh-rsa` and `ssh-ed25519` stanza types are **not** in the C2SP age
//! specification. They are a convention shared by Go age and Rust age, so
//! cross-tool agreement is the only specification there is. The tests at the
//! bottom of this file therefore include ciphertexts produced by the real
//! `age` CLI (v1.2.1, Go) and assert that we decrypt them.
//!
//! One divergence is real and user-visible: Rust age caps `ssh-rsa` at a
//! 4096-bit modulus (`rsa::RsaPublicKey::MAX_SIZE`), Go age does not, and
//! GitLab hands out 8192-bit keys. A file encrypted elsewhere to such a key
//! cannot be decrypted here. That is surfaced as its own message rather than
//! a generic parse error.

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

// ---------------------------------------------------------------------------
// Domain separation constants
//
// New prefixes for a new key type. They are distinct from -- and, critically,
// not a string-prefix of -- `gpg-tools:password:`, `gpg-tools:passkey:`,
// `gpg-tools:crx-password:`, `gpg-tools:crx-passkey:` and
// `gpg-tools:store:v1:`. The identity is *appended* to the prefix, so if one
// prefix were a prefix of another, some (prefix, identity) pair could produce
// the same AAD bytes as a different key type's -- the exact cross-type
// confusion these exist to prevent. `lib/protection/aad-prefixes.test.ts`
// asserts both properties against literals.
// ---------------------------------------------------------------------------

const SSH_PASSWORD_AAD_PREFIX: &str = "gpg-tools:ssh-password:";
const SSH_PASSKEY_AAD_PREFIX: &str = "gpg-tools:ssh-passkey:";
/// HKDF info string for the PRF-derived AES key. Distinct from the PGP and
/// CRX ones: the same authenticator and the same PRF output must not derive
/// the same AES key for two different key types.
const SSH_PRF_HKDF_INFO: &[u8] = b"gpg-tools-ssh-prf-v1";

/// The identity bound into the AAD is the key's SSH SHA-256 fingerprint
/// (`SHA256:<base64-no-pad>`), the same string `ssh-keygen -l` prints.
const FINGERPRINT_PREFIX: &str = "SHA256:";

/// age's binary header magic, and the first line of its armored form.
const AGE_BINARY_MAGIC: &[u8] = b"age-encryption.org/v1";
const AGE_ARMOR_BEGIN: &str = "-----BEGIN AGE ENCRYPTED FILE-----";

/// Rust age's `ssh-rsa` modulus bounds. The lower one is age's own refusal to
/// touch weak RSA; the upper one is `rsa::RsaPublicKey::MAX_SIZE`.
const RSA_MIN_BITS: u32 = 2048;
const RSA_MAX_BITS: u32 = 4096;

/// age's ssh stanzas identify their recipient by the first four bytes of the
/// SHA-256 of its public-key blob, base64 (no padding) -- six characters. It
/// is derived from *public* material alone, which is what makes
/// [`select_age_decryption_key`] possible without any identity.
const AGE_SSH_TAG_LEN: usize = 4;

/// How much of a file [`age_header_stanzas`] will decode looking for the
/// header. An age header is a version line, one stanza per recipient and a
/// MAC line; 64 KiB is thousands of recipients, and the cap keeps the scan
/// off the (arbitrarily large) payload.
const AGE_HEADER_SCAN_LIMIT: u64 = 64 * 1024;

// ---------------------------------------------------------------------------
// User-facing rejection messages
//
// These are shown verbatim in the UI. Each names why the key cannot work and
// what to do instead; none of them may degrade into "invalid key".
// ---------------------------------------------------------------------------

const MSG_ECDSA: &str = "ECDSA SSH keys can't be used for encryption — age only supports ssh-ed25519 and ssh-rsa. Generate an Ed25519 key with `ssh-keygen -t ed25519`.";
// Deliberately says nothing about passphrases: a FIDO key is not
// passphrase-protected material we failed to open, it is a key whose protocol
// has no encryption operation at all. Suggesting a retry would be a dead end.
const MSG_FIDO: &str = "FIDO/hardware-backed SSH keys can't be used for encryption — the FIDO protocol has no encryption operation. Use a software Ed25519 key.";
const MSG_DSA: &str = "DSA keys are obsolete (removed from OpenSSH 10.0, rejected by GitHub since 2022) and unsupported. Generate an Ed25519 key.";
const MSG_LEGACY_PEM: &str = "This key uses the insecure legacy PEM encryption format. Convert it with `ssh-keygen -p -f <key>`, then try again.";
// Not a refusal: the key is importable, we just need the passphrase to
// strip its protection. The UI reveals its passphrase field on this and
// retries from the same step, so it is matched programmatically rather
// than by prose -- see `sshPassphraseRequiredMessage` below.
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

// ---------------------------------------------------------------------------
// Minimal SSH wire-format reader (RFC 4251 §5)
//
// Why hand-rolled rather than `ssh-key`'s parser: the rejection messages above
// have to name the key type, and `ssh-key` only parses types whose Cargo
// feature is enabled (we do not enable `dsa`). A key it cannot parse comes
// back as a generic error with the type erased, which is precisely the
// "generic parse error" outcome the messages exist to avoid. Reading the
// leading type string off the wire needs ~40 lines and works for every type,
// supported or not, so the *classification* is ours and only the supported
// types are handed on.
// ---------------------------------------------------------------------------

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

    /// A length-prefixed byte string. The declared length is checked against
    /// the remaining input *before* the usize cast, which would truncate on
    /// wasm32.
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

/// `SHA256:<base64-no-pad>` over the public-key blob -- the fingerprint
/// `ssh-keygen -l` prints, and the identity this module binds into every AAD.
///
/// It is a *public* value, which is exactly why [`validate_identity`] exists:
/// binding to it proves nothing on its own.
fn fingerprint(blob: &[u8]) -> String {
    format!(
        "{FINGERPRINT_PREFIX}{}",
        B64_NO_PAD.encode(Sha256::digest(blob))
    )
}

/// The recipient tag age writes into an `ssh-ed25519` / `ssh-rsa` stanza for
/// this public-key blob.
///
/// NOT a prefix of [`fingerprint`]'s output even though both hash the same
/// bytes: base64 packs three bytes into four characters, so truncating the
/// digest and truncating its base64 diverge at the fourth byte.
fn age_ssh_tag(blob: &[u8]) -> String {
    B64_NO_PAD.encode(&Sha256::digest(blob)[..AGE_SSH_TAG_LEN])
}

// ---------------------------------------------------------------------------
// Key-type classification
// ---------------------------------------------------------------------------

/// Map an SSH key type we deliberately refuse onto its message.
///
/// Extension point: native age identities never reach here -- they are not
/// SSH key types and would be classified before this call.
fn rejection_for_key_type(key_type: &str) -> Option<&'static str> {
    if key_type.starts_with("sk-") {
        // sk-ssh-ed25519@openssh.com, sk-ecdsa-sha2-nistp256@openssh.com.
        // Checked before the ecdsa arm so an sk-ecdsa key is called FIDO, not
        // ECDSA -- the FIDO reason is the one the user can act on.
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

/// Everything this module needs to know about a public key, all of it
/// non-secret.
struct SshPublicKey {
    /// Canonical `"<type> <base64>"` recipient line, comment stripped. This
    /// is what `age::ssh::Recipient::from_str` is fed.
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

/// Parse an `authorized_keys`-style line: `<type> <base64> [comment]`.
///
/// The comment is parsed here rather than taken from age, because age's
/// `Display for ssh::Recipient` drops it -- and for an SSH key the comment is
/// the only human-readable name there is.
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
    // Everything after the base64 is the comment, which may itself contain
    // spaces ("alice@host", but also "work laptop").
    let comment = parts.next().unwrap_or("").trim().to_string();

    if key_type.is_empty() || encoded.is_empty() {
        return Err("Not an SSH public key (expected `<type> <base64> [comment]`)".to_string());
    }
    let blob = B64
        .decode(encoded)
        .map_err(|_| "Not an SSH public key (the base64 body is malformed)".to_string())?;

    // The type appears twice -- as the leading token and inside the blob --
    // and OpenSSH treats the in-blob one as authoritative. Requiring them to
    // agree stops a key from being classified as one type and used as
    // another.
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

/// Turn a recipient line into an age recipient, keeping our messages.
///
/// Extension point: a native age recipient (`age1…`) would be a second arm
/// here returning a `Box<dyn age::Recipient>`.
fn age_recipient(line: &str) -> Result<::age::ssh::Recipient, String> {
    // Our own classification runs first so the failure modes age reports
    // coarsely (`Unsupported`, `RsaModulusTooLarge`) arrive as the specific
    // messages above.
    let parsed = parse_public_key_line(line)?;
    parsed
        .recipient
        .parse::<::age::ssh::Recipient>()
        .map_err(|e| format!("age rejected this SSH recipient: {e:?}"))
}

// ---------------------------------------------------------------------------
// Import-time normalization
//
// The whole point of this section: whatever OpenSSH file the user hands us,
// what gets sealed is always an *unencrypted* OpenSSH private key. That is the
// one form `age::ssh::Identity::from_buffer` can use without callbacks.
// ---------------------------------------------------------------------------

/// A key that has been stripped of its source passphrase and is ready to seal.
struct NormalizedIdentity {
    /// Unencrypted OpenSSH private key, PEM text. Secret.
    plaintext: Zeroizing<Vec<u8>>,
    public: SshPublicKey,
}

/// The OpenSSH private-key envelope's leading magic, before the base64 body.
const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";
const OPENSSH_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
const OPENSSH_END: &str = "-----END OPENSSH PRIVATE KEY-----";

/// Pull the cleartext public-key blob out of an OpenSSH private key *without*
/// decrypting it, so the key type can be classified (and rejected) before the
/// user is asked for a passphrase they may not need to supply.
///
/// Layout: magic, string ciphername, string kdfname, string kdfoptions,
/// u32 nkeys, string publickey[0], ...
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
    // A legacy PEM key encrypted with the pre-OpenSSH-v1 scheme. Checked
    // before the PKCS#8 arm: `Proc-Type` is the load-bearing marker and can
    // sit under several BEGIN lines.
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

/// Parse an OpenSSH private key, strip its passphrase, and re-emit it
/// unencrypted.
///
/// `source_passphrase` is the passphrase on the *file*, empty when the key is
/// unencrypted. It is consumed here and nowhere else; the caller owns it in a
/// `Zeroizing` and it dies at the end of the wasm call.
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

    // Classify from the cleartext public half first: a FIDO or ECDSA key must
    // be refused with its own message even when it is passphrase-protected,
    // and without asking for that passphrase.
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

    // `to_openssh` hands back a `Zeroizing<String>`; the `Vec<u8>` copy is
    // wrapped in `Zeroizing` too, and the `String` is dropped (and wiped) at
    // the end of this function.
    let pem = key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| format!("Could not normalize this OpenSSH private key: {e}"))?;
    let plaintext = Zeroizing::new(pem.as_bytes().to_vec());

    // Re-derive the public half from the *normalized* bytes rather than
    // trusting the input's copy, so what we fingerprint is exactly what we
    // seal.
    let public = public_key_of_normalized(&plaintext)?;
    let comment = key.comment().to_string();

    // Final gate: age itself must accept the normalized bytes as a usable
    // identity. If it would not, the import fails now rather than at the
    // user's first decrypt.
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

/// The public half of a normalized (unencrypted) OpenSSH private key.
/// Comment is left empty; callers that have one fill it in.
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

// ---------------------------------------------------------------------------
// Identity store
// ---------------------------------------------------------------------------

// A `protected::HandleStore` of its own -- the same machinery as `lib.rs`'s
// `KEY_STORE` and `crx.rs`'s `CRX_KEY_STORE`, deliberately a separate
// instance so the "KEY_STORE is OpenPGP-only and populated only by
// unlockWith*" invariant (SECURITY.md §4) stays true. Handles come from the
// crate-wide `next_handle`, so no two stores ever issue the same one.
thread_local! {
    static SSH_KEY_STORE: protected::HandleStore = protected::HandleStore::new();
}

/// Assert that decrypted plaintext really is the private key its AAD claims,
/// then store it.
///
/// The AAD binds a blob to a fingerprint *string*, and fingerprints are
/// public: an attacker can seal their own key under a victim's fingerprint,
/// and the AEAD tag will verify. Two checks close that, and both are needed:
///
/// 1. The public blob carried inside the OpenSSH key must hash to the bound
///    fingerprint. This ties identity -> public key.
/// 2. A live round-trip -- encrypt a random probe to the recipient derived
///    from that public blob, then decrypt it with the identity. This ties
///    public key -> private key, and is the part a forged file cannot fake:
///    it is the same operation a real decrypt performs.
///
/// Check 1 alone would accept a file whose cleartext public section was
/// copied from the victim; check 2 alone would accept a self-consistent
/// foreign key. Together they are self-certifying.
///
/// `crx.rs::store_decrypted_der` is the precedent (it re-derives the
/// extension id from the key's public half). On rejection the payload is
/// dropped inside `insert_validated`, which zeroizes it.
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

    // The probe is random so a replayed/precomputed ciphertext proves
    // nothing; it is drawn from the crate CSPRNG like every other value this
    // module controls.
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

// ---------------------------------------------------------------------------
// age encrypt / decrypt
// ---------------------------------------------------------------------------

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

/// Decrypt an age file, binary or armored -- `ArmoredReader` sniffs the first
/// 36 bytes for the armor marker and passes binary input straight through, so
/// callers never have to say which they have.
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

// ---------------------------------------------------------------------------
// WASM exports: public / no secret material
// ---------------------------------------------------------------------------

/// Parse an SSH public key line into `{ recipient, algorithm, fingerprint,
/// comment }`. No secret material in or out.
///
/// `recipient` is the canonical `<type> <base64>` form with the comment
/// stripped -- that is what [`encrypt_age_to_recipients`] expects back.
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

/// Encrypt to one or more SSH recipients. `recipients_json` is a JSON array
/// of public-key lines. `armor` selects the
/// `-----BEGIN AGE ENCRYPTED FILE-----` form over the binary one.
///
/// Every recipient must be usable: a single bad key fails the whole call
/// rather than silently producing a file the user cannot share as intended.
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

/// Whether `data` looks like an age message -- binary header or armor marker.
/// A cheap sniff for routing, not a validity check.
#[wasm_bindgen(js_name = "isAgeMessage")]
pub fn is_age_message(data: &[u8]) -> bool {
    if data.starts_with(AGE_BINARY_MAGIC) {
        return true;
    }
    // Armored files may carry leading whitespace from a copy/paste.
    let head = &data[..data.len().min(256)];
    match std::str::from_utf8(head) {
        Ok(text) => text.trim_start().starts_with(AGE_ARMOR_BEGIN),
        // A partial UTF-8 sequence at the 256-byte cut is not armor.
        Err(_) => false,
    }
}

/// The `(stanza tag, first argument)` pairs in an age file's header.
///
/// The header is ASCII and self-delimiting: a version line, one `-> tag args`
/// stanza per recipient (each followed by its base64 body), then a `---` MAC
/// line that ends it. Reading it needs no key of any kind.
///
/// Only the *first* argument is kept, because that is where both ssh stanza
/// types put the recipient tag. Scanning stops at the MAC line so the binary
/// payload after it is never treated as text; a header larger than
/// [`AGE_HEADER_SCAN_LIMIT`] is truncated rather than followed, which can only
/// lose stanzas (never invent one -- a match still has to reproduce the tag).
fn age_header_stanzas(ciphertext: &[u8]) -> Result<Vec<(String, String)>, String> {
    // `ArmoredReader` sniffs the armor marker and passes binary straight
    // through, exactly as `age_decrypt` relies on -- so callers need not say
    // which form they hold.
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

/// Pick which of the caller's SSH public keys should decrypt `ciphertext`, by
/// matching the header's ssh stanza tags against each candidate. Returns JSON:
/// the index into `candidates_json`, or `null` when nothing matches.
///
/// The age counterpart of `lib.rs`'s `selectDecryptionKey`, and the same
/// promise: the UI can default-select the right identity up front, without
/// unlocking any of them. Nothing secret is read or returned -- the tag is a
/// hash of the recipient's *public* key.
///
/// A candidate matches only when the stanza type equals its algorithm AND the
/// tag reproduces, so a 4-byte collision between an `ssh-rsa` and an
/// `ssh-ed25519` key cannot cross the two. A candidate this module would
/// refuse as a recipient is skipped rather than matched.
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
        // `recipient` is canonical `<type> <base64>`, so the body is exactly
        // the blob the tag is computed over.
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

/// Name the format of a private key file we will not accept, before anything
/// is asked of the user. Returns JSON: one of the curated messages, or `null`
/// when the file is not a format we recognise-but-refuse.
///
/// Recognition is not acceptance: this exists so a PuTTY `.ppk`, a PKCS#8 key
/// or a legacy encrypted PEM is named at import time rather than reaching the
/// protect step and failing there. It is the same classification
/// [`normalize_openssh_identity`] performs, hoisted so the answer is available
/// without a passphrase.
///
/// The file crosses the boundary but nothing secret comes back, and the copy
/// wasm-bindgen marshalled is wiped on return -- the same `Vec<u8>` ->
/// `Zeroizing` contract every secret parameter in this module keeps.
/// The exact message `protectSshIdentityWith*` returns when the key needs
/// its passphrase. Exported so the JS side can recognise that case by
/// comparing against this value at runtime instead of matching on prose:
/// a transcribed copy drifts the moment the wording is edited, and the
/// failure is silent -- the passphrase field simply stops appearing and
/// passphrase-protected keys become unimportable. Carries no secret.
#[wasm_bindgen(js_name = "sshPassphraseRequiredMessage")]
pub fn ssh_passphrase_required_message() -> String {
    MSG_PASSPHRASE_REQUIRED.to_string()
}

#[wasm_bindgen(js_name = "sshPrivateKeyFormatRejection")]
pub fn ssh_private_key_format_rejection(key_file: Vec<u8>) -> Result<String, String> {
    let key_file = Zeroizing::new(key_file);
    let rejection = std::str::from_utf8(&key_file)
        .ok()
        .and_then(reject_foreign_private_key_format);
    serde_json::to_string(&rejection).str_err()
}

// ---------------------------------------------------------------------------
// WASM exports: secret-side
//
// @secret-handling (mirrors the convention documented in
// `lib/pgp/wasm-secrets.ts`)
//
// Every secret parameter below is taken **by value** as `Vec<u8>` and wrapped
// in `Zeroizing` on the first line of the function, so the copy wasm-bindgen
// marshalled across the ABI is overwritten on function exit -- including on
// the error paths. This is deliberately stricter than `crx.rs`'s unlock
// exports, which still take `&[u8]` and therefore leave the marshalled
// password unzeroized (see `T-UNLOCK-PARAM-NOT-OWNED` in
// `lib/security/threat-model.ts`).
//
// Plaintext key material never crosses to JS from this module: there is no
// export here that returns a private key. The only secret that leaves is the
// *decrypted message* from `decryptAgeWithHandle`, which is the point of the
// call.
// ---------------------------------------------------------------------------

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
/// `[16 salt][12 iv][ct]`. The sealed payload is the key *normalized to
/// unencrypted OpenSSH form* -- see the module header for why.
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
// The argument list is the one the JS boundary already carries for every
// password unlock in the crate (`unlockWithPassword`, `unlockCrxWithPassword`):
// the three slices of `[16 salt][12 iv][ct]`, the identity, the password and
// the three Argon2 parameters. Bundling them into a struct would move the same
// nine values one layer out, exactly as `protected::open_with_password` notes.
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

// ---------------------------------------------------------------------------
// Tests (run natively via `cargo test`)
// ---------------------------------------------------------------------------



#[cfg(test)]
mod age_tests {
    use super::*;

    // ── Fixtures ────────────────────────────────────────────────────
    //
    // Throwaway keys generated for this suite with `ssh-keygen` (OpenSSH
    // 9.x) -- no user key material is in this repo, per SECURITY.md. The
    // `AGE_CLI_*` ciphertexts were produced by the real Go `age` CLI
    // v1.2.1 against these same public keys, and are the cross-tool
    // vectors: the `ssh-rsa` / `ssh-ed25519` stanza types are not in the
    // C2SP age spec, so agreement with Go age is the only spec there is.
    // `age_cli_decrypts_our_ciphertext` re-checks the other direction
    // live when the CLI is installed.
    //
    // Declared at column 0 on purpose: indenting them would indent the
    // PEM and armor bodies inside the raw strings, which base64 rejects.

const ED25519_PUB: &str = r#"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIALwHu/03Nd9eyyrPgxjkFu80Fe1EgN06J8iaY8B+wf6 alice@example.com"#;

const ED25519_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAC8B7v9NzXfXssqz4MY5BbvNBXtRIDdOifImmPAfsH+gAAAJhBxc2tQcXN
rQAAAAtzc2gtZWQyNTUxOQAAACAC8B7v9NzXfXssqz4MY5BbvNBXtRIDdOifImmPAfsH+g
AAAEBA0hh8yBNIqqCUtk4PA5Ii53GhHm7T0f3kb7lSUXGdmwLwHu/03Nd9eyyrPgxjkFu8
0Fe1EgN06J8iaY8B+wf6AAAAEWFsaWNlQGV4YW1wbGUuY29tAQIDBA==
-----END OPENSSH PRIVATE KEY-----
"#;

const ED25519_ENC_PUB: &str = r#"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGeO7+ppZ3dvenXFmkPhdLIxEbLSjyhJSqzvIJtkjZkn locked@example.com"#;

const ED25519_ENC_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCtWLauzz
7ngEmNII8YuGr4AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIGeO7+ppZ3dvenXF
mkPhdLIxEbLSjyhJSqzvIJtkjZknAAAAoCGjE3xIijl7N3+0XOzTHatjES/fA8iJhgNIEI
//CFVhY3xEIVh4ISkcXo9cqEnsjCSe0vgKHJlaFkGpvi1MAQtz0cdpMEfGO0/eUoRVO/nE
n/aDJtlfKlQPWSM6SLo96YvenNPECVl/PbFjKrkn3gw8nyobBZpBiFQiGA1l2+19gLsHRC
50mZlrCmTJrYsrAx271bxrLyZbxInFXOmQxmw=
-----END OPENSSH PRIVATE KEY-----
"#;

const RSA2048_PUB: &str = r#"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDnv+3cHn+ucJO/00PQE0tYGhxeW2VTRCPfHpq2sLZov+IckUE/TONFqsHFVYQLGpB3i3YnyhYefy06kOvxuwhSL8B56e//J/xneCQxbbISt+ypQXn8CdWD4MNhkMmQXx10/Ss8L4JfZm3Po1/F50a32W/XTtp/1vXQ+MKbEqFs5R2oX1ahRtiPo3Z369k/V1JA9QoN3IIz5qZg+a00X6IzA6FhxndVxktX+Qps+7oJ65dwqAAV08gADypK+IWKeVvAYZub7Vzd3y0R2Jt8sm2FnqHVh4TonGxTX/Q6XExPfI5F/cer+3VbIrdF6BhQV88xC4M5/EFv8U+ghUSrFBUD rsa2048@example.com"#;

const RSA2048_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEA57/t3B5/rnCTv9ND0BNLWBocXltlU0Qj3x6atrC2aL/iHJFBP0zj
RarBxVWECxqQd4t2J8oWHn8tOpDr8bsIUi/Aeenv/yf8Z3gkMW2yErfsqUF5/AnVg+DDYZ
DJkF8ddP0rPC+CX2Ztz6NfxedGt9lv107af9b10PjCmxKhbOUdqF9WoUbYj6N2d+vZP1dS
QPUKDdyCM+amYPmtNF+iMwOhYcZ3VcZLV/kKbPu6CeuXcKgAFdPIAA8qSviFinlbwGGbm+
1c3d8tEdibfLJthZ6h1YeE6JxsU1/0OlxMT3yORf3Hq/t1WyK3RegYUFfPMQuDOfxBb/FP
oIVEqxQVAwAAA9Ck6biwpOm4sAAAAAdzc2gtcnNhAAABAQDnv+3cHn+ucJO/00PQE0tYGh
xeW2VTRCPfHpq2sLZov+IckUE/TONFqsHFVYQLGpB3i3YnyhYefy06kOvxuwhSL8B56e//
J/xneCQxbbISt+ypQXn8CdWD4MNhkMmQXx10/Ss8L4JfZm3Po1/F50a32W/XTtp/1vXQ+M
KbEqFs5R2oX1ahRtiPo3Z369k/V1JA9QoN3IIz5qZg+a00X6IzA6FhxndVxktX+Qps+7oJ
65dwqAAV08gADypK+IWKeVvAYZub7Vzd3y0R2Jt8sm2FnqHVh4TonGxTX/Q6XExPfI5F/c
er+3VbIrdF6BhQV88xC4M5/EFv8U+ghUSrFBUDAAAAAwEAAQAAAQALoH12hbEyN0OyZA8K
6WzmRqkVstAqlUiXcRmiAMumBbp6ZG85lcnxPNfr5pZxWCvXU4/h/ymM7iR+w7aSsieAuB
SYCTyZOJBZQJXQRQiiF8gv1bEhC/1CWIx04Ka8L4lyzSDWLCwGTUVFHZU4gJnzr10FGFeu
AkLi8RgSX6TpqZyVwNRGemBTFM1SvMeXhuopkHtgkgiBd+0i1XajwKe7E9IobhKm3cweW/
yzN5imCBIif13MVmC7wC/C+RZRvVBcR8FEHiU/MUGVNLJV8XCKSAEISkVA+BM0p5ISe0zb
hWwz2E/hCrLkVzjbP0eCQbkq1OB4anOBho1i8v1IgY0BAAAAgQCU+kuDtprnuZ2SDouB23
ppzTlFFhzAq+8h9ihyz9mqS+eurscdUZQNW9s0nnUlBfdogvR05szcSI1PWvvZPUlT8eS6
r+1sNU2MSV3nHLcr+6zQputNCJCtTNz9XgUkGa70Fa50QcnFDaFjovLPC8wMGSX6JUZDke
UFddQYjh7utAAAAIEA/UPPnngid+bLJY8KUPrc+yZBP1OglZNQdLuyLeYF1Rc7a0c2R0CT
hZoQtVk74bMnFKjKcEP2Lm57haV+6UMHW7Jc0wnDjMjg0qAwVTzDSN+3b75X1NgNI2GF+X
UfrB0PtvBXBJj4NhFIhWn1KKtmdhpin2NdRdrU9u6HjiFMdTMAAACBAOpAot7VKNS2JiS4
wZWipc9H90zTWb0ENmFkTF2Ti1wUB/Wd+JcYRxhCkiNPNeO8PVW76f8GfAmFDDToDmBDbN
qO8apfIjtsT+OYaMb6gGPkJdj/QpCrPV0hmK1f6dXbC7HdFfdKP1wD7Rlf/K/96tpKgqNF
Q7z8WNmDPxit/0DxAAAAE3JzYTIwNDhAZXhhbXBsZS5jb20BAgMEBQYH
-----END OPENSSH PRIVATE KEY-----
"#;

const RSA8192_PUB: &str = r#"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAEAQC9Q8nqf3udu4FfIXanMNbEDX1NwEZSYSsAO1ky69uvyIDx4pxptNh14B7bylmP4icgw9+zJBL8QWC0CjclzPD6cM9I+kJfmZwX6zjaftcg3VnUq/E/sMg6PIuKDcAFdv0Qym92THeYyC/lfvIfSun03/k7byJmop/jn1LjjHAyw8L4/pshY61zDY1mNeuJGBoYWljSUg0GdUoFqDwP6x+U8XsWcf0KoueY1VaFgZJUzTofSF09pqoGo1Z8vpSkWLWk5GopTjrSEyCgl0aa8gVUu+Wfzc3i4Z3HIQaEt0s7ihFxMc3gwq876NkYfDR08BYuRKqtEEGO48iqv+ebwFCNxvKHnXHAmQPmPRfTPg7shj4fS/rTu0RXCe9teXqJTBSxRGQLoXqPfzoQyWh6t8yrJTOYccz2n6IhsxyZzjOPetNr5SAiP2NWraGDY/g3x31hprutRFyyyxSYqZ8VlTEFhQDLXR41kMowpC1gN0uRpTkJJqP2FJHOmVzxARscz5vlLo192PHUIyKjqFq2+InEzsMynpm3HsrRlEish+OegVUw+Hf+vEn/cY3Q8ggp59YV8trJhgYzsOQ4Oft/ANikkDcDZ4jSOiickr2c6PuAKcFKOsXw1UrEUGY0NWNBUFunoW65WX2z8OHNZt3H46v8MQDPuZABaLRbJXUbBOMSh6LO1RPWwy6P9VWSjfww+QGPuTaEdHen/ZV+e+bH81Z9KaCRLjEjmDJO9zOdJpYPUG/Z2dDVpFgtmveOKAWyR7PyjpBPGWKBh9lWyGXl8HmeiRY4hZjYJIlz1lYXpQF3uhf/nemUXJj2wtmtWhA5kEW9EDOAV0V9Sgsbl99Aax05MuMhdhyAmZVEVNIpq7xEBChg9SeWzY+nAi6MaHlvpiWvsi35ExU0NhAF0a1EYLeLGBqdBcXuBtvRPhD/LCcaVClW5LhSs/tbE4yUwLQV2RIeGnzfci0KELYz/M99zngFeYKWqsOkeUXSXnvfMWTmDQSiz70v8ABUpq5PRrmUYxFrDj5PHgnl0DSCsq3LZPBBjL1FE/PBTqAQKHzmTpPC78gPGtrpTy50FTEr7Ae7atLWFPxaqb12QRobd1QFEQlSk9wxs7F2/tB4nZitpdUhBwesiQsDKCC0N+ElQ8zGGSPS32AvdjkbzaNOEOB88S4RQDXxw2R2DEOF7KOoIzia5fOPicQ3MKB+Sl1lJxcnWNtb9brBFbWxZ8hRFDm3Z9nF8EbIeboaPYwUCWubJAaBSwZttQ11ihNRuy/BqwUlm1ufysY8J+RUtYRKrPcRLduTfVsj6snXhAlICzuPOD4MYpO2NVAu5j7oAp3AExMD0ZYeuNBrvAcZ0zNwfVCqi+B/ big@example.com"#;

const RSA1024_PUB: &str = r#"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDCOIDWGtVE2bL6yKiVH46XzplUvBSCspML0eLD/kToDNynqvFRrzW6rf19OQiGUMHx4hnMUaZCwDTqjfJXS4fcyuYXIwKDvEFai+eVEd/Na1dKvsgG58MtgXfM8Tdt6Ejj2+FB38M9nyo54cOlFpFfqbBPOo+No2olWUWwYyGWvQ== small@example.com"#;

const ECDSA_PUB: &str = r#"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFRxtTsrSw6vTVnE9RgMN1VMqJzBlbyBWQxPweR0PLRkVzWr9FM+2E22fT7hr7own7h0LasVdFaIdukOlrSjxno= ec@example.com"#;

const ECDSA_KEY: &str = r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQRUcbU7K0sOr01ZxPUYDDdVTKicwZW8
gVkMT8HkdDy0ZFc1q/RTPthNtn0+4a+6MJ+4dC2rFXRWiHbpDpa0o8Z6AAAAqDpL/cc6S/
3HAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFRxtTsrSw6vTVnE
9RgMN1VMqJzBlbyBWQxPweR0PLRkVzWr9FM+2E22fT7hr7own7h0LasVdFaIdukOlrSjxn
oAAAAgLB02fxE9kSi5R8PhdHkDdotN/xtoV0hJwYj256f6ZM0AAAAOZWNAZXhhbXBsZS5j
b20BAg==
-----END OPENSSH PRIVATE KEY-----
"#;

const DSA_PUB: &str = r#"ssh-dss AAAAB3NzaC1kc3MAAACBAMm0XxWiDbnff0Uvw4EXSUyfoNx7WVeE5T6EY/w/J62+WTAm3CU1Q+SYsL8KETpvYnzpB39Gj5Yjg01OKks6EJb9c8d77fWKzFyLgr28AZkJQONKMduGaqFv/NIsOZ1pOsLmWR1GF6sEfm4cLPZWkzHFAtAgubrdh2i2kmDyvdgvAAAAFQCLOxknNGsc6bvIZCjbN6beWdO4HQAAAIBc2xFps/hl8j+D2fcJWeVubgmTwL7dUMGgopt440/vZ5ILTxKYKjyLOO46Hxi+9+p0nCBJE14o8W27OfdT/PElEe/MGAiAIeRczSntletPZoq4A23PvTeZ3OKWrMAVKQ8V5USL5P7/utc1ewf1zUkGBFJiXjFa4nWAaTwjnTXV4QAAAIBwo4s3sJygq4dbbfUGs1Md+Tpfc+IWbnQsmK+tekpcthQYuy1AWWOmoBRcYZotUO4gGf96fNgEhOGmShvTvhi8vvOYV+Or6ThipCcnTNOfIfX+L5g31KNbgWcxPKGuwczwz7SciLDHdk9TbB105mGONoBi7XJ7fN+ztsBOfzPpfw== dsa@example.com"#;

const AGE_CLI_CT_ED25519_BIN_B64: &str = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1lZDI1NTE5IGhmQmNYZyBvOTZlVS9jb2JnYmV2ditUbHp1RzBNUzk4ZkxOLzhlc2kxdlB0NE42U0dNCmlqekpLanlSQkdxblVKNXNISzFudFpRNnBaTjBWYnIzbktzRlNCZ1dvemsKLS0tIDZDNXl6MVVsd3BsdmdVWVkvdHR6bUhnNWl2VGdZTjRlMCtubTQ4dE9xNFEKqsusD2Cq0riaThWmqcSVPsqulFMLFOrg090FE3FWyWsxzKFTL6GXZSnbA/uyRoQOU1X08C7DaEcOryIeV9I8IGrMbQczBrebdQ==";

const AGE_CLI_CT_ED25519_ARMOR: &str = r#"-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1lZDI1NTE5IGhmQmNYZyBoVy93
ZzNaMWh4YStoNit3anZHNyt4dkJoY0cvT2NSNlpDcCthYnVjc2trCndnOFNtVDB1
M09MU2FRRDhvVzREMHlIYjNIVGRJR3Z0c0pPWllFWkNvcjQKLS0tIGwxck5mREtQ
OXVHajVWekE3THhwUjgxd1JRR1pCWFlmd2pZREpXQjViQ3MK3UU4CERxpbCdDn+S
dqdcLi2MKP22Y91oE1McMZNqqj3wRKAKZfKKFIVw5FFW9hklG0bqp+SLBw9H2tON
ZgPuQPJAPk5hS/wQ1A==
-----END AGE ENCRYPTED FILE-----
"#;

const AGE_CLI_CT_RSA_BIN_B64: &str = "YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1yc2EgN1RaWFlBCjJqWUVZY3pWeDhWM2ZIUTcvakVISTRMY08vaUR2ZEpHS3dJOWw5Uzd5cWRyR2FQSERpRGd2MWVmN2V3SG5RTDEKcHNxTXVSUEg1T3ZhQWJZUVc1QkE1bTdqNmJLcFVkZVFNRXFKeWJPK2ZOVTBLL3ZZSnZJZHNUYzJFUUprWEU2LwpLRGRnREVENFJ1R2RCZ2hFbDIwb0RhcWE5WjU3RTltQ1BkWDdmTTlkK2pHaDg2aTRtWEdjV2hvTk81ZjMzZnZqCjBadFRCeHdlUFplNll6UW9wUkR1Z3lKNHNQdEVEWEg3TG05Y05MYzgzeWc2bUhpSm0wdGM1VENtM0tnaC9ydUwKWDNHaHpOMG5kY0JUcERvL3hXRFpsbWlZQ1ZabkZtcTJTNkpqak1mUWRRa1I4ck9LOTRDOTl6bHdVVU5yRW0rYwpJV3RhRnBjMUJUN1d1d2lMZXM3N2x3Ci0tLSBNc0RoL1VYN0hkUGNEek5pa1ljMkptdzBKOGdTOWNybEkwWWtpVys0RmZFChettURTnJECyNIDyVvxXrUMMhyUrGR6YjSR0zjAZNTQnxISRLg9/gRehDuNYBEuJ4zt8YssAWN9Ic6Qnzfz4EXDMuTHDDRl/c8=";

const AGE_CLI_CT_RSA_ARMOR: &str = r#"-----BEGIN AGE ENCRYPTED FILE-----
YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IHNzaC1yc2EgN1RaWFlBClB0NXNFU0dz
MDVtNzRwZ0E5Rm1JNnFlMjU1SzBGUHVTMlhMaFRXcmJGaStYMExjdHJTQllPYUpQ
OExpV3l2Y3kKa2R3R2RaLzA0eWNIendab1lwVkRicGxVaFdqTllRM2UyL1hGWFlN
KzBMY2lQMEFlZ3VGWC9UT2YxZHFvODJjVwpVZnIvMWJyU21IWm9hZXBuaXg3c1dX
dFNNWC9KNkNKbHU4bnFqQUhlU3BUcDM3citzYUdQUktaeTg4YUJUQnZtCitzMWRU
VWtuck8rVW5JeEtRYkxCNm4zZTlhZVpzZjlhMDdMeXhMSnNXdlR3bUtVZEJSaHVP
Q0tQV3VPVHI3Rm0KbHE4bmFkQThjZlgvdGlBRUl5Zm11YUtpQ0FjMmFadkp0NlRn
UmgvT0cxdks0WGNpUUxWWklwbkpXcGRnNkgvbAptWWd0Vmdhc3JidjVyVml1MTR3
MnhRCi0tLSAwU1Mra0tUQzViTWxJbERJTTdtM2lvTE5aQkNaOEhpazluZ1MwU0lD
ZUZrCvPvnre8VsB2Zkcbq5QR6o4edRYz+RCsF3FG1UuE/VEvAziYUUVoA/f8FQmj
0zGLdm+nRYnTwmiH8MG7/IT6chudVNBuTiN0dbM=
-----END AGE ENCRYPTED FILE-----
"#;

const ENC_KEY_PASSPHRASE: &[u8] = b"correct horse battery staple";
const PLAINTEXT: &[u8] = b"cross-tool vector: hello from the age CLI";
/// A `sk-ssh-ed25519@openssh.com` public key line, hand-assembled: a real
/// one needs a hardware token, and the rejection depends only on the key
/// type string.
const FIDO_PUB: &str = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fAAAABHNzaDo= fido@example.com";

    // Deliberately weak Argon2 parameters: these tests exercise the
    // envelope's plumbing, not its cost. Production values come from JS.
    const TEST_MEM_KIB: u32 = 64;
    const TEST_ITERS: u32 = 1;
    const TEST_PAR: u32 = 1;

    // Fingerprints as `ssh-keygen -lf` prints them. Hard-coded rather than
    // recomputed so the test would catch us changing how we hash.
    const ED25519_FPR: &str = "SHA256:hfBcXl2f8ULI3/KX9lgL1e+zsWQSQc75zL8naYRM1rY";
    const ED25519_ENC_FPR: &str = "SHA256:yOrpBFC84MjVC8NpQZB2mAmivzrwfVrRynXtzWzq/s0";
    const RSA2048_FPR: &str = "SHA256:7TZXYGCK6AyEBeqIG4ReYtoGyg7fYPbnQIe1icaOsO0";

    fn unpack(packed: &[u8]) -> (serde_json::Value, Vec<u8>) {
        let json_len =
            u32::from_le_bytes([packed[0], packed[1], packed[2], packed[3]]) as usize;
        let meta: serde_json::Value =
            serde_json::from_slice(&packed[4..4 + json_len]).unwrap();
        (meta, packed[4 + json_len..].to_vec())
    }

    /// Import under a password and unlock again -- the full at-rest path.
    fn protect_and_unlock(key_file: &str, source_passphrase: &[u8]) -> (u32, serde_json::Value) {
        let packed = protect_ssh_identity_with_password(
            key_file.as_bytes().to_vec(),
            source_passphrase.to_vec(),
            b"vault password".to_vec(),
            TEST_MEM_KIB,
            TEST_ITERS,
            TEST_PAR,
        )
        .unwrap();
        let (meta, blob) = unpack(&packed);
        let fpr = meta["fingerprint"].as_str().unwrap().to_string();
        let handle = unlock_ssh_identity_with_password(
            &blob[28..],
            &blob[16..28],
            &blob[..16],
            &fpr,
            b"vault password".to_vec(),
            TEST_MEM_KIB,
            TEST_ITERS,
            TEST_PAR,
        )
        .unwrap();
        (handle, meta)
    }

    fn recipients_json(lines: &[&str]) -> String {
        serde_json::to_string(lines).unwrap()
    }

    // ── Public parsing ──────────────────────────────────────────────

    #[test]
    fn parses_an_ed25519_public_key_line() {
        let json: serde_json::Value =
            serde_json::from_str(&parse_ssh_recipient(ED25519_PUB).unwrap()).unwrap();
        assert_eq!(json["algorithm"], "ssh-ed25519");
        assert_eq!(json["fingerprint"], ED25519_FPR);
        // The comment is ours to parse: age's Display drops it, and it is
        // the only human-readable name an SSH key has.
        assert_eq!(json["comment"], "alice@example.com");
        // Canonical recipient: type + base64, comment stripped.
        assert_eq!(
            json["recipient"].as_str().unwrap(),
            ED25519_PUB.rsplitn(2, ' ').nth(1).unwrap()
        );
    }

    #[test]
    fn parses_an_rsa_public_key_line() {
        let json: serde_json::Value =
            serde_json::from_str(&parse_ssh_recipient(RSA2048_PUB).unwrap()).unwrap();
        assert_eq!(json["algorithm"], "ssh-rsa");
        assert_eq!(json["fingerprint"], RSA2048_FPR);
        assert_eq!(json["comment"], "rsa2048@example.com");
    }

    #[test]
    fn keeps_a_multi_word_comment_intact() {
        // ED25519_PUB already carries a comment, so build the line from the
        // canonical two-token form.
        let two_token = ED25519_PUB.rsplitn(2, ' ').nth(1).unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&parse_ssh_recipient(&format!("{two_token} work laptop")).unwrap())
                .unwrap();
        assert_eq!(json["comment"], "work laptop");
    }

    #[test]
    fn a_key_line_with_no_comment_parses() {
        let two_token = ED25519_PUB.rsplitn(2, ' ').nth(1).unwrap();
        let json: serde_json::Value =
            serde_json::from_str(&parse_ssh_recipient(two_token).unwrap()).unwrap();
        assert_eq!(json["comment"], "");
    }

    #[test]
    fn rejects_a_line_whose_label_and_blob_disagree() {
        // The blob is authoritative in OpenSSH; disagreement must not be
        // silently resolved in either direction.
        let b64 = ED25519_PUB.split(' ').nth(1).unwrap();
        let err = parse_ssh_recipient(&format!("ssh-rsa {b64}")).unwrap_err();
        assert!(err.contains("inconsistent"), "{err}");
    }

    // ── Rejection paths (exact user-facing messages) ────────────────

    #[test]
    fn rejects_ecdsa_public_key() {
        assert_eq!(parse_ssh_recipient(ECDSA_PUB).unwrap_err(), MSG_ECDSA);
    }

    #[test]
    fn rejects_ecdsa_private_key_without_asking_for_a_passphrase() {
        let err = protect_ssh_identity_with_password(
            ECDSA_KEY.as_bytes().to_vec(),
            vec![],
            b"pw".to_vec(),
            TEST_MEM_KIB,
            TEST_ITERS,
            TEST_PAR,
        )
        .unwrap_err();
        assert_eq!(err, MSG_ECDSA);
    }

    #[test]
    fn rejects_fido_public_key() {
        assert_eq!(parse_ssh_recipient(FIDO_PUB).unwrap_err(), MSG_FIDO);
        // Must never suggest a passphrase retry: FIDO has no encryption
        // operation at all, so retrying is a dead end.
        assert!(!MSG_FIDO.to_lowercase().contains("passphrase"));
    }

    #[test]
    fn rejects_dsa_public_key() {
        assert_eq!(parse_ssh_recipient(DSA_PUB).unwrap_err(), MSG_DSA);
    }

    #[test]
    fn rejects_rsa_below_2048_bits_and_names_the_size() {
        assert_eq!(
            parse_ssh_recipient(RSA1024_PUB).unwrap_err(),
            "This RSA key is only 1024 bits. age requires at least 2048 bits."
        );
    }

    #[test]
    fn rejects_rsa_above_4096_bits_and_explains_the_divergence() {
        let err = parse_ssh_recipient(RSA8192_PUB).unwrap_err();
        assert_eq!(
            err,
            "This RSA key is 8192 bits; we support up to 4096. Note the age CLI accepts larger keys, so a file encrypted elsewhere to this key may not decrypt here."
        );
        // The whole point of this message is that it is NOT a parse error.
        assert!(!err.contains("invalid"));
    }

    #[test]
    fn rejects_encrypted_legacy_pem() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,5C905C47022DDA74BFF7C7EA3D38DD86\n\nZmFrZQ==\n-----END RSA PRIVATE KEY-----\n";
        let err = protect_ssh_identity_with_password(
            pem.as_bytes().to_vec(),
            vec![],
            b"pw".to_vec(),
            TEST_MEM_KIB,
            TEST_ITERS,
            TEST_PAR,
        )
        .unwrap_err();
        assert_eq!(err, MSG_LEGACY_PEM);
    }

    #[test]
    fn rejects_pkcs8() {
        for pem in [
            "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n",
        ] {
            let err = protect_ssh_identity_with_password(
                pem.as_bytes().to_vec(),
                vec![],
                b"pw".to_vec(),
                TEST_MEM_KIB,
                TEST_ITERS,
                TEST_PAR,
            )
            .unwrap_err();
            assert_eq!(err, MSG_PKCS8);
        }
    }

    #[test]
    fn rejects_putty_ppk() {
        let ppk = "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nComment: k\n";
        let err = protect_ssh_identity_with_password(
            ppk.as_bytes().to_vec(),
            vec![],
            b"pw".to_vec(),
            TEST_MEM_KIB,
            TEST_ITERS,
            TEST_PAR,
        )
        .unwrap_err();
        assert_eq!(err, MSG_PPK);
    }

    /// The same three formats, named up front by the export the import
    /// preview calls -- no passphrase, no protect step. This is what puts
    /// MSG_PPK / MSG_LEGACY_PEM / MSG_PKCS8 in front of the user at all: the
    /// import flow routes on the format and shows whatever comes back here.
    #[test]
    fn names_foreign_private_key_formats_without_a_passphrase() {
        for (file, expected) in [
            (
                "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n",
                Some(MSG_PPK),
            ),
            (
                "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\nZmFrZQ==\n-----END RSA PRIVATE KEY-----\n",
                Some(MSG_LEGACY_PEM),
            ),
            (
                "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n",
                Some(MSG_PKCS8),
            ),
            (
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----\n",
                Some(MSG_PKCS8),
            ),
            // Ours, and a PGP block: neither is a format we recognise-but-
            // refuse, so neither may be claimed from the paths that own them.
            (ED25519_KEY, None),
            ("-----BEGIN PGP PRIVATE KEY BLOCK-----\n", None),
            ("-----BEGIN RSA PRIVATE KEY-----\nZmFrZQ==\n", None),
        ] {
            let json = ssh_private_key_format_rejection(file.as_bytes().to_vec()).unwrap();
            assert_eq!(
                serde_json::from_str::<Option<String>>(&json).unwrap(),
                expected.map(str::to_string),
                "{file}"
            );
        }
    }

    /// Binary that is not UTF-8 is not a foreign *text* format -- it must come
    /// back `null` rather than erroring, so the caller can fall through.
    #[test]
    fn foreign_format_check_tolerates_binary() {
        let json = ssh_private_key_format_rejection(vec![0xff, 0xfe, 0x00]).unwrap();
        assert_eq!(serde_json::from_str::<Option<String>>(&json).unwrap(), None);
    }

    // ── Identity selection (which key opens this file) ──────────────

    fn selected(ciphertext: &[u8], candidates: &[&str]) -> Option<usize> {
        let json = select_age_decryption_key(ciphertext, &recipients_json(candidates)).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    /// The tag is a public value, so the match works with no identity at all
    /// -- including against ciphertext the Go CLI produced.
    #[test]
    fn selects_the_identity_a_file_is_encrypted_to() {
        let candidates = [RSA2048_PUB, ED25519_PUB];
        for (ct, expected) in [
            (
                B64.decode(AGE_CLI_CT_ED25519_BIN_B64).unwrap(),
                Some(1usize),
            ),
            (AGE_CLI_CT_ED25519_ARMOR.as_bytes().to_vec(), Some(1)),
            (B64.decode(AGE_CLI_CT_RSA_BIN_B64).unwrap(), Some(0)),
            (AGE_CLI_CT_RSA_ARMOR.as_bytes().to_vec(), Some(0)),
        ] {
            assert_eq!(selected(&ct, &candidates), expected);
        }
    }

    /// Both forms of our own output, and the index is into the candidate list
    /// the caller passed -- not the recipient order in the file.
    #[test]
    fn selects_from_our_own_ciphertext_in_both_forms() {
        for armor in [false, true] {
            let ct = encrypt_age_to_recipients(
                PLAINTEXT,
                &recipients_json(&[ED25519_PUB]),
                armor,
            )
            .unwrap();
            assert_eq!(selected(&ct, &[RSA2048_PUB, ED25519_PUB]), Some(1));
            assert_eq!(selected(&ct, &[ED25519_PUB, RSA2048_PUB]), Some(0));
        }
    }

    #[test]
    fn selects_nothing_when_no_candidate_is_a_recipient() {
        let ct = B64.decode(AGE_CLI_CT_ED25519_BIN_B64).unwrap();
        assert_eq!(selected(&ct, &[RSA2048_PUB]), None);
        assert_eq!(selected(&ct, &[]), None);
        // Candidates this module refuses outright are skipped, not matched.
        assert_eq!(selected(&ct, &[ECDSA_PUB, DSA_PUB, "not a key"]), None);
    }

    /// The tag is only four bytes, so the stanza *type* is checked too: an
    /// `ssh-rsa` key can never answer an `ssh-ed25519` stanza.
    #[test]
    fn selection_requires_the_stanza_type_to_agree() {
        let ct = B64.decode(AGE_CLI_CT_ED25519_BIN_B64).unwrap();
        let stanzas = age_header_stanzas(&ct).unwrap();
        assert_eq!(stanzas.len(), 1);
        assert_eq!(stanzas[0].0, "ssh-ed25519");

        // Same tag, wrong stanza type -> no match. Spliced at the byte level:
        // the header is ASCII but the payload after it is not.
        let needle = b"-> ssh-ed25519 ";
        let at = ct
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("stanza line");
        let mut forged = ct[..at].to_vec();
        forged.extend_from_slice(b"-> ssh-rsa ");
        forged.extend_from_slice(&ct[at + needle.len()..]);
        assert_eq!(selected(&forged, &[ED25519_PUB]), None);
    }

    /// Not an age file at all: an error, not a wrong answer.
    #[test]
    fn selection_rejects_non_age_input() {
        assert!(select_age_decryption_key(b"", &recipients_json(&[ED25519_PUB])).is_err());
        assert!(select_age_decryption_key(
            b"-----BEGIN PGP MESSAGE-----\n",
            &recipients_json(&[ED25519_PUB])
        )
        .is_err());
    }

    /// The stanza tag is NOT a prefix of the `SHA256:` fingerprint, even
    /// though both hash the same blob -- base64 boundaries differ. Pinned so
    /// nobody "simplifies" one into the other.
    #[test]
    fn stanza_tag_is_not_a_fingerprint_prefix() {
        let blob = B64.decode(ED25519_PUB.split(' ').nth(1).unwrap()).unwrap();
        let tag = age_ssh_tag(&blob);
        assert_eq!(tag.len(), 6);
        // The tag the Go CLI wrote into the captured vector.
        assert!(
            String::from_utf8_lossy(&B64.decode(AGE_CLI_CT_ED25519_BIN_B64).unwrap())
                .contains(&format!("-> ssh-ed25519 {tag} ")),
        );
        let fp = fingerprint(&blob);
        assert_ne!(fp[FINGERPRINT_PREFIX.len()..][..6], tag);
    }

    // ── Round trips ─────────────────────────────────────────────────

    #[test]
    fn ed25519_round_trip_binary_and_armored() {
        let (handle, meta) = protect_and_unlock(ED25519_KEY, b"");
        assert_eq!(meta["fingerprint"], ED25519_FPR);
        assert_eq!(meta["algorithm"], "ssh-ed25519");
        assert_eq!(meta["comment"], "alice@example.com");

        for armor in [false, true] {
            let ct =
                encrypt_age_to_recipients(PLAINTEXT, &recipients_json(&[ED25519_PUB]), armor)
                    .unwrap();
            assert_eq!(is_age_message(&ct), true);
            assert_eq!(
                ct.starts_with(AGE_ARMOR_BEGIN.as_bytes()),
                armor,
                "armor flag not honoured"
            );
            assert_eq!(decrypt_age_with_handle(&ct, handle).unwrap(), PLAINTEXT);
        }
        drop_ssh_identity(handle).unwrap();
    }

    #[test]
    fn rsa_round_trip_binary_and_armored() {
        let (handle, meta) = protect_and_unlock(RSA2048_KEY, b"");
        assert_eq!(meta["fingerprint"], RSA2048_FPR);
        assert_eq!(meta["algorithm"], "ssh-rsa");

        for armor in [false, true] {
            let ct =
                encrypt_age_to_recipients(PLAINTEXT, &recipients_json(&[RSA2048_PUB]), armor)
                    .unwrap();
            assert_eq!(decrypt_age_with_handle(&ct, handle).unwrap(), PLAINTEXT);
        }
        drop_ssh_identity(handle).unwrap();
    }

    #[test]
    fn encrypts_to_several_recipients_at_once() {
        let ct = encrypt_age_to_recipients(
            PLAINTEXT,
            &recipients_json(&[ED25519_PUB, RSA2048_PUB]),
            false,
        )
        .unwrap();
        for key in [ED25519_KEY, RSA2048_KEY] {
            let (handle, _) = protect_and_unlock(key, b"");
            assert_eq!(decrypt_age_with_handle(&ct, handle).unwrap(), PLAINTEXT);
            drop_ssh_identity(handle).unwrap();
        }
    }

    #[test]
    fn one_bad_recipient_fails_the_whole_call() {
        // Silently dropping an unusable recipient would hand the user a
        // file they believe is shareable and is not.
        let err = encrypt_age_to_recipients(
            PLAINTEXT,
            &recipients_json(&[ED25519_PUB, ECDSA_PUB]),
            false,
        )
        .unwrap_err();
        assert_eq!(err, MSG_ECDSA);
    }

    // ── Passphrase-protected import (normalize-at-import) ───────────

    #[test]
    fn passphrase_protected_key_is_normalized_sealed_and_usable() {
        let packed = protect_ssh_identity_with_password(
            ED25519_ENC_KEY.as_bytes().to_vec(),
            ENC_KEY_PASSPHRASE.to_vec(),
            b"vault password".to_vec(),
            TEST_MEM_KIB,
            TEST_ITERS,
            TEST_PAR,
        )
        .unwrap();
        let (meta, blob) = unpack(&packed);
        assert_eq!(meta["fingerprint"], ED25519_ENC_FPR);
        assert_eq!(meta["comment"], "locked@example.com");

        let handle = unlock_ssh_identity_with_password(
            &blob[28..],
            &blob[16..28],
            &blob[..16],
            ED25519_ENC_FPR,
            b"vault password".to_vec(),
            TEST_MEM_KIB,
            TEST_ITERS,
            TEST_PAR,
        )
        .unwrap();

        let ct =
            encrypt_age_to_recipients(PLAINTEXT, &recipients_json(&[ED25519_ENC_PUB]), false)
                .unwrap();
        assert_eq!(decrypt_age_with_handle(&ct, handle).unwrap(), PLAINTEXT);
        drop_ssh_identity(handle).unwrap();
    }

    #[test]
    fn the_source_passphrase_is_stripped_not_carried() {
        // What gets sealed must be an *unencrypted* OpenSSH key -- that is
        // the only form `age::ssh::Identity` can use without callbacks.
        let normalized =
            normalize_openssh_identity(ED25519_ENC_KEY.as_bytes(), ENC_KEY_PASSPHRASE).unwrap();
        let text = std::str::from_utf8(&normalized.plaintext).unwrap();
        assert!(text.starts_with(OPENSSH_BEGIN));
        assert!(matches!(
            ::age::ssh::Identity::from_buffer(normalized.plaintext.as_slice(), None).unwrap(),
            ::age::ssh::Identity::Unencrypted(_)
        ));
        assert_eq!(normalized.public.fingerprint, ED25519_ENC_FPR);
    }

    #[test]
    fn a_wrong_source_passphrase_is_reported_as_such() {
        let err = normalize_openssh_identity(ED25519_ENC_KEY.as_bytes(), b"nope")
            .err()
            .expect("a wrong passphrase must not import");
        assert_eq!(err, "Wrong passphrase for this SSH key.");
    }

    #[test]
    fn an_encrypted_key_with_no_passphrase_asks_for_one() {
        let err = normalize_openssh_identity(ED25519_ENC_KEY.as_bytes(), b"")
            .err()
            .expect("an encrypted key with no passphrase must not import");
        assert!(err.contains("passphrase-protected"), "{err}");
    }

    // ── PRF (passkey) path ──────────────────────────────────────────

    #[test]
    fn prf_round_trip() {
        let prf = vec![7u8; 32];
        let stored_secret = vec![9u8; 32];
        let packed = protect_ssh_identity_with_prf(
            ED25519_KEY.as_bytes().to_vec(),
            vec![],
            prf.clone(),
            stored_secret.clone(),
        )
        .unwrap();
        let (meta, blob) = unpack(&packed);
        // PRF blobs carry no Argon2 salt: `[12 iv][ct]`.
        let handle = unlock_ssh_identity_with_prf(
            &blob[12..],
            &blob[..12],
            prf,
            stored_secret,
            meta["fingerprint"].as_str().unwrap(),
        )
        .unwrap();
        let ct = encrypt_age_to_recipients(PLAINTEXT, &recipients_json(&[ED25519_PUB]), false)
            .unwrap();
        assert_eq!(decrypt_age_with_handle(&ct, handle).unwrap(), PLAINTEXT);
        drop_ssh_identity(handle).unwrap();
    }

    #[test]
    fn the_ssh_prf_info_string_is_not_the_pgp_or_crx_one() {
        // Same authenticator, same PRF output: colliding info strings would
        // derive one AES key for two key types.
        assert_ne!(SSH_PRF_HKDF_INFO, b"gpg-tools-prf-v1");
        assert_ne!(SSH_PRF_HKDF_INFO, b"gpg-tools-crx-prf-v1");
        for other in [
            "gpg-tools:password:",
            "gpg-tools:passkey:",
            "gpg-tools:crx-password:",
            "gpg-tools:crx-passkey:",
            "gpg-tools:store:v1:",
        ] {
            for ours in [SSH_PASSWORD_AAD_PREFIX, SSH_PASSKEY_AAD_PREFIX] {
                assert!(!ours.starts_with(other), "{ours} / {other}");
                assert!(!other.starts_with(ours), "{other} / {ours}");
            }
        }
    }

    // ── Identity validation (`insert_validated`) ────────────────────

    /// Seal `plaintext` under an arbitrary fingerprint, exactly as an
    /// attacker with a text editor and our own envelope could.
    fn forge_blob(plaintext: &[u8], claimed_fpr: &str) -> Vec<u8> {
        protected::seal_with_password(
            plaintext,
            claimed_fpr,
            SSH_PASSWORD_AAD_PREFIX,
            b"vault password",
            TEST_MEM_KIB,
            TEST_ITERS,
            TEST_PAR,
        )
        .unwrap()
    }

    fn try_unlock(blob: &[u8], fpr: &str) -> Result<u32, String> {
        unlock_ssh_identity_with_password(
            &blob[28..],
            &blob[16..28],
            &blob[..16],
            fpr,
            b"vault password".to_vec(),
            TEST_MEM_KIB,
            TEST_ITERS,
            TEST_PAR,
        )
    }

    #[test]
    fn rejects_a_blob_whose_key_does_not_match_its_bound_fingerprint() {
        // AAD strings are public, so the AEAD tag verifies fine here. Only
        // the payload itself can settle whether it is the key the
        // fingerprint names.
        let key = normalize_openssh_identity(ED25519_KEY.as_bytes(), b"").unwrap();
        let blob = forge_blob(&key.plaintext, ED25519_ENC_FPR);
        let err = try_unlock(&blob, ED25519_ENC_FPR).unwrap_err();
        assert_eq!(err, "Decrypted key does not match this SSH key's fingerprint");
    }

    #[test]
    fn rejects_a_key_wearing_someone_elses_public_half() {
        // The nastier forgery: splice the victim's cleartext public blob
        // into the attacker's OpenSSH key, so the *fingerprint* check
        // passes. Only the live encrypt/decrypt probe catches this.
        let attacker = normalize_openssh_identity(ED25519_KEY.as_bytes(), b"").unwrap();
        let victim = normalize_openssh_identity(ED25519_ENC_KEY.as_bytes(), ENC_KEY_PASSPHRASE)
            .unwrap();

        let spliced = splice_public_blob(&attacker.plaintext, &victim.plaintext);
        // Precondition: the splice really did move the fingerprint.
        assert_eq!(
            public_key_of_normalized(&spliced).unwrap().fingerprint,
            ED25519_ENC_FPR
        );

        let blob = forge_blob(&spliced, ED25519_ENC_FPR);
        let err = try_unlock(&blob, ED25519_ENC_FPR).unwrap_err();
        assert_eq!(err, "Decrypted key does not match this SSH key's fingerprint");
    }

    /// Replace the cleartext public-key string of `host` with `donor`'s.
    /// Both must be ed25519 keys, whose blobs are the same length.
    fn splice_public_blob(host: &[u8], donor: &[u8]) -> Zeroizing<Vec<u8>> {
        fn body(pem: &str) -> Vec<u8> {
            let b64: String = pem
                .lines()
                .skip_while(|l| l.trim() != OPENSSH_BEGIN)
                .skip(1)
                .take_while(|l| l.trim() != OPENSSH_END)
                .flat_map(|l| l.trim().chars())
                .collect();
            B64.decode(b64).unwrap()
        }
        let mut raw = body(std::str::from_utf8(host).unwrap());
        let host_blob = openssh_public_blob(std::str::from_utf8(host).unwrap()).unwrap();
        let donor_blob = openssh_public_blob(std::str::from_utf8(donor).unwrap()).unwrap();
        assert_eq!(host_blob.len(), donor_blob.len());
        let at = raw
            .windows(host_blob.len())
            .position(|w| w == host_blob.as_slice())
            .expect("public blob appears in the cleartext section");
        raw[at..at + donor_blob.len()].copy_from_slice(&donor_blob);

        let mut pem = String::from(OPENSSH_BEGIN);
        pem.push('\n');
        for chunk in B64.encode(&raw).as_bytes().chunks(70) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str(OPENSSH_END);
        pem.push('\n');
        Zeroizing::new(pem.into_bytes())
    }

    #[test]
    fn rejects_a_blob_of_junk_that_decrypts_cleanly() {
        let blob = forge_blob(b"not a key at all", ED25519_FPR);
        let err = try_unlock(&blob, ED25519_FPR).unwrap_err();
        assert!(err.contains("not a usable SSH private key"), "{err}");
    }

    #[test]
    fn a_wrong_vault_password_is_opaque() {
        let key = normalize_openssh_identity(ED25519_KEY.as_bytes(), b"").unwrap();
        let blob = forge_blob(&key.plaintext, ED25519_FPR);
        let err = unlock_ssh_identity_with_password(
            &blob[28..],
            &blob[16..28],
            &blob[..16],
            ED25519_FPR,
            b"wrong".to_vec(),
            TEST_MEM_KIB,
            TEST_ITERS,
            TEST_PAR,
        )
        .unwrap_err();
        // Must not distinguish wrong password from tampered blob.
        assert!(!err.contains("fingerprint"), "{err}");
    }

    // ── Handles ─────────────────────────────────────────────────────

    #[test]
    fn a_dropped_handle_stops_working() {
        let (handle, _) = protect_and_unlock(ED25519_KEY, b"");
        let ct = encrypt_age_to_recipients(PLAINTEXT, &recipients_json(&[ED25519_PUB]), false)
            .unwrap();
        assert!(decrypt_age_with_handle(&ct, handle).is_ok());
        drop_ssh_identity(handle).unwrap();
        assert!(decrypt_age_with_handle(&ct, handle).is_err());
        // Idempotent, like the other stores.
        drop_ssh_identity(handle).unwrap();
    }

    #[test]
    fn decrypting_a_file_addressed_elsewhere_says_so() {
        let (handle, _) = protect_and_unlock(ED25519_KEY, b"");
        let ct = encrypt_age_to_recipients(PLAINTEXT, &recipients_json(&[RSA2048_PUB]), false)
            .unwrap();
        let err = decrypt_age_with_handle(&ct, handle).unwrap_err();
        assert!(err.contains("not encrypted to this SSH key"), "{err}");
        drop_ssh_identity(handle).unwrap();
    }

    // ── Message detection ───────────────────────────────────────────

    #[test]
    fn detects_age_messages_in_both_forms() {
        assert!(is_age_message(AGE_BINARY_MAGIC));
        assert!(is_age_message(AGE_CLI_CT_ED25519_ARMOR.as_bytes()));
        assert!(is_age_message(
            format!("\n  {AGE_CLI_CT_ED25519_ARMOR}").as_bytes()
        ));
        assert!(is_age_message(&B64.decode(AGE_CLI_CT_ED25519_BIN_B64).unwrap()));

        assert!(!is_age_message(b""));
        assert!(!is_age_message(b"-----BEGIN PGP MESSAGE-----"));
        assert!(!is_age_message(&[0xff, 0xfe, 0xfd]));
    }

    // ── Cross-tool vectors (Go age <-> Rust age) ────────────────────

    #[test]
    fn decrypts_ciphertext_from_the_go_age_cli() {
        for (key, vectors) in [
            (
                ED25519_KEY,
                [
                    B64.decode(AGE_CLI_CT_ED25519_BIN_B64).unwrap(),
                    AGE_CLI_CT_ED25519_ARMOR.as_bytes().to_vec(),
                ],
            ),
            (
                RSA2048_KEY,
                [
                    B64.decode(AGE_CLI_CT_RSA_BIN_B64).unwrap(),
                    AGE_CLI_CT_RSA_ARMOR.as_bytes().to_vec(),
                ],
            ),
        ] {
            let (handle, _) = protect_and_unlock(key, b"");
            for ct in vectors {
                assert_eq!(decrypt_age_with_handle(&ct, handle).unwrap(), PLAINTEXT);
            }
            drop_ssh_identity(handle).unwrap();
        }
    }

    /// The other direction: our ciphertext must open in the Go `age` CLI.
    ///
    /// Skipped when `age` is not installed -- the captured vectors above
    /// cover Go -> Rust unconditionally, but Rust -> Go can only be proven
    /// against a live CLI.
    #[test]
    fn age_cli_decrypts_our_ciphertext() {
        use std::process::Command;

        if Command::new("age").arg("--version").output().is_err() {
            eprintln!("skipping: the `age` CLI is not installed");
            return;
        }

        let dir = std::env::temp_dir().join(format!("gpg-wasm-age-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        for (name, key, pubkey) in [
            ("ed25519", ED25519_KEY, ED25519_PUB),
            ("rsa", RSA2048_KEY, RSA2048_PUB),
        ] {
            for (ext, armor) in [("bin", false), ("age", true)] {
                let key_path = dir.join(format!("{name}.key"));
                let ct_path = dir.join(format!("{name}.{ext}"));
                std::fs::write(&key_path, key).unwrap();
                std::fs::write(
                    &ct_path,
                    encrypt_age_to_recipients(PLAINTEXT, &recipients_json(&[pubkey]), armor)
                        .unwrap(),
                )
                .unwrap();

                let out = Command::new("age")
                    .arg("-d")
                    .arg("-i")
                    .arg(&key_path)
                    .arg(&ct_path)
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "age CLI failed for {name}/{ext}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
                assert_eq!(out.stdout, PLAINTEXT, "{name}/{ext}");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
