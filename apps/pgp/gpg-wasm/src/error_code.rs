//! Stable classes for the engine errors the UI tells apart.
//!
//! A coded error is `\x1f<code>\x1f<message>`: the JS side decodes the
//! prefix once, at the wasm boundary (`lib/errors/engine-error.ts`), and
//! classifies on the code; the message stays the engine's own text for
//! the details line. Only a leading prefix counts, and [`coded`] strips
//! the separator from what it wraps, so quoted text (Sequoia's, a user
//! ID) can never pose as a code.
//!
//! Errors not listed here stay plain strings. Codes must match
//! `EngineErrorCode` in `engine-error.ts`.

const SEP: char = '\u{1f}';

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    /// Secret-key S2K passphrase, or an AES-GCM vault/store unlock.
    WrongPassphrase,
    /// A decrypt was handed a message with no encryption layer.
    NotEncrypted,
    /// Past the engine's own size ceiling. Never a password problem.
    TooLarge,
    /// Symmetric decrypt failed: wrong password and damage are one class.
    SymmetricWrongPassword,
    /// GnuPG's pre-RFC-9580 OCB packet; no password opens it here.
    OcbUnsupported,
    /// Encrypted to a key we don't hold.
    NoDecryptionKey,
    NotCrx,
    CrxUnsigned,
    /// Cleartext verify refused words around the signed block.
    TextOutsideSignature,
    KeyExpired,
    KeyRevoked,
    /// No OpenPGP armor / certificate in the input.
    NotPgpData,
}

impl ErrorCode {
    pub const ALL: [ErrorCode; 12] = [
        ErrorCode::WrongPassphrase,
        ErrorCode::NotEncrypted,
        ErrorCode::TooLarge,
        ErrorCode::SymmetricWrongPassword,
        ErrorCode::OcbUnsupported,
        ErrorCode::NoDecryptionKey,
        ErrorCode::NotCrx,
        ErrorCode::CrxUnsigned,
        ErrorCode::TextOutsideSignature,
        ErrorCode::KeyExpired,
        ErrorCode::KeyRevoked,
        ErrorCode::NotPgpData,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::WrongPassphrase => "wrong-passphrase",
            ErrorCode::NotEncrypted => "not-encrypted",
            ErrorCode::TooLarge => "too-large",
            ErrorCode::SymmetricWrongPassword => "symmetric-wrong-password",
            ErrorCode::OcbUnsupported => "ocb-unsupported",
            ErrorCode::NoDecryptionKey => "no-decryption-key",
            ErrorCode::NotCrx => "not-crx",
            ErrorCode::CrxUnsigned => "crx-unsigned",
            ErrorCode::TextOutsideSignature => "text-outside-signature",
            ErrorCode::KeyExpired => "key-expired",
            ErrorCode::KeyRevoked => "key-revoked",
            ErrorCode::NotPgpData => "not-pgp-data",
        }
    }
}

/// `msg` tagged with `code`. An existing code on `msg` is replaced: the
/// outermost classification is the one that holds.
pub fn coded(code: ErrorCode, msg: &str) -> String {
    let body = message(msg);
    let mut out = String::with_capacity(body.len() + code.as_str().len() + 2);
    out.push(SEP);
    out.push_str(code.as_str());
    out.push(SEP);
    out.extend(body.chars().filter(|&c| c != SEP));
    out
}

/// The leading code's raw name, if `err` carries one.
fn code_name(err: &str) -> Option<&str> {
    let rest = err.strip_prefix(SEP)?;
    let end = rest.find(SEP)?;
    Some(&rest[..end])
}

/// The code `err` carries, if any.
pub fn error_code(err: &str) -> Option<ErrorCode> {
    let name = code_name(err)?;
    ErrorCode::ALL.into_iter().find(|c| c.as_str() == name)
}

/// `err` without its code prefix: the human text.
pub fn message(err: &str) -> &str {
    match code_name(err) {
        Some(name) => &err[name.len() + 2 * SEP.len_utf8()..],
        None => err,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_round_trips() {
        for code in ErrorCode::ALL {
            let e = coded(code, "human text");
            assert_eq!(error_code(&e), Some(code));
            assert_eq!(message(&e), "human text");
        }
    }

    #[test]
    fn code_names_are_unique_kebab_case() {
        let mut names: Vec<_> = ErrorCode::ALL.iter().map(|c| c.as_str()).collect();
        assert!(names
            .iter()
            .all(|n| n.chars().all(|c| c.is_ascii_lowercase() || c == '-')));
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ErrorCode::ALL.len());
    }

    #[test]
    fn only_a_leading_prefix_counts() {
        let quoted = format!("Failed: {}", coded(ErrorCode::WrongPassphrase, "x"));
        assert_eq!(error_code(&quoted), None);
        assert_eq!(error_code("plain text"), None);
        assert_eq!(error_code("\u{1f}no-such-code\u{1f}x"), None);
    }

    #[test]
    fn rewrapping_keeps_the_outer_code_and_drops_stray_separators() {
        let inner = coded(ErrorCode::TooLarge, "inner");
        let outer = coded(
            ErrorCode::SymmetricWrongPassword,
            &format!("{inner} \u{1f}x"),
        );
        assert_eq!(error_code(&outer), Some(ErrorCode::SymmetricWrongPassword));
        assert!(!message(&outer).contains('\u{1f}'));
    }
}
