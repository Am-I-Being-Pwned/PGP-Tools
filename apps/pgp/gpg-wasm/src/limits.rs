//! Output size caps for decrypt/verify and the capped readers that enforce them.

use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::{coded, ErrorCode, StrErr};

/// Absolute ceiling on a decrypted message: wasm32 can't address more than
/// 4 GiB. `u64` because 4 GiB overflows a wasm32 `usize` by one byte.
pub(crate) const MAX_DECRYPTED_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Max decrypted/ciphertext ratio. A ratio, not a flat number, is what
/// separates a big file from a bomb: real files decrypt to ~their own size,
/// a measured decompression bomb is 754x.
const MAX_EXPANSION_RATIO: u64 = 4;

/// Flat allowance below which the ratio doesn't bind (small messages
/// legitimately exceed 4x once packet framing comes off).
pub(crate) const MIN_EXPANSION_ALLOWANCE: u64 = 64 * 1024 * 1024;

/// Ceiling on verified cleartext. Much tighter because `verify_message`
/// returns it JSON-escaped (6 bytes per NUL) in one `String` in a 32-bit
/// address space; 16 MiB is ~ten thousand pages.
pub(crate) const MAX_VERIFIED_BYTES: u64 = 16 * 1024 * 1024;

/// Ceiling on `verify_message` input (fits anything under
/// `MAX_VERIFIED_BYTES` once armored). Checked first, because framing walks
/// the input line by line before the output cap applies.
pub(crate) const MAX_SIGNED_INPUT_BYTES: usize = 24 * 1024 * 1024;

/// Ceiling on lines in a signed message: the framing check keeps one entry
/// per line, and 200 MB of newlines exhausted wasm memory.
pub(crate) const MAX_SIGNED_LINES: usize = 2_000_000;

/// Output ceiling for a ciphertext: generous, but tied to input size.
pub(crate) fn decrypt_limit(ciphertext_len: usize) -> u64 {
    (ciphertext_len as u64)
        .saturating_mul(MAX_EXPANSION_RATIO)
        .clamp(MIN_EXPANSION_ALLOWANCE, MAX_DECRYPTED_BYTES)
}

/// Error for a read past the engine ceiling, coded `TooLarge`. Callers that
/// wrap errors (`decrypt_with_password` -> "Wrong password") must let it
/// through by code, or a correct password on a big file reads as wrong.
const TOO_LARGE_TO_OPEN: &str = "This message is too large to open here.";

pub(crate) fn too_large_to_open() -> String {
    coded(ErrorCode::TooLarge, TOO_LARGE_TO_OPEN)
}

pub(crate) fn read_capped<R: std::io::Read>(reader: R, limit: u64) -> Result<Vec<u8>, String> {
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
pub(crate) const OUTPUT_CAP_REACHED: &str =
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
pub(crate) fn read_within<R: std::io::Read>(
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
pub(crate) fn stream_buffer(max_output: Option<u32>, limit: u64) -> Option<usize> {
    match max_output.map(u64::from) {
        Some(cap) if cap < limit => Some(cap as usize + 1),
        _ => None,
    }
}
