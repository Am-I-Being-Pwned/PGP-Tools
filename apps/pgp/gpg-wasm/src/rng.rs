//! Randomness for the paths this crate controls.
//!
//! ## Why this module exists
//!
//! On `wasm32-unknown-unknown` there is exactly one entropy source:
//! `globalThis.crypto.getRandomValues`, reached through `getrandom`'s
//! wasm-bindgen glue. Both `getrandom` v0.3 (`wasm_js`) and v0.2 (`js`)
//! resolve `getRandomValues` **per call**, so code running in the
//! side-panel realm that replaces it owns every byte this module later
//! calls random. That is `T-ENTROPY-POISON` / SECURITY.md §8.10.
//!
//! This module does not close that hole -- nothing inside WASM can,
//! because there is no second, independent entropy source available on
//! this target. What it does is stop the *repetition*: the platform RNG
//! is read once, at first use, to seed a ChaCha20 CSPRNG
//! (`rand_chacha::ChaCha20Rng`, used exactly as its authors document --
//! `from_seed` with 32 bytes from the platform CSPRNG, then `fill_bytes`).
//! Every later draw comes from ChaCha20's keystream.
//!
//! Consequence: a `getRandomValues` poisoned *after* the first draw, or
//! one pinned to a constant forever, no longer produces repeated GCM
//! nonces, repeated Argon2id salts, or repeated key material. An
//! attacker who poisons `getRandomValues` *before* the first draw knows
//! the seed and therefore the entire stream; against that, this buys
//! nothing.
//!
//! ## Scope
//!
//! Covers the call sites this crate owns:
//!   * AES-256-GCM nonces (`aes_gcm_encrypt`)
//!   * Argon2id salts (password-protection blobs, PGP and CRX)
//!   * the in-WASM draft session key
//!   * CRX RSA-2048 key generation (RustCrypto `rsa` takes an `RngCore`)
//!
//! It does **not** cover OpenPGP key generation. Sequoia's RustCrypto
//! backend hard-codes `rand_core::OsRng` (`crypto/backend/rust.rs`,
//! plus per-algorithm `OsRng` uses in `backend/rust/asymmetric.rs`) and
//! `CertBuilder::generate()` takes no RNG argument, so there is no
//! injection point short of patching the dependency.
//!
//! ## Not reseeded, deliberately
//!
//! Reseeding would mean reading the platform source again -- the exact
//! thing whose repeated use this module exists to avoid -- and a reseed
//! from a poisoned source replaces good state with attacker-chosen
//! state. The trade-off given up is the usual argument for OS reseeding
//! (VM snapshot / fork duplicating PRNG state). A browser extension
//! panel is not forked, and a snapshot-restore that duplicates the WASM
//! instance would duplicate the platform RNG's state too.

use std::cell::RefCell;

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use zeroize::Zeroizing;

thread_local! {
    /// Seeded lazily on first use, then never reseeded.
    static CSPRNG: RefCell<Option<ChaCha20Rng>> = const { RefCell::new(None) };

    /// Test-only stand-in for a poisoned `crypto.getRandomValues`. When
    /// set, `platform_fill` writes this byte repeatedly, exactly as a
    /// patched `getRandomValues` returning a constant would.
    #[cfg(test)]
    static PLATFORM_STUB: RefCell<Option<u8>> = const { RefCell::new(None) };
}

/// The one place this crate touches the platform entropy source.
fn platform_fill(dest: &mut [u8]) -> Result<(), String> {
    #[cfg(test)]
    {
        let stub = PLATFORM_STUB.with(|s| *s.borrow());
        if let Some(byte) = stub {
            dest.fill(byte);
            return Ok(());
        }
    }
    getrandom::fill(dest).map_err(|e| format!("RNG failed: {e}"))
}

/// Fill `dest` with CSPRNG output. Drop-in replacement for the
/// `getrandom::fill` calls this crate used to make directly.
pub(crate) fn fill(dest: &mut [u8]) -> Result<(), String> {
    CSPRNG.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            let mut seed = Zeroizing::new([0u8; 32]);
            platform_fill(seed.as_mut())?;
            *slot = Some(ChaCha20Rng::from_seed(*seed));
        }
        slot.as_mut()
            .expect("CSPRNG seeded above")
            .fill_bytes(dest);
        Ok(())
    })
}

/// `RngCore` view of [`fill`], for APIs that accept an injected RNG
/// (RustCrypto `rsa` key generation).
pub(crate) struct VaultRng;

impl RngCore for VaultRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // A CSPRNG failure in a browser is unrecoverable; the rest of the
        // crate treats it the same way.
        fill(dest).expect("CSPRNG failed");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for VaultRng {}

// ---------------------------------------------------------------------------
// Test hooks
// ---------------------------------------------------------------------------

/// Pin the simulated platform RNG to a constant byte and clear any
/// derived CSPRNG state, so the next draw reseeds from the degenerate
/// source. Models an attacker who replaced `crypto.getRandomValues` with
/// a function that writes a fixed byte.
#[cfg(test)]
pub(crate) fn poison_platform_rng_for_test(byte: u8) {
    PLATFORM_STUB.with(|s| *s.borrow_mut() = Some(byte));
    CSPRNG.with(|c| *c.borrow_mut() = None);
}

/// Undo [`poison_platform_rng_for_test`].
#[cfg(test)]
pub(crate) fn restore_platform_rng_for_test() {
    PLATFORM_STUB.with(|s| *s.borrow_mut() = None);
    CSPRNG.with(|c| *c.borrow_mut() = None);
}

/// Read the simulated platform source directly, bypassing the CSPRNG --
/// only to demonstrate the baseline this module protects against.
#[cfg(test)]
pub(crate) fn platform_fill_for_test(dest: &mut [u8]) -> Result<(), String> {
    platform_fill(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Baseline: what every call site used to do. Under a poisoned
    /// platform RNG every "random" buffer is identical.
    #[test]
    fn poisoned_platform_rng_repeats_itself() {
        poison_platform_rng_for_test(0x41);

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        platform_fill_for_test(&mut a).unwrap();
        platform_fill_for_test(&mut b).unwrap();

        assert_eq!(a, b, "the poisoned source is degenerate by construction");
        assert_eq!(a, [0x41u8; 32]);

        restore_platform_rng_for_test();
    }

    /// The property that matters: seeded once from that same degenerate
    /// source, the CSPRNG still emits distinct, non-repeating output.
    #[test]
    fn csprng_output_differs_even_under_a_constant_platform_rng() {
        poison_platform_rng_for_test(0x41);

        let mut draws = Vec::new();
        for _ in 0..8 {
            let mut buf = [0u8; 32];
            fill(&mut buf).unwrap();
            assert_ne!(buf, [0x41u8; 32], "must not pass the constant through");
            assert_ne!(buf, [0u8; 32]);
            draws.push(buf);
        }

        for i in 0..draws.len() {
            for j in (i + 1)..draws.len() {
                assert_ne!(draws[i], draws[j], "draws {i} and {j} collided");
            }
        }

        restore_platform_rng_for_test();
    }

    /// The honest counterpart: the stream is a function of the seed.
    /// Same poisoned source, fresh CSPRNG state, same stream. Asserted so
    /// the test above is not mistaken for a claim of unpredictability --
    /// poisoning that lands before the first draw is NOT mitigated.
    #[test]
    fn a_known_seed_still_yields_a_known_stream() {
        poison_platform_rng_for_test(0x41);
        let mut first = [0u8; 32];
        fill(&mut first).unwrap();

        poison_platform_rng_for_test(0x41);
        let mut again = [0u8; 32];
        fill(&mut again).unwrap();

        assert_eq!(first, again, "pre-seeding poisoning is not mitigated");

        restore_platform_rng_for_test();
    }

    /// Unpoisoned, it behaves like any CSPRNG.
    #[test]
    fn real_platform_rng_produces_distinct_draws() {
        restore_platform_rng_for_test();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    /// `VaultRng` is a faithful view of `fill`.
    #[test]
    fn vault_rng_draws_are_distinct_under_a_constant_platform_rng() {
        poison_platform_rng_for_test(0xFF);
        let mut rng = VaultRng;
        let x = rng.next_u64();
        let y = rng.next_u64();
        assert_ne!(x, y);
        assert_ne!(x, u64::MAX, "must not pass the constant through");
        restore_platform_rng_for_test();
    }
}
