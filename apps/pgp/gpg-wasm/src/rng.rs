//! Randomness for the paths this crate controls (T-ENTROPY-POISON, SECURITY.md §8.10).
//!
//! `getrandom` resolves `crypto.getRandomValues` per call, so a realm that
//! replaces it owns every byte. Nothing in WASM can close that; instead the
//! platform RNG is read once to seed a ChaCha20 CSPRNG, so later poisoning
//! cannot cause repeated nonces, salts or keys. Poisoning before the first
//! draw is not mitigated.
//!
//! Covers GCM nonces, Argon2id salts, the draft session key and CRX RSA
//! keygen. Not OpenPGP keygen: Sequoia hard-codes `OsRng` with no injection point.
//!
//! Never reseeded: a reseed re-reads the source this exists to avoid, and
//! from a poisoned source replaces good state with attacker-chosen state.

use std::cell::RefCell;

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use zeroize::Zeroizing;

thread_local! {
    /// Seeded lazily on first use, then never reseeded.
    static CSPRNG: RefCell<Option<ChaCha20Rng>> = const { RefCell::new(None) };

    /// Test-only stand-in for a poisoned `getRandomValues` returning a constant.
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

/// Fill `dest` with CSPRNG output.
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
        // A CSPRNG failure in a browser is unrecoverable.
        fill(dest).expect("CSPRNG failed");
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for VaultRng {}

/// Simulate a constant-byte `getRandomValues` and clear CSPRNG state so the
/// next draw reseeds from it.
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

/// Read the simulated platform source directly, bypassing the CSPRNG.
#[cfg(test)]
pub(crate) fn platform_fill_for_test(dest: &mut [u8]) -> Result<(), String> {
    platform_fill(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Baseline: under a poisoned platform RNG every buffer is identical.
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

    /// Seeded once from that same source, the CSPRNG still emits distinct output.
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

    /// The stream is a function of the seed: poisoning before the first draw is
    /// NOT mitigated.
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
