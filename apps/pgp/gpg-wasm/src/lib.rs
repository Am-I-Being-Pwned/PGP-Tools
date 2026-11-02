//! # GPG Tools - Sequoia-PGP WASM Module
//!
//! The WASM/Rust trust boundary: every cryptographic operation lives in this
//! crate. Auditors start at `apps/pgp/SECURITY.md`. JS reaches it only through
//! `lib/pgp/wasm-public.ts` (no secrets) and `lib/pgp/wasm-secrets.ts` (secrets,
//! per-function zeroize contracts).
//!
//! Invariants:
//! - Private keys live in WASM memory (`KEY_STORE`, zeroized on drop); JS holds
//!   only integer handles.
//! - `KEY_STORE` is populated **only** by the unlock paths (`unlockWithPassword`,
//!   `unlockWithPrf`). Generate/import hold the plaintext cert for one call and
//!   return a protected blob; it never enters the store.
//! - Sign/encrypt/decrypt rematerialize a transient `Cert` per call.
//! - Armored secret material crosses to JS only via `getKeyArmored` (destructive
//!   export UI).
//! - Verification never aborts: every signature is classified and a bad one
//!   anywhere yields "invalid", so the UI withholds the plaintext.
//! - Constant-time caveat: WASM needs `allow-variable-time-crypto`; browser
//!   sandboxing is the mitigation.

use std::alloc::{GlobalAlloc, Layout, System};

/// Zeroize-on-free global allocator.
///
/// Freed WASM memory is not cleared, so plaintext freed across the
/// wasm-bindgen ABI (where `Drop`/`Zeroizing` can't reach, e.g. a returned
/// `Vec<u8>` freed by `__wbindgen_free`) would linger. Wiping every block on
/// `dealloc` covers that without relying on each call site. `realloc` stays
/// the trait default (alloc + copy + dealloc) so a moved block is wiped too.
struct ZeroizeOnFree;

unsafe impl GlobalAlloc for ZeroizeOnFree {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        #[cfg(test)]
        alloc_meter::track(layout.size() as isize);
        System.alloc(layout)
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        #[cfg(test)]
        alloc_meter::track(layout.size() as isize);
        System.alloc_zeroed(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        #[cfg(test)]
        alloc_meter::track(-(layout.size() as isize));
        std::ptr::write_bytes(ptr, 0, layout.size());
        System.dealloc(ptr, layout);
    }
}

/// Test-only per-thread peak-live-heap meter, to bound Sequoia's read-ahead.
/// Const-initialised cells with no destructor: touching them must not
/// allocate (that would recurse into the allocator).
#[cfg(test)]
mod alloc_meter {
    use std::cell::Cell;

    thread_local! {
        static LIVE: Cell<isize> = const { Cell::new(0) };
        static PEAK: Cell<isize> = const { Cell::new(0) };
    }

    pub(crate) fn track(delta: isize) {
        let _ = LIVE.try_with(|live| {
            let now = live.get() + delta;
            live.set(now);
            let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
        });
    }

    /// Run `f`, returning its result and the most it held live at once
    /// above what was live when it started.
    pub(crate) fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize) {
        let base = LIVE.with(Cell::get);
        PEAK.with(|peak| peak.set(base));
        let out = f();
        (out, (PEAK.with(Cell::get) - base).max(0) as usize)
    }
}

#[global_allocator]
static GLOBAL: ZeroizeOnFree = ZeroizeOnFree;

use openpgp::policy::{HashAlgoSecurity, StandardPolicy};
use openpgp::types::HashAlgorithm;
use sequoia_openpgp as openpgp;
use std::sync::OnceLock;

/// The policy gating every key operation: `StandardPolicy` relaxed only to
/// accept SHA-1 in *binding* signatures, which need second-preimage
/// resistance (still intact) rather than collision resistance (broken).
/// Data signatures and certifications stay on the hardened default. Keys
/// that rely on it get a `securityWarning` (see `strict_policy`).
fn policy() -> &'static StandardPolicy<'static> {
    static POLICY: OnceLock<StandardPolicy<'static>> = OnceLock::new();
    POLICY.get_or_init(|| {
        let mut p = StandardPolicy::new();
        p.accept_hash_property(
            HashAlgorithm::SHA1,
            HashAlgoSecurity::SecondPreImageResistance,
        );
        p
    })
}

/// Sequoia's hardened defaults. Only used to *detect* weak crypto for a
/// warning -- never to gate an operation.
fn strict_policy() -> &'static StandardPolicy<'static> {
    static STRICT: OnceLock<StandardPolicy<'static>> = OnceLock::new();
    STRICT.get_or_init(StandardPolicy::new)
}

trait StrErr<T> {
    fn str_err(self) -> Result<T, String>;
}
impl<T, E: std::fmt::Display> StrErr<T> for Result<T, E> {
    fn str_err(self) -> Result<T, String> {
        self.map_err(|e| e.to_string())
    }
}

mod aead;
mod certs;
mod decrypt;
mod encryption;
mod key_store;
mod limits;
mod protect;
mod s2k;
mod sanitize;
mod sessions;
mod sign;

pub(crate) use aead::*;
pub use certs::*;
pub use decrypt::*;
pub use encryption::*;
pub use key_store::*;
pub use limits::*;
pub use protect::*;
pub(crate) use s2k::*;
pub(crate) use sanitize::*;
pub use sessions::*;
pub use sign::*;

/// At-rest key-protection envelope shared by every key type (see module header).
mod protected;

/// CRX signing & verification; see the module header for why CRX3 isn't OpenPGP.
mod crx;

/// age encryption to imported SSH keys; see the module header.
mod age;

/// Stable codes on the errors the UI tells apart.
mod error_code;
use error_code::{coded, ErrorCode};

/// ChaCha20 CSPRNG seeded once from `crypto.getRandomValues` (T-ENTROPY-POISON).
mod rng;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod kat_tests;

#[cfg(test)]
mod trust_tests;
