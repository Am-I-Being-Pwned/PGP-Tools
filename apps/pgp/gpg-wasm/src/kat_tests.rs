//! Known-answer tests for every primitive whose output is persisted.
//!
//! Argon2id derives vault keys, HKDF-SHA256 + AES-256-GCM seal the blobs
//! on users' disks, and AES-CFB decrypts GnuPG secret keys at import. A
//! dependency bump that changed a single output byte of any of them would
//! lock users out of their vaults, so every vector below is pinned:
//!
//! - **Standard vectors** (RFC 5869 HKDF, NIST SP 800-38A CFB128) prove
//!   the primitives are the textbook ones.
//! - **Crate vectors** (Argon2id derivations, sealed-blob layouts, the
//!   contacts / store key schedule) were generated with the RustCrypto
//!   versions this crate shipped with before the 2026-10 major bump
//!   (argon2 0.5.3, aes-gcm 0.10.3, hkdf 0.12.4, sha2 0.10.9, aes 0.8.4,
//!   cfb-mode 0.8.2) and cross-checked against Python `cryptography`
//!   where it has the primitive. They pin the exact bytes this crate
//!   writes and must read back forever.
//!
//! **Never edit an expected value to make a test pass.** A mismatch here
//! means stored vaults/backups would no longer open. All inputs are fixed,
//! synthetic test values -- there is no real key material in this file.

use super::*;
use openpgp::types::SymmetricAlgorithm;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    assert!(s.len() % 2 == 0, "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Run `f` with the platform RNG pinned to `byte`, so the CSPRNG (and
/// therefore every salt / IV this crate draws) is a fixed stream.
fn with_fixed_rng<T>(byte: u8, f: impl FnOnce() -> T) -> T {
    rng::poison_platform_rng_for_test(byte);
    let out = f();
    rng::restore_platform_rng_for_test();
    out
}

const PASSWORD: &[u8] = b"correct horse battery staple";
const SALT: &[u8] = b"0123456789abcdef";

// ── Argon2id ─────────────────────────────────────────────────────────

#[test]
fn kat_argon2id_test_params() {
    let key = argon2_derive(PASSWORD, SALT, 4096, 3, 1).unwrap();
    assert_eq!(
        hex(&key),
        "2f8186f7b07132513ebb79a01833cb875faee5432f2c21d0093c70202b339837"
    );
}

/// The parameters the extension actually ships with
/// (`lib/protection/password-kdf.ts`: 64 MiB, 3 passes, 1 lane).
#[test]
fn kat_argon2id_production_params() {
    let key = argon2_derive(PASSWORD, SALT, 65536, 3, 1).unwrap();
    assert_eq!(
        hex(&key),
        "94c86f541abdb3d9aabfea59aa03963549483e9c0b1a79336e76b54cee6c917e"
    );
}

/// Multi-lane, longer salt, single pass: exercises the lane/segment
/// indexing a 1-lane vector cannot reach.
#[test]
fn kat_argon2id_multi_lane() {
    let salt = b"a-longer-salt-of-32-bytes-exact!";
    let key = argon2_derive(b"pw", salt, 1024, 1, 4).unwrap();
    assert_eq!(
        hex(&key),
        "68a1672c65594f0bf6374ba9579570c39d43e9db44a584d2661a3f9cd0f8fe72"
    );
}

// ── HKDF-SHA256 ──────────────────────────────────────────────────────

/// RFC 5869 Appendix A.1 (Test Case 1). Our wrappers emit 32 bytes, which
/// is the first 32 bytes of the RFC's 42-byte OKM.
#[test]
fn kat_hkdf_rfc5869_case1() {
    let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = unhex("000102030405060708090a0b0c");
    let info = unhex("f0f1f2f3f4f5f6f7f8f9");
    let okm = protected::hkdf_derive(&ikm, &salt, &info).unwrap();
    assert_eq!(
        hex(&okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    );
}

#[test]
fn kat_contacts_key_from_prf() {
    let key = derive_contacts_key(&[0x11; 32], &[0x22; 32]).unwrap();
    assert_eq!(
        hex(&key),
        "0c05c1e11955eee1b47d416f2bbdfa3481f944004fc2cfa532e99e962a139aca"
    );
}

/// Argon2id output fed into HKDF with the same salt: the password-unlock
/// contacts key schedule end to end.
#[test]
fn kat_contacts_key_from_password() {
    let key = derive_contacts_key_from_password(PASSWORD, SALT, 4096, 3, 1).unwrap();
    assert_eq!(
        hex(&key),
        "034d85e835929c62631fbeb2d31bf79b8247b0e1383adcb0f55dbaf311facdc7"
    );
}

// ── AES-256-GCM ──────────────────────────────────────────────────────

const GCM_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const GCM_IV: &str = "cafebabefacedbaddecaf888";
const GCM_AAD: &[u8] = b"gpg-tools:password:KAT";
const GCM_PT: &[u8] = b"known-answer plaintext, longer than one AES block";
const GCM_CT: &str = "e1cdcf51c4572e75357c38af5b6de55e644eb434a76d465422b06a16dbfb458b\
         c531af66aeba2c42671e7b4850ef4f0632cbac8e7428d2d3972f1a76eca92835\
         b0";

#[test]
fn kat_aes_gcm_decrypt() {
    let pt = aes_gcm_decrypt(&unhex(GCM_KEY), &unhex(GCM_IV), &unhex(GCM_CT), GCM_AAD).unwrap();
    assert_eq!(pt, GCM_PT);

    // Same bytes, wrong AAD: must fail the tag check.
    assert!(aes_gcm_decrypt(&unhex(GCM_KEY), &unhex(GCM_IV), &unhex(GCM_CT), b"other").is_err());
}

/// `aes_gcm_encrypt` draws its IV from the crate CSPRNG; pinned, the whole
/// `[iv][ct||tag]` output is a fixed string.
#[test]
fn kat_aes_gcm_encrypt_fixed_rng() {
    let out = with_fixed_rng(0x5a, || {
        aes_gcm_encrypt(&unhex(GCM_KEY), GCM_PT, GCM_AAD).unwrap()
    });
    assert_eq!(
        hex(&out),
        "570416449232bd07fdecc45c0eb8bf55a07961034f68cd168ce03e06e88b1c6d\
         2dd075aa586aa4515cb1ab8ab178872993cf9d773b0d43cee4efe63a02374dff\
         cce51a27ea346eca88ce99fb80"
    );
}

// ── Sealed blobs (wire formats in protected.rs) ──────────────────────

/// `[16 salt][12 iv][ct||tag]` under Argon2id. Pinned RNG fixes salt + iv.
#[test]
fn kat_seal_with_password_blob() {
    let blob = with_fixed_rng(0x33, || {
        protected::seal_with_password(GCM_PT, "KAT-ID", PASSWORD_AAD_PREFIX, PASSWORD, 4096, 3, 1)
            .unwrap()
    });
    assert_eq!(
        hex(&blob),
        "7754de54ddddd532b3e7c6749833becb99ccfe46c7384610f73b62752b757d63\
         f1026d7a9eb72abfb2ac7db87c8da061c4cb09e23c31acda7311d9dab95f28b2\
         a30d8e4b5b7922d513ddcdb3fc355555276f82fd43e26773fac2f02741"
    );

    let opened = protected::open_with_password(
        &blob[28..],
        &blob[16..28],
        &blob[..16],
        "KAT-ID",
        PASSWORD_AAD_PREFIX,
        PASSWORD,
        4096,
        3,
        1,
    )
    .unwrap();
    assert_eq!(opened.as_slice(), GCM_PT);
}

/// `[12 iv][ct||tag]` under HKDF(PRF, storedSecret).
#[test]
fn kat_seal_with_prf_blob() {
    let blob = with_fixed_rng(0x44, || {
        protected::seal_with_prf(
            GCM_PT,
            "KAT-ID",
            PASSKEY_AAD_PREFIX,
            PASSKEY_HKDF_INFO,
            &[0x11; 32],
            &[0x22; 32],
        )
        .unwrap()
    });
    assert_eq!(
        hex(&blob),
        "73a448384bab47d419f52711e66d539094557a0e89e117449aff2dbffa64b1ed\
         ad451d40a2ae8aaea790af8978c9847ff1b6ee9724e856584f2a4e626ae3dc05\
         ab88d49d57417618dea3f30163"
    );

    let opened = protected::open_with_prf(
        &blob[12..],
        &blob[..12],
        "KAT-ID",
        PASSKEY_AAD_PREFIX,
        PASSKEY_HKDF_INFO,
        &[0x11; 32],
        &[0x22; 32],
    )
    .unwrap();
    assert_eq!(opened.as_slice(), GCM_PT);
}

/// Contacts session key -> HKDF store subkey -> AES-GCM, i.e. the
/// `encryptStore` / `decryptStore` path history and backups use.
#[test]
fn kat_store_envelope() {
    init_contacts_session_with_prf(vec![0x11; 32], vec![0x22; 32]).unwrap();
    let blob = with_fixed_rng(0x66, || {
        encrypt_store("kat-domain", GCM_PT.to_vec()).unwrap()
    });
    let opened = decrypt_store("kat-domain", &blob[12..], &blob[..12]);
    drop_contacts_session();

    assert_eq!(
        hex(&blob),
        "c0579fdc21c3e1338c85757ffad8b6805ff8ec8c27950e16d0341519a679d1a9\
         344af23cb6091009498f0671df99ca011d6fbf4cb4edf9c47cbe3f20e677514d\
         e4927890828b901e9c32e28357"
    );
    assert_eq!(opened.unwrap(), GCM_PT);
}

// ── AES-CFB128 (GnuPG secret-key fallback) ───────────────────────────

const SP800_38A_PT: &str = "6bc1bee22e409f96e93d7e117393172a\
                            ae2d8a571e03ac9c9eb76fac45af8e51\
                            30c81c46a35ce411e5fbc1191a0a52ef\
                            f69f2445df4f9b17ad2b417be66c3710";
const SP800_38A_IV: &str = "000102030405060708090a0b0c0d0e0f";

/// NIST SP 800-38A F.3.14 / F.3.16 / F.3.18 (CFB128-AES{128,192,256}.Decrypt).
#[test]
fn kat_cfb128_sp800_38a() {
    let cases = [
        (
            SymmetricAlgorithm::AES128,
            "2b7e151628aed2a6abf7158809cf4f3c",
            "3b3fd92eb72dad20333449f8e83cfb4a\
             c8a64537a0b3a93fcde3cdad9f1ce58b\
             26751f67a3cbb140b1808cf187a4f4df\
             c04b05357c5d1c0eeac4c66f9ff7f2e6",
        ),
        (
            SymmetricAlgorithm::AES192,
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            "cdc80d6fddf18cab34c25909c99a4174\
             67ce7f7f81173621961a2b70171d3d7a\
             2e1e8a1dd59b88b1c8e60fed1efac4c9\
             c05f9f9ca9834fa042ae8fba584b09ff",
        ),
        (
            SymmetricAlgorithm::AES256,
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            "dc7e84bfda79164b7ecd8486985d3860\
             39ffed143b28b1c832113c6331e5407b\
             df10132415e54b92a13ed0a8267ae2f9\
             75a385741ab9cef82031623d55b1e471",
        ),
    ];
    for (sym, key, ct) in cases {
        let pt = cfb_decrypt(sym, &unhex(key), &unhex(SP800_38A_IV), &unhex(ct)).unwrap();
        assert_eq!(hex(&pt), hex(&unhex(SP800_38A_PT)), "{sym}");
    }
}

/// GnuPG secret-key ciphertext is rarely block-aligned: 37 bytes leaves a
/// 5-byte partial final block that the mode must handle identically.
#[test]
fn kat_cfb128_partial_block() {
    let key = unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    let pt = cfb_decrypt(
        SymmetricAlgorithm::AES256,
        &key,
        &unhex(SP800_38A_IV),
        &unhex(
            "c3d7532f8040a4aef2869ff9cbac563eab743e35eefcfbf3d20e6f185102af78\
         a6f273cc6e",
        ),
    )
    .unwrap();
    assert_eq!(pt, b"thirty-seven bytes of GnuPG secrets!!");
}
