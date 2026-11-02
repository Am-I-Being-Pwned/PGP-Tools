use super::*;
// The test decrypt helpers bypass `protected::open_*`, so they scrub their own key.
use zeroize::Zeroize;

#[test]
fn crx_embeds_the_input_archive_verbatim() {
    // The bytes after the prefix + header must be the untouched input archive.
    let key = generate_rsa2048().unwrap();
    let zip = b"PK\x03\x04 example archive bytes standing in for a real zip";
    let crx = assemble_crx(zip, &key).unwrap();
    assert_eq!(&crx[0..4], CRX_MAGIC);
    assert_eq!(read_u32_le(&crx, 4).unwrap(), CRX_VERSION);
    let header_size = read_u32_le(&crx, 8).unwrap() as usize;
    assert_eq!(&crx[12 + header_size..], &zip[..]);
}

#[test]
fn sign_verify_round_trip() {
    let key = generate_rsa2048().unwrap();
    let zip = b"PK\x03\x04 pretend this is a zipped extension";
    let crx = assemble_crx(zip, &key).unwrap();

    assert_eq!(&crx[0..4], CRX_MAGIC);
    assert_eq!(read_u32_le(&crx, 4).unwrap(), CRX_VERSION);

    let outcome = verify_crx_inner(&crx);
    assert!(outcome.valid, "error: {:?}", outcome.error);

    let id = outcome.extension_id.unwrap();
    assert_eq!(id.len(), 32);
    assert!(id.chars().all(|c| ('a'..='p').contains(&c)));
    assert_eq!(outcome.algorithm.as_deref(), Some("sha256_with_rsa"));
}

#[test]
fn tampered_payload_fails_verification() {
    let key = generate_rsa2048().unwrap();
    let crx = assemble_crx(b"original archive bytes", &key).unwrap();

    let mut tampered = crx.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff; // flip a byte of the ZIP payload

    let outcome = verify_crx_inner(&tampered);
    assert!(!outcome.valid);
    assert!(outcome.extension_id.is_some());
    assert_eq!(
        crate::error_code::error_code(outcome.error.as_deref().unwrap()),
        Some(ErrorCode::CrxUnsigned),
    );
}

#[test]
fn extension_id_and_signature_are_deterministic() {
    let key = generate_rsa2048().unwrap();
    let a = assemble_crx(b"same bytes", &key).unwrap();
    let b = assemble_crx(b"same bytes", &key).unwrap();
    // Unblinded PKCS#1 v1.5 over identical input is byte-identical.
    assert_eq!(a, b);
}

#[test]
fn extension_id_matches_derived_id() {
    let key = generate_rsa2048().unwrap();
    let spki = spki_der(&key).unwrap();
    let expected = extension_id(&crx_id_from_spki(&spki));
    let outcome = verify_crx_inner(&assemble_crx(b"x", &key).unwrap());
    assert_eq!(outcome.extension_id.as_deref(), Some(expected.as_str()));
}

#[test]
fn not_a_crx_is_reported_cleanly() {
    let outcome = verify_crx_inner(b"definitely not a crx");
    assert!(!outcome.valid);
    let err = outcome.error.unwrap();
    assert!(err.contains("Cr24"));
    assert_eq!(crate::error_code::error_code(&err), Some(ErrorCode::NotCrx));
}

#[test]
fn pkcs8_round_trips_through_der() {
    let key = generate_rsa2048().unwrap();
    let der = private_key_der(&key).unwrap();
    let ext_id = extension_id(&crx_id_from_spki(&spki_der(&key).unwrap()));
    let handle = store_decrypted_der(der, &ext_id).unwrap();
    let reloaded = crx_store_get(handle).unwrap();
    drop_crx_key(handle).unwrap();
    assert_eq!(spki_der(&key).unwrap(), spki_der(&reloaded).unwrap());
}

#[test]
fn unlock_rejects_key_that_does_not_match_extension_id() {
    // AAD strings are public: a foreign key sealed under a victim's id must be
    // refused at store time.
    let key_a = generate_rsa2048().unwrap();
    let key_b = generate_rsa2048().unwrap();
    let ext_id_a = extension_id(&crx_id_from_spki(&spki_der(&key_a).unwrap()));
    let der_b = private_key_der(&key_b).unwrap();

    let result = store_decrypted_der(der_b, &ext_id_a);
    assert!(result.is_err(), "foreign key under ext id A must be refused");
    assert!(result.unwrap_err().contains("does not belong"));
}

/// Assemble a raw CRX3 from a pre-encoded header (for headers `assemble_crx` never makes).
fn raw_crx(header: &[u8], archive: &[u8]) -> Vec<u8> {
    let mut crx = Vec::new();
    crx.extend_from_slice(CRX_MAGIC);
    crx.extend_from_slice(&CRX_VERSION.to_le_bytes());
    crx.extend_from_slice(&(header.len() as u32).to_le_bytes());
    crx.extend_from_slice(header);
    crx.extend_from_slice(archive);
    crx
}

#[test]
fn imports_pkcs8_and_pkcs1_pem_to_same_extension_id() {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::pkcs8::LineEnding;

    let key = generate_rsa2048().unwrap();
    let expected = extension_id(&crx_id_from_spki(&spki_der(&key).unwrap()));

    let pkcs8_pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let pkcs1_pem = key.to_pkcs1_pem(LineEnding::LF).unwrap();

    let from_pkcs8 = parse_rsa_private_pem(&pkcs8_pem).unwrap();
    let from_pkcs1 = parse_rsa_private_pem(&pkcs1_pem).unwrap();

    let id_pkcs8 = extension_id(&crx_id_from_spki(&spki_der(&from_pkcs8).unwrap()));
    let id_pkcs1 = extension_id(&crx_id_from_spki(&spki_der(&from_pkcs1).unwrap()));

    assert_eq!(id_pkcs8, expected);
    assert_eq!(id_pkcs1, expected);
}

#[test]
fn rejects_valid_signature_with_mismatched_identity() {
    // A genuine signature by key B under a header claiming key A's identity.
    let key_a = generate_rsa2048().unwrap();
    let key_b = generate_rsa2048().unwrap();

    let spki_b = spki_der(&key_b).unwrap();
    let crx_id_a = crx_id_from_spki(&spki_der(&key_a).unwrap());

    let signed_data = encode_signed_data(&crx_id_a);
    let archive = b"spoofed identity archive";
    let digest = Sha256::digest(signing_payload(&signed_data, archive));
    let sig_b = key_b
        .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
        .unwrap();
    // The proof carries B's SPKI, which hashes to B's id, not A's.
    let proof = encode_proof(&spki_b, &sig_b);
    let header = encode_header(&proof, &signed_data);
    let crx = raw_crx(&header, archive);

    let outcome = verify_crx_inner(&crx);
    assert!(!outcome.valid, "mismatched pubkey/crx_id must not verify");
    // Still reports the identity the CRX claims (A).
    assert_eq!(
        outcome.extension_id.as_deref(),
        Some(extension_id(&crx_id_a).as_str())
    );
}

#[test]
fn spliced_public_key_fails_verification() {
    // Splice key B's SPKI over key A's in a valid CRX (same length).
    let key_a = generate_rsa2048().unwrap();
    let key_b = generate_rsa2048().unwrap();
    let spki_a = spki_der(&key_a).unwrap();
    let spki_b = spki_der(&key_b).unwrap();
    assert_eq!(spki_a.len(), spki_b.len());

    let crx = assemble_crx(b"legit archive", &key_a).unwrap();
    assert!(verify_crx_inner(&crx).valid);

    let pos = crx
        .windows(spki_a.len())
        .position(|w| w == spki_a.as_slice())
        .expect("SPKI must appear in the CRX header");
    let mut tampered = crx.clone();
    tampered[pos..pos + spki_b.len()].copy_from_slice(&spki_b);

    assert!(
        !verify_crx_inner(&tampered).valid,
        "swapping in a foreign public key must invalidate the CRX"
    );
}

#[test]
fn malformed_inputs_never_panic() {
    // Each must yield valid:false, never a panic.
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        CRX_MAGIC.to_vec(),
        // Header-length field truncated.
        {
            let mut v = CRX_MAGIC.to_vec();
            v.extend_from_slice(&CRX_VERSION.to_le_bytes());
            v.push(0x01);
            v
        },
        {
            let mut v = CRX_MAGIC.to_vec();
            v.extend_from_slice(&CRX_VERSION.to_le_bytes());
            v.extend_from_slice(&u32::MAX.to_le_bytes());
            v
        },
        raw_crx(&[0xffu8; 32], b"archive"),
    ];

    for case in cases {
        let outcome = verify_crx_inner(&case);
        assert!(!outcome.valid);
        assert!(outcome.error.is_some());
    }
}

#[test]
fn empty_and_large_archives_round_trip() {
    let key = generate_rsa2048().unwrap();

    let empty = assemble_crx(b"", &key).unwrap();
    assert!(verify_crx_inner(&empty).valid, "empty archive must verify");

    let large: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    let big = assemble_crx(&large, &key).unwrap();
    assert!(verify_crx_inner(&big).valid, "100 KB archive must verify");
}

/// Cheapest Argon2 params the crate allows; these tests exercise AAD/identity, not the KDF.
const TEST_ARGON2_MEM: u32 = 8;
const TEST_ARGON2_ITERS: u32 = 1;
const TEST_ARGON2_PAR: u32 = 1;

/// Split packed `[u32_le json_len][json][blob]` as the JS side does.
fn unpack_meta_blob(packed: &[u8]) -> (serde_json::Value, Vec<u8>) {
    let json_len = u32::from_le_bytes([packed[0], packed[1], packed[2], packed[3]]) as usize;
    let json = &packed[4..4 + json_len];
    let blob = packed[4 + json_len..].to_vec();
    (serde_json::from_slice(json).unwrap(), blob)
}

/// Decrypt a password blob as `unlock_crx_with_password` does; returns the DER.
fn decrypt_password_blob(
    blob: &[u8],
    ext_id: &str,
    password: &[u8],
) -> Result<Vec<u8>, String> {
    let salt = &blob[0..16];
    let iv = &blob[16..28];
    let ct = &blob[28..];
    let mut derived = crate::argon2_derive(
        password,
        salt,
        TEST_ARGON2_MEM,
        TEST_ARGON2_ITERS,
        TEST_ARGON2_PAR,
    )
    .unwrap();
    let aad = format!("{CRX_PASSWORD_AAD_PREFIX}{ext_id}");
    let result = crate::aes_gcm_decrypt(&derived, iv, ct, aad.as_bytes());
    derived.zeroize();
    result
}

/// Generate a key into `CRX_KEY_STORE`; returns handle, extension id and SPKI.
fn insert_generated_key() -> (u32, String, Vec<u8>) {
    let key = generate_rsa2048().unwrap();
    let spki = spki_der(&key).unwrap();
    let ext_id = extension_id(&crx_id_from_spki(&spki));
    let der = private_key_der(&key).unwrap();
    let handle = CRX_KEY_STORE.with(|store| store.insert(der)).unwrap();
    (handle, ext_id, spki)
}

#[test]
fn reprotect_round_trips_and_recovers_the_same_key() {
    let (handle, ext_id, spki) = insert_generated_key();
    let password = b"correct horse battery staple";

    let packed = reprotect_crx_key_with_password(
        handle,
        password.to_vec(),
        TEST_ARGON2_MEM,
        TEST_ARGON2_ITERS,
        TEST_ARGON2_PAR,
    )
    .unwrap();
    drop_crx_key(handle).unwrap();

    let (meta, blob) = unpack_meta_blob(&packed);

    assert_eq!(meta["extensionId"], ext_id);
    assert_eq!(meta["publicKeyDerB64"], B64.encode(&spki));
    assert_eq!(meta["algorithm"], "rsa2048");

    // 16 salt + 12 iv + ciphertext (with its 16-byte tag).
    assert!(blob.len() > 16 + 12, "blob too short to hold salt+iv+ct");

    let der = decrypt_password_blob(&blob, &ext_id, password).unwrap();
    let recovered = RsaPrivateKey::from_pkcs8_der(&der).unwrap();
    let recovered_spki = spki_der(&recovered).unwrap();
    assert_eq!(recovered_spki, spki, "recovered public key must match");
    assert_eq!(
        extension_id(&crx_id_from_spki(&recovered_spki)),
        ext_id,
        "recovered extension id must match"
    );
}

#[test]
fn reprotect_wrong_password_fails_to_decrypt() {
    let (handle, ext_id, _spki) = insert_generated_key();

    let packed = reprotect_crx_key_with_password(
        handle,
        b"the right password".to_vec(),
        TEST_ARGON2_MEM,
        TEST_ARGON2_ITERS,
        TEST_ARGON2_PAR,
    )
    .unwrap();
    drop_crx_key(handle).unwrap();

    let (_meta, blob) = unpack_meta_blob(&packed);

    let result = decrypt_password_blob(&blob, &ext_id, b"the wrong password");
    assert!(result.is_err(), "wrong password must fail the GCM tag check");
}

#[test]
fn reprotect_wrong_extension_id_aad_fails() {
    // AAD binds to the extension id: a different id must fail even with the right password.
    let (handle, _ext_id, _spki) = insert_generated_key();

    let packed = reprotect_crx_key_with_password(
        handle,
        b"a decent password".to_vec(),
        TEST_ARGON2_MEM,
        TEST_ARGON2_ITERS,
        TEST_ARGON2_PAR,
    )
    .unwrap();
    drop_crx_key(handle).unwrap();

    let (_meta, blob) = unpack_meta_blob(&packed);
    let result = decrypt_password_blob(
        &blob,
        "abcdefghijklmnopabcdefghijklmnop",
        b"a decent password",
    );
    assert!(result.is_err(), "mismatched AAD (ext id) must fail");
}

#[test]
fn reprotect_absent_handle_returns_err_not_panic() {
    let result = reprotect_crx_key_with_password(
        0xDEAD_BEEF,
        b"whatever password".to_vec(),
        TEST_ARGON2_MEM,
        TEST_ARGON2_ITERS,
        TEST_ARGON2_PAR,
    );
    assert!(result.is_err(), "bogus handle must be an Err, not a panic");
}

#[test]
fn reprotect_identity_is_deterministic_but_randomness_is_fresh() {
    let (handle, ext_id, _spki) = insert_generated_key();
    let password = b"same password twice";

    let packed_a = reprotect_crx_key_with_password(
        handle,
        password.to_vec(),
        TEST_ARGON2_MEM,
        TEST_ARGON2_ITERS,
        TEST_ARGON2_PAR,
    )
    .unwrap();
    let packed_b = reprotect_crx_key_with_password(
        handle,
        password.to_vec(),
        TEST_ARGON2_MEM,
        TEST_ARGON2_ITERS,
        TEST_ARGON2_PAR,
    )
    .unwrap();
    drop_crx_key(handle).unwrap();

    let (meta_a, blob_a) = unpack_meta_blob(&packed_a);
    let (meta_b, blob_b) = unpack_meta_blob(&packed_b);

    assert_eq!(meta_a["extensionId"], ext_id);
    assert_eq!(meta_a["extensionId"], meta_b["extensionId"]);
    assert_eq!(meta_a["publicKeyDerB64"], meta_b["publicKeyDerB64"]);

    // Salt and iv are fresh per seal.
    assert_ne!(&blob_a[0..16], &blob_b[0..16], "salt must be fresh");
    assert_ne!(&blob_a[16..28], &blob_b[16..28], "iv must be fresh");
    assert_ne!(blob_a, blob_b, "re-seal must not be byte-identical");

    let der_a = decrypt_password_blob(&blob_a, &ext_id, password).unwrap();
    let der_b = decrypt_password_blob(&blob_b, &ext_id, password).unwrap();
    let spki_a = spki_der(&RsaPrivateKey::from_pkcs8_der(&der_a).unwrap()).unwrap();
    let spki_b = spki_der(&RsaPrivateKey::from_pkcs8_der(&der_b).unwrap()).unwrap();
    assert_eq!(spki_a, spki_b);
}

#[test]
fn export_pem_round_trips_to_the_same_key() {
    let (handle, ext_id, spki) = insert_generated_key();

    let pem = export_crx_private_key_pem(handle).unwrap();
    drop_crx_key(handle).unwrap();

    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    let recovered = parse_rsa_private_pem(&pem).unwrap();
    let recovered_spki = spki_der(&recovered).unwrap();
    assert_eq!(recovered_spki, spki, "exported PEM must be the same key");
    assert_eq!(
        extension_id(&crx_id_from_spki(&recovered_spki)),
        ext_id,
        "extension identity must survive the export"
    );
}

// Entropy under a constant platform RNG (src/rng.rs).

/// With `getRandomValues` pinned to a constant, two keygens still diverge.
#[test]
fn constant_platform_rng_no_longer_yields_identical_rsa_keys() {
    crate::rng::poison_platform_rng_for_test(0x41);

    let key_a = generate_rsa2048().unwrap();
    let spki_a = spki_der(&key_a).unwrap();

    // The CSPRNG keeps advancing (not reseeded), so the second keygen differs.
    let key_b = generate_rsa2048().unwrap();
    let spki_b = spki_der(&key_b).unwrap();

    crate::rng::restore_platform_rng_for_test();

    assert_ne!(
        spki_a, spki_b,
        "two keygens under a constant platform RNG must not collide"
    );
    assert_ne!(
        extension_id(&crx_id_from_spki(&spki_a)),
        extension_id(&crx_id_from_spki(&spki_b)),
    );
}

/// Salt and GCM nonce stay fresh under a constant platform RNG (nonce reuse
/// under one key is catastrophic).
#[test]
fn constant_platform_rng_no_longer_yields_repeated_salt_or_nonce() {
    let (handle, ext_id, _spki) = insert_generated_key();
    let password = b"same password twice";

    crate::rng::poison_platform_rng_for_test(0x00);

    let packed_a = reprotect_crx_key_with_password(
        handle,
        password.to_vec(),
        TEST_ARGON2_MEM,
        TEST_ARGON2_ITERS,
        TEST_ARGON2_PAR,
    )
    .unwrap();
    let packed_b = reprotect_crx_key_with_password(
        handle,
        password.to_vec(),
        TEST_ARGON2_MEM,
        TEST_ARGON2_ITERS,
        TEST_ARGON2_PAR,
    )
    .unwrap();
    drop_crx_key(handle).unwrap();
    crate::rng::restore_platform_rng_for_test();

    let (_meta_a, blob_a) = unpack_meta_blob(&packed_a);
    let (_meta_b, blob_b) = unpack_meta_blob(&packed_b);

    assert_ne!(&blob_a[0..16], &blob_b[0..16], "salt must still be fresh");
    assert_ne!(&blob_a[16..28], &blob_b[16..28], "iv must still be fresh");
    assert_ne!(&blob_a[0..16], &[0u8; 16], "must not pass the constant through");
    assert_ne!(&blob_a[16..28], &[0u8; 12], "must not pass the constant through");

    let der_a = decrypt_password_blob(&blob_a, &ext_id, password).unwrap();
    let der_b = decrypt_password_blob(&blob_b, &ext_id, password).unwrap();
    assert_eq!(der_a, der_b);
}

#[test]
fn export_pem_absent_handle_returns_err_not_panic() {
    let result = export_crx_private_key_pem(0xDEAD_BEEF);
    assert!(result.is_err(), "bogus handle must be an Err, not a panic");
}

/// Seal/open round-trips through the real exports, not the test helper.
#[test]
fn import_then_unlock_round_trips_through_the_real_exports() {
    let key = generate_rsa2048().unwrap();
    let spki = spki_der(&key).unwrap();
    let ext_id = extension_id(&crx_id_from_spki(&spki));
    let pem = key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap()
        .to_string();

    let packed = import_crx_key_with_password(
        &pem,
        b"correct horse battery staple".to_vec(),
        TEST_ARGON2_MEM,
        TEST_ARGON2_ITERS,
        TEST_ARGON2_PAR,
    )
    .unwrap();
    let (meta, blob) = unpack_meta_blob(&packed);
    assert_eq!(meta["extensionId"], ext_id);

    let handle = unlock_crx_with_password(
        &blob[28..],
        &blob[16..28],
        &blob[0..16],
        &ext_id,
        b"correct horse battery staple".to_vec(),
        TEST_ARGON2_MEM,
        TEST_ARGON2_ITERS,
        TEST_ARGON2_PAR,
    )
    .unwrap();
    let recovered = crx_store_get(handle).unwrap();
    drop_crx_key(handle).unwrap();
    assert_eq!(spki_der(&recovered).unwrap(), spki);

    assert!(
        unlock_crx_with_password(
            &blob[28..],
            &blob[16..28],
            &blob[0..16],
            &ext_id,
            b"not the password".to_vec(),
            TEST_ARGON2_MEM,
            TEST_ARGON2_ITERS,
            TEST_ARGON2_PAR,
        )
        .is_err(),
        "wrong password must fail"
    );
}

/// Frozen at-rest fixture from before `unlock_crx_with_*` took owned params.
/// If this fails, the at-rest format changed and every stored CRX key is unreadable.
#[test]
fn a_blob_sealed_before_the_owned_param_change_still_unlocks() {
    // Emitted by `import_crx_key_with_password` over a throwaway key.
    const SEALED_PACKED_B64: &str = "5QEAAHsiYWxnb3JpdGhtIjoicnNhMjA0OCIsImV4dGVuc2lvbklkIjoiaGNnZGVncGFmbmxnbWNwa2NlbGJnaGtqYmJrb2loaWUiLCJwdWJsaWNLZXlEZXJCNjQiOiJNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXZEQmJZcW9LSU9OaXY2Z3pFWVAzR0RPMjNKYnFBVWhuNjlqVE9XNGdCU3hvVEpKbmtNaWNpdHdFY0JrSW92TlFiczIwYkNUVkpnb0UvMkk0VUZCQU1BT2VKa1JyN3o0YkFGNE9FR0wxZlppaFM3Smd4eXhmdGhnT2pWMjFoR2V5VllGcnFUclB6TFRCTFUrV2RjYW1zcmFEOGRKeGJYTkozekY2MDE2ZTZKZGIzVUtMdUZEcWJ6blJlRU5vc29DcWszNjZpVFB6RXp4cTJsNU9UNFFGUU5KZjdIa2JFZmt3bEw1TTlxYys4STJIQ2FSdUwva2plRzlPMURlUWJVTUxtM2owVWdkeHJJQzJjU214cThwYTZjVE1WNXVCdWdjdEJTVG9jdFE3TGVidERtYnBSZzBCL3lNSjN4M0Q4VCt1cjVVWUVNSFVsSlpHZzMxTkFHK1NrUUlEQVFBQiJ9QA/ATlc/xtOIxkpQeyD5ECZ8e9TkCLBK+NKXDTWOTK+AzuFJ0q4cE5YMs2jSsqcZXZXRDkREJkxUYZcutFGB0RAxpkMzGYHyi8w88+2wtxJ8rvTHwncxACAXTBMowPFheXTw+b0ielI10gtAY+K1yzN7vGHt+2oXHfdKTeNqfg0cVv9MvkJP6LRd245IUS4OoxgwAbvz0BnkVlTpwntcm7BT1pYCL+59IFn7JiSGIpMQdbHaVAbkDlD2W5VyaOtFde/GQC8OA/v2BfrDh0BH8QHCq2Mt9Vb5ci28ZsPwj32WhhuqcoiW8IPez3BuqcE6Ulixf0HchiOCvA+53d55RO2Zj0UDce27xQvtDfqonEXta5v4dS+eoPVb45r4laj+lOI4nsyNBuWaQAD84UPFbrdWr2+MHIALzWZTGM5AaV5WmzvXQZmM8rRtbMk91agTu/s9fYoe08lnfwjgHSvNCSJbqeooVI60G/khAAXjgpKzotxTsG2Cr1mqxt/ycIUDcSSmI9ih7D27JbNsYS+IEYPNDAmQiP3tsHIkETFVsukwvWBzRq9fd90d9vyCUIAuqzxiWMjPBTnKuFXSAIMwvgBnor6YlMkD9B+pj+7Lo7nsk8OVsAphkMfDL/FbAtfxazUvPlLKpGo9s9z9WSDYGijGCk4QLPElDjiSjkA/8rbcYij2nRn+GmKsBEDGUyM9lC90Gl6PYBCUuUPUwz54wxU1zGdnlZP6w/7W3xGmHJRN9FRgmQwLWuxI19VDWFQoHwegQoijYmvxPV5WIWG436MWdEnc/sRZNtxAvNklDvJKstsHMonsnRfQXq2cRbdme2KuM72ehXPPIP1XgMFTMCbJn4TZamJse0unCoePMlqlDPsfPxEmmzU/Tcw2cwRYFEz5RGCizveYOhERwQLU5lyIyRjrZZWdfZ/LkPD7A6TpNV0Juy0qsnJC0cDEL8+ensqfFWMnKfghdQSVPr8ZBvByw1+NRDVoAIXEh5Z1yOK9AupXwvwtcRwR5bryhBYjjv9e+wb80ER+IFBDsC2h7LJVv3Lq15lJ4SwFe2bquC/CtyjQrwFo2llkR8O80cF62GiTzQNEvHaAnVSAfeVIujRYyPSMZV5DgoJHhH5Z4iwv6ycMf/ZS68pymonQITJ8spVvvv+0iqxweESeKmmgA9AEGkcULwvJj4jk0wmjkwPvQs/XNxAaUDikDerXqPJf2x1e29NMNxf1O+y5Ai44gfYE4x3JylEMZPwki8kKHL2V69Hy5bjsKyExzZtTzdXJrkS9ENxIPMsior15iV7VHicPwdy+4rvwPaOIO2IquJgrbY3BwA4vkNAruIbkyr1y0tx5k8ul1smj5qvGqODE4IYG67oAd0NTLSzYL6ojCQY82vGaOEU5sAVpBLqkIniYA0M9SvWo00zU8UdQHZURbdiNFi+lwzIxFmLK4b0gYPo86foZICLIGy6DnBIwQKmGL4mNZsdgyRg+ZokSOFK70A6JQeWO/d3KqMiK3qQWff01sc/K+J4wJj2P2d43+9j5JVocSCzgN1wyiryChGE6udPii1uJXtvslupDxjALwLt0z+tmTFiiikXe/g54EuhEO4FuEiKBqsy+WZTtsfmZ19z8hxZVVLNd6Rd/wxhBrUn4DZiyzslUn4MXIfIKvokXpZSnbssAswKCiTDLJQ==";
    const SEALED_EXT_ID: &str = "hcgdegpafnlgmcpkcelbghkjbbkoihie";
    let password = b"fixture password";

    let packed = B64.decode(SEALED_PACKED_B64).unwrap();
    let (meta, blob) = unpack_meta_blob(&packed);
    assert_eq!(meta["extensionId"], SEALED_EXT_ID);
    assert_eq!(meta["algorithm"], "rsa2048");

    let handle = unlock_crx_with_password(
        &blob[28..],
        &blob[16..28],
        &blob[0..16],
        SEALED_EXT_ID,
        password.to_vec(),
        TEST_ARGON2_MEM,
        TEST_ARGON2_ITERS,
        TEST_ARGON2_PAR,
    )
    .expect("a key sealed by the shipped build must still open");
    let recovered = crx_store_get(handle).unwrap();
    drop_crx_key(handle).unwrap();

    let recovered_spki = spki_der(&recovered).unwrap();
    assert_eq!(meta["publicKeyDerB64"], B64.encode(&recovered_spki));
    assert_eq!(
        extension_id(&crx_id_from_spki(&recovered_spki)),
        SEALED_EXT_ID
    );
}
