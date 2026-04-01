use super::*;

fn gen_test_key() -> String {
    let opts = r#"{"name":"Test User","email":"test@example.com","type":"ecc"}"#;
    generate_key(opts).unwrap()
}

/// Helper: decrypt via handle and return (plaintext_bytes, sig_info)
fn test_decrypt(
    ciphertext: &[u8],
    priv_armor: &str,
    verification_keys: Option<String>,
) -> (Vec<u8>, serde_json::Value) {
    let handle = store_key(priv_armor).unwrap();
    let packed = decrypt_with_handle(ciphertext, handle, verification_keys).unwrap();
    drop_key(handle).unwrap();

    let sig_len = u32::from_le_bytes([packed[0], packed[1], packed[2], packed[3]]) as usize;
    let sig_json = std::str::from_utf8(&packed[4..4 + sig_len]).unwrap();
    let sig: serde_json::Value = serde_json::from_str(sig_json).unwrap();
    let plaintext = packed[4 + sig_len..].to_vec();
    (plaintext, sig)
}

#[test]
fn test_ping() {
    assert_eq!(ping(), "gpg-wasm ok");
}

#[test]
fn test_generate_key() {
    let json = gen_test_key();
    let result: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(result["publicKeyArmored"]
        .as_str()
        .unwrap()
        .contains("BEGIN PGP PUBLIC KEY"));
    assert!(result["privateKeyArmored"]
        .as_str()
        .unwrap()
        .contains("BEGIN PGP PRIVATE KEY"));
    assert!(result["revocationCertificate"]
        .as_str()
        .unwrap()
        .contains("BEGIN PGP SIGNATURE"));
    assert!(!result["keyInfo"]["keyId"].as_str().unwrap().is_empty());
    assert_eq!(
        result["keyInfo"]["userIds"][0],
        "Test User <test@example.com>"
    );
    assert_eq!(result["keyInfo"]["isPrivate"], true);
}

#[test]
fn test_generate_key_with_comment_and_expiry() {
    let opts =
        r#"{"name":"Alice","email":"alice@test.com","comment":"work","type":"ecc","expiresIn":31536000}"#;
    let json = generate_key(opts).unwrap();
    let result: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        result["keyInfo"]["userIds"][0],
        "Alice (work) <alice@test.com>"
    );
    assert!(result["keyInfo"]["expiresAt"].as_f64().is_some());
}

#[test]
fn test_parse_public_key() {
    let gen_json = gen_test_key();
    let gen: serde_json::Value = serde_json::from_str(&gen_json).unwrap();
    let pub_armor = gen["publicKeyArmored"].as_str().unwrap();

    let info_json = parse_key(pub_armor).unwrap();
    let info: serde_json::Value = serde_json::from_str(&info_json).unwrap();
    assert_eq!(info["isPrivate"], false);
    assert_eq!(info["userIds"][0], "Test User <test@example.com>");
}

#[test]
fn test_parse_private_key() {
    let gen_json = gen_test_key();
    let gen: serde_json::Value = serde_json::from_str(&gen_json).unwrap();
    let priv_armor = gen["privateKeyArmored"].as_str().unwrap();

    let info_json = parse_key(priv_armor).unwrap();
    let info: serde_json::Value = serde_json::from_str(&info_json).unwrap();
    assert_eq!(info["isPrivate"], true);
}

#[test]
fn test_encrypt_decrypt_text() {
    let gen_json = gen_test_key();
    let gen: serde_json::Value = serde_json::from_str(&gen_json).unwrap();
    let pub_armor = gen["publicKeyArmored"].as_str().unwrap();
    let priv_armor = gen["privateKeyArmored"].as_str().unwrap();

    let recipients = serde_json::to_string(&vec![pub_armor]).unwrap();
    let ciphertext = encrypt(b"Hello, Sequoia!", &recipients, None).unwrap();
    assert!(!ciphertext.is_empty());

    let (plaintext_bytes, _sig) = test_decrypt(&ciphertext, priv_armor, None);
    assert_eq!(
        std::str::from_utf8(&plaintext_bytes).unwrap(),
        "Hello, Sequoia!"
    );
}

#[test]
fn test_encrypt_decrypt_with_signature() {
    let gen_json = gen_test_key();
    let gen: serde_json::Value = serde_json::from_str(&gen_json).unwrap();
    let pub_armor = gen["publicKeyArmored"].as_str().unwrap();
    let priv_armor = gen["privateKeyArmored"].as_str().unwrap();

    let recipients = serde_json::to_string(&vec![pub_armor]).unwrap();
    let ciphertext =
        encrypt(b"Signed message", &recipients, Some(priv_armor.to_string())).unwrap();

    let verification_keys = serde_json::to_string(&vec![pub_armor]).unwrap();
    let (plaintext_bytes, sig) =
        test_decrypt(&ciphertext, priv_armor, Some(verification_keys));
    assert_eq!(
        std::str::from_utf8(&plaintext_bytes).unwrap(),
        "Signed message"
    );
    assert_eq!(sig["signatureValid"], true);
    assert!(sig["signerKeyId"].as_str().is_some());
}

#[test]
fn test_sign_verify() {
    let gen_json = gen_test_key();
    let gen: serde_json::Value = serde_json::from_str(&gen_json).unwrap();
    let pub_armor = gen["publicKeyArmored"].as_str().unwrap();
    let priv_armor = gen["privateKeyArmored"].as_str().unwrap();

    let signed = sign_message("Test message", priv_armor).unwrap();
    assert!(signed.contains("BEGIN PGP SIGNED MESSAGE"));

    let verification_keys = serde_json::to_string(&vec![pub_armor]).unwrap();
    let result_json = verify_message(&signed, &verification_keys).unwrap();
    let result: serde_json::Value = serde_json::from_str(&result_json).unwrap();
    assert_eq!(result["text"].as_str().unwrap(), "Test message");
    assert_eq!(result["signatureValid"], true);
}

#[test]
fn test_key_store_handle() {
    let gen_json = gen_test_key();
    let gen: serde_json::Value = serde_json::from_str(&gen_json).unwrap();
    let priv_armor = gen["privateKeyArmored"].as_str().unwrap();

    let handle = store_key(priv_armor).unwrap();
    assert!(handle > 0);

    let signed = sign_with_handle("Handle test", handle).unwrap();
    assert!(signed.contains("BEGIN PGP SIGNED MESSAGE"));

    drop_key(handle).unwrap();

    let result = sign_with_handle("Should fail", handle);
    assert!(result.is_err());
}

#[test]
fn test_encrypt_decrypt_binary() {
    let gen_json = gen_test_key();
    let gen: serde_json::Value = serde_json::from_str(&gen_json).unwrap();
    let pub_armor = gen["publicKeyArmored"].as_str().unwrap();
    let priv_armor = gen["privateKeyArmored"].as_str().unwrap();

    let binary_data: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let recipients = serde_json::to_string(&vec![pub_armor]).unwrap();
    let ciphertext = encrypt(&binary_data, &recipients, None).unwrap();

    let (plaintext_bytes, _sig) = test_decrypt(&ciphertext, priv_armor, None);
    assert_eq!(plaintext_bytes, binary_data);
}

#[test]
fn test_ed25519_full_round_trip() {
    let opts = r#"{"name":"Ed User","email":"ed@test.com","type":"ecc"}"#;
    let json = generate_key(opts).unwrap();
    let gen: serde_json::Value = serde_json::from_str(&json).unwrap();

    let algo = gen["keyInfo"]["algorithm"].as_str().unwrap();
    assert!(
        algo.contains("Ed") || algo.contains("25519") || algo.contains("EdDSA"),
        "Expected Ed25519-based algo, got: {}",
        algo
    );

    let pub_armor = gen["publicKeyArmored"].as_str().unwrap();
    let priv_armor = gen["privateKeyArmored"].as_str().unwrap();

    let recipients = serde_json::to_string(&vec![pub_armor]).unwrap();
    let ciphertext =
        encrypt(b"Ed25519 round trip", &recipients, Some(priv_armor.to_string())).unwrap();

    let verification_keys = serde_json::to_string(&vec![pub_armor]).unwrap();
    let (plaintext_bytes, sig) =
        test_decrypt(&ciphertext, priv_armor, Some(verification_keys.clone()));
    assert_eq!(
        std::str::from_utf8(&plaintext_bytes).unwrap(),
        "Ed25519 round trip"
    );
    assert_eq!(sig["signatureValid"], true);

    let signed = sign_message("Ed25519 signing", priv_armor).unwrap();
    assert!(signed.contains("BEGIN PGP SIGNED MESSAGE"));

    let verify_json = verify_message(&signed, &verification_keys).unwrap();
    let verify_result: serde_json::Value = serde_json::from_str(&verify_json).unwrap();
    assert_eq!(verify_result["text"].as_str().unwrap(), "Ed25519 signing");
    assert_eq!(verify_result["signatureValid"], true);

    let handle = store_key(priv_armor).unwrap();
    let handle_signed = sign_with_handle("Handle Ed25519", handle).unwrap();
    assert!(handle_signed.contains("BEGIN PGP SIGNED MESSAGE"));
    let handle_ct = encrypt(b"Handle decrypt", &recipients, None).unwrap();
    let (handle_plaintext, _) = test_decrypt(&handle_ct, priv_armor, None);
    assert_eq!(
        std::str::from_utf8(&handle_plaintext).unwrap(),
        "Handle decrypt"
    );
    drop_key(handle).unwrap();
}

#[test]
fn test_argon2_derive() {
    let password = b"test-password";
    let salt = b"16-byte-salt!!!!";
    let key = argon2_derive(password, salt, 4096, 3, 1).unwrap();
    assert_eq!(key.len(), 32);
    let key2 = argon2_derive(password, salt, 4096, 3, 1).unwrap();
    assert_eq!(key, key2);
    let key3 = argon2_derive(b"different", salt, 4096, 3, 1).unwrap();
    assert_ne!(key, key3);
}

#[test]
fn test_unlock_with_password() {
    let gen_json = gen_test_key();
    let gen: serde_json::Value = serde_json::from_str(&gen_json).unwrap();
    let priv_armor = gen["privateKeyArmored"].as_str().unwrap();

    // Simulate what JS does: Argon2 derive -> AES-GCM encrypt the private key
    let password = b"test-password-123";
    let salt = b"16-byte-salt!!!!";
    let key_id = "test-key-id";

    // Derive AES key
    let derived = argon2_derive(password, salt, 4096, 3, 1).unwrap();

    // Encrypt with AES-GCM
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};
    use aes_gcm::aead::Payload;
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(&derived).unwrap();
    let iv = [0u8; 12]; // fixed IV for test
    let nonce = Nonce::from_slice(&iv);
    let aad = format!("gpg-tools:password:{}", key_id);
    let ciphertext = cipher.encrypt(nonce, Payload {
        msg: priv_armor.as_bytes(),
        aad: aad.as_bytes(),
    }).unwrap();

    // Now unlock entirely in WASM
    let handle = unlock_with_password(
        &ciphertext, &iv, salt, key_id, password, 4096, 3, 1,
    ).unwrap();
    assert!(handle > 0);

    // Verify we can sign with the handle
    let signed = sign_with_handle("unlock test", handle).unwrap();
    assert!(signed.contains("BEGIN PGP SIGNED MESSAGE"));

    drop_key(handle).unwrap();
}

#[test]
fn test_unlock_with_prf() {
    let gen_json = gen_test_key();
    let gen: serde_json::Value = serde_json::from_str(&gen_json).unwrap();
    let priv_armor = gen["privateKeyArmored"].as_str().unwrap();

    // Simulate PRF output + stored secret
    let prf_output = b"32-byte-fake-prf-output-for-test";
    let stored_secret = b"32-byte-fake-stored-secret-test!";
    let key_id = "test-key-id-prf";

    // HKDF derive
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(stored_secret.as_slice()), prf_output.as_slice());
    let mut derived = vec![0u8; 32];
    hk.expand(b"gpg-tools-prf-v1", &mut derived).unwrap();

    // Encrypt with AES-GCM
    use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead, Nonce};
    use aes_gcm::aead::Payload;
    let cipher = Aes256Gcm::new_from_slice(&derived).unwrap();
    let iv = [1u8; 12];
    let nonce = Nonce::from_slice(&iv);
    let aad = format!("gpg-tools:passkey:{}", key_id);
    let ciphertext = cipher.encrypt(nonce, Payload {
        msg: priv_armor.as_bytes(),
        aad: aad.as_bytes(),
    }).unwrap();

    // Unlock entirely in WASM
    let handle = unlock_with_prf(
        &ciphertext, &iv, prf_output, stored_secret, key_id,
    ).unwrap();
    assert!(handle > 0);

    let signed = sign_with_handle("prf unlock test", handle).unwrap();
    assert!(signed.contains("BEGIN PGP SIGNED MESSAGE"));

    drop_key(handle).unwrap();
}

#[test]
fn test_rsa_key_generation() {
    let opts = r#"{"name":"RSA User","email":"rsa@test.com","type":"rsa"}"#;
    let json = generate_key(opts).unwrap();
    let result: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(result["publicKeyArmored"]
        .as_str()
        .unwrap()
        .contains("BEGIN PGP PUBLIC KEY"));
    let pub_armor = result["publicKeyArmored"].as_str().unwrap();
    let priv_armor = result["privateKeyArmored"].as_str().unwrap();
    let recipients = serde_json::to_string(&vec![pub_armor]).unwrap();
    let ct = encrypt(b"RSA test", &recipients, None).unwrap();
    let (dec_bytes, _sig) = test_decrypt(&ct, priv_armor, None);
    assert_eq!(std::str::from_utf8(&dec_bytes).unwrap(), "RSA test");
}

// =====================================================================
// Contacts session tests
// =====================================================================

/// Helper: drop the contacts session to ensure clean state between tests.
/// (Tests may run in any order on the same thread.)
fn reset_contacts_session() {
    drop_contacts_session();
    assert!(!has_contacts_session());
}

#[test]
fn test_contacts_session_lifecycle_with_prf() {
    reset_contacts_session();

    let prf_output = b"32-byte-fake-prf-output-for-test";
    let stored_secret = b"32-byte-fake-stored-secret-test!";

    assert!(!has_contacts_session());

    init_contacts_session_with_prf(prf_output, stored_secret).unwrap();
    assert!(has_contacts_session());

    drop_contacts_session();
    assert!(!has_contacts_session());
}

#[test]
fn test_contacts_encrypt_decrypt_round_trip_prf() {
    reset_contacts_session();

    let prf_output = b"32-byte-fake-prf-output-for-test";
    let stored_secret = b"32-byte-fake-stored-secret-test!";
    init_contacts_session_with_prf(prf_output, stored_secret).unwrap();

    let plaintext = b"[{\"keyId\":\"abc123\",\"name\":\"Alice\"}]";
    let packed = encrypt_contacts(plaintext).unwrap();

    // Packed format: [12-byte IV][ciphertext]
    assert!(packed.len() > 12);
    let iv = &packed[..12];
    let ciphertext = &packed[12..];

    let decrypted = decrypt_contacts(ciphertext, iv).unwrap();
    assert_eq!(decrypted, plaintext);

    reset_contacts_session();
}

#[test]
fn test_contacts_encrypt_without_session_fails() {
    reset_contacts_session();

    let result = encrypt_contacts(b"should fail");
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("Contacts session not active"));
}

#[test]
fn test_contacts_decrypt_without_session_fails() {
    reset_contacts_session();

    let result = decrypt_contacts(b"fake-ciphertext", &[0u8; 12]);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("Contacts session not active"));
}

#[test]
fn test_contacts_decrypt_wrong_key_fails() {
    reset_contacts_session();

    // Encrypt with one key
    let prf_output_a = b"aaaa-fake-prf-output-32-bytes!!!";
    let stored_secret_a = b"aaaa-fake-stored-secret-32bytes!";
    init_contacts_session_with_prf(prf_output_a, stored_secret_a).unwrap();

    let packed = encrypt_contacts(b"secret contacts").unwrap();
    let iv = &packed[..12];
    let ciphertext = &packed[12..];

    // Switch to a different key
    let prf_output_b = b"bbbb-fake-prf-output-32-bytes!!!";
    let stored_secret_b = b"bbbb-fake-stored-secret-32bytes!";
    init_contacts_session_with_prf(prf_output_b, stored_secret_b).unwrap();

    // Decryption should fail (wrong key)
    let result = decrypt_contacts(ciphertext, iv);
    assert!(result.is_err());

    reset_contacts_session();
}

#[test]
fn test_contacts_session_replaced_on_reinit() {
    reset_contacts_session();

    // Init with key A, encrypt
    let prf_a = b"aaaa-fake-prf-output-32-bytes!!!";
    let secret_a = b"aaaa-fake-stored-secret-32bytes!";
    init_contacts_session_with_prf(prf_a, secret_a).unwrap();
    let packed_a = encrypt_contacts(b"data-a").unwrap();

    // Re-init with key B (should replace, not accumulate)
    let prf_b = b"bbbb-fake-prf-output-32-bytes!!!";
    let secret_b = b"bbbb-fake-stored-secret-32bytes!";
    init_contacts_session_with_prf(prf_b, secret_b).unwrap();
    let packed_b = encrypt_contacts(b"data-b").unwrap();

    // Decrypt B should work
    let iv_b = &packed_b[..12];
    let ct_b = &packed_b[12..];
    assert_eq!(decrypt_contacts(ct_b, iv_b).unwrap(), b"data-b");

    // Decrypt A should fail (session now has key B)
    let iv_a = &packed_a[..12];
    let ct_a = &packed_a[12..];
    assert!(decrypt_contacts(ct_a, iv_a).is_err());

    reset_contacts_session();
}

#[test]
fn test_encrypt_canary_and_init_session() {
    reset_contacts_session();

    let password = b"strong-password-123";
    let salt = b"16-byte-salt!!!!";

    let packed = encrypt_canary_and_init_session(password, salt, 4096, 3, 1).unwrap();
    assert!(packed.len() > 12);

    // Session should now be active
    assert!(has_contacts_session());

    // Should be able to encrypt/decrypt contacts
    let ct = encrypt_contacts(b"test contacts").unwrap();
    let iv = &ct[..12];
    let ciphertext = &ct[12..];
    assert_eq!(decrypt_contacts(ciphertext, iv).unwrap(), b"test contacts");

    reset_contacts_session();
}

#[test]
fn test_verify_canary_correct_password() {
    reset_contacts_session();

    let password = b"correct-password-123";
    let salt = b"16-byte-salt!!!!";

    // Setup: encrypt canary
    let packed = encrypt_canary_and_init_session(password, salt, 4096, 3, 1).unwrap();
    let canary_iv = &packed[..12];
    let canary_ct = &packed[12..];

    // Drop session to simulate app restart
    drop_contacts_session();
    assert!(!has_contacts_session());

    // Verify with correct password should succeed and init session
    let ok = verify_canary_and_init_session(canary_ct, canary_iv, password, salt, 4096, 3, 1).unwrap();
    assert!(ok);
    assert!(has_contacts_session());

    reset_contacts_session();
}

#[test]
fn test_verify_canary_wrong_password() {
    reset_contacts_session();

    let password = b"correct-password-123";
    let wrong_password = b"wrong-password-456!!";
    let salt = b"16-byte-salt!!!!";

    // Setup: encrypt canary
    let packed = encrypt_canary_and_init_session(password, salt, 4096, 3, 1).unwrap();
    let canary_iv = &packed[..12];
    let canary_ct = &packed[12..];

    drop_contacts_session();

    // Verify with wrong password should return false and NOT init session
    let ok = verify_canary_and_init_session(canary_ct, canary_iv, wrong_password, salt, 4096, 3, 1).unwrap();
    assert!(!ok);
    assert!(!has_contacts_session());

    reset_contacts_session();
}

#[test]
fn test_verify_canary_then_encrypt_contacts() {
    reset_contacts_session();

    let password = b"my-master-password";
    let salt = b"16-byte-salt!!!!";

    // Setup
    let packed = encrypt_canary_and_init_session(password, salt, 4096, 3, 1).unwrap();
    let canary_iv = &packed[..12];
    let canary_ct = &packed[12..];

    // Encrypt some contacts while session is active
    let contacts_packed = encrypt_contacts(b"[{\"keyId\":\"def456\"}]").unwrap();
    let contacts_iv = &contacts_packed[..12];
    let contacts_ct = &contacts_packed[12..];

    // Simulate app restart
    drop_contacts_session();

    // Re-verify password → session should be restored
    let ok = verify_canary_and_init_session(canary_ct, canary_iv, password, salt, 4096, 3, 1).unwrap();
    assert!(ok);

    // Decrypt contacts should work with the restored session
    let decrypted = decrypt_contacts(contacts_ct, contacts_iv).unwrap();
    assert_eq!(decrypted, b"[{\"keyId\":\"def456\"}]");

    reset_contacts_session();
}

#[test]
fn test_contacts_key_domain_separation_password_vs_prf() {
    reset_contacts_session();

    // Encrypt contacts with a password-derived session
    let password = b"test-password-for-sep";
    let salt = b"16-byte-salt!!!!";
    encrypt_canary_and_init_session(password, salt, 4096, 3, 1).unwrap();
    let packed = encrypt_contacts(b"password-contacts").unwrap();
    let iv = &packed[..12];
    let ct = &packed[12..];

    // Switch to a PRF-derived session (different key derivation path)
    let prf_output = b"32-byte-fake-prf-output-for-test";
    let stored_secret = b"32-byte-fake-stored-secret-test!";
    init_contacts_session_with_prf(prf_output, stored_secret).unwrap();

    // Should NOT be able to decrypt password-encrypted contacts with PRF key
    assert!(decrypt_contacts(ct, iv).is_err());

    reset_contacts_session();
}

#[test]
fn test_empty_contacts_encrypt_decrypt() {
    reset_contacts_session();

    let prf_output = b"32-byte-fake-prf-output-for-test";
    let stored_secret = b"32-byte-fake-stored-secret-test!";
    init_contacts_session_with_prf(prf_output, stored_secret).unwrap();

    // Empty JSON array
    let packed = encrypt_contacts(b"[]").unwrap();
    let iv = &packed[..12];
    let ct = &packed[12..];
    assert_eq!(decrypt_contacts(ct, iv).unwrap(), b"[]");

    // Empty bytes
    let packed2 = encrypt_contacts(b"").unwrap();
    let iv2 = &packed2[..12];
    let ct2 = &packed2[12..];
    assert_eq!(decrypt_contacts(ct2, iv2).unwrap(), b"");

    reset_contacts_session();
}

#[test]
fn test_large_contacts_encrypt_decrypt() {
    reset_contacts_session();

    let prf_output = b"32-byte-fake-prf-output-for-test";
    let stored_secret = b"32-byte-fake-stored-secret-test!";
    init_contacts_session_with_prf(prf_output, stored_secret).unwrap();

    // Simulate ~100 contacts worth of data (~100KB)
    let large_data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    let packed = encrypt_contacts(&large_data).unwrap();
    let iv = &packed[..12];
    let ct = &packed[12..];
    assert_eq!(decrypt_contacts(ct, iv).unwrap(), large_data);

    reset_contacts_session();
}

#[test]
fn test_canary_tampered_ciphertext_fails() {
    reset_contacts_session();

    let password = b"test-password-tamper";
    let salt = b"16-byte-salt!!!!";

    let packed = encrypt_canary_and_init_session(password, salt, 4096, 3, 1).unwrap();
    let canary_iv = &packed[..12];
    let mut canary_ct = packed[12..].to_vec();

    drop_contacts_session();

    // Tamper with the ciphertext
    if let Some(byte) = canary_ct.last_mut() {
        *byte ^= 0xFF;
    }

    // Should fail gracefully (return false, not panic/error)
    let ok = verify_canary_and_init_session(&canary_ct, canary_iv, password, salt, 4096, 3, 1).unwrap();
    assert!(!ok);
    assert!(!has_contacts_session());

    reset_contacts_session();
}
