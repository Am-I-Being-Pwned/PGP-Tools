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

/// Regression: a SIGNED message must still DECRYPT when we don't hold the
/// signer's public key. Decryption and signature verification are separate
/// concerns -- a missing signer key means "can't verify", not "fail".
#[test]
fn test_decrypt_signed_without_signer_key_succeeds() {
    // Recipient/decryption key.
    let recip = serde_json::from_str::<serde_json::Value>(&gen_test_key()).unwrap();
    let recip_pub = recip["publicKeyArmored"].as_str().unwrap();
    let recip_priv = recip["privateKeyArmored"].as_str().unwrap();

    // A DIFFERENT key that signs the message; we deliberately never supply
    // its public key to the decryptor.
    let signer = serde_json::from_str::<serde_json::Value>(&gen_test_key()).unwrap();
    let signer_priv = signer["privateKeyArmored"].as_str().unwrap();

    let recipients = serde_json::to_string(&vec![recip_pub]).unwrap();
    let ciphertext =
        encrypt(b"Message from a stranger", &recipients, Some(signer_priv.to_string()))
            .unwrap();

    // Decrypt WITHOUT any verification keys -> must not error.
    let (plaintext_bytes, sig) = test_decrypt(&ciphertext, recip_priv, None);
    assert_eq!(
        std::str::from_utf8(&plaintext_bytes).unwrap(),
        "Message from a stranger"
    );
    // Signed, but unverifiable because we lack the signer's public key.
    assert_eq!(sig["signatureValid"], false);
    assert_eq!(sig["signatureStatus"], "unknown_key");
}

#[test]
fn test_select_decryption_key_picks_the_recipient() {
    // Two distinct keys; encrypt only to `b`.
    let a = serde_json::from_str::<serde_json::Value>(&gen_test_key()).unwrap();
    let b = serde_json::from_str::<serde_json::Value>(&gen_test_key()).unwrap();
    let a_pub = a["publicKeyArmored"].as_str().unwrap();
    let a_fpr = a["keyInfo"]["keyId"].as_str().unwrap();
    let b_pub = b["publicKeyArmored"].as_str().unwrap();
    let b_fpr = b["keyInfo"]["keyId"].as_str().unwrap();

    let recipients = serde_json::to_string(&vec![b_pub]).unwrap();
    let ciphertext = encrypt(b"pick me", &recipients, None).unwrap();

    // Candidate set contains both keys (a first) -- must still choose b.
    let candidates = serde_json::to_string(&vec![a_pub, b_pub]).unwrap();
    let chosen = select_decryption_key(&ciphertext, &candidates).unwrap();
    let chosen: Option<String> = serde_json::from_str(&chosen).unwrap();
    assert_eq!(chosen.as_deref(), Some(b_fpr));
    assert_ne!(chosen.as_deref(), Some(a_fpr));

    // A candidate set without the recipient yields null.
    let only_a = serde_json::to_string(&vec![a_pub]).unwrap();
    let none = select_decryption_key(&ciphertext, &only_a).unwrap();
    let none: Option<String> = serde_json::from_str(&none).unwrap();
    assert_eq!(none, None);
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
        &ciphertext, &iv, salt, key_id, password.to_vec(), 4096, 3, 1,
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
        &ciphertext, &iv, prf_output.to_vec(), stored_secret.to_vec(), key_id,
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

    init_contacts_session_with_prf(prf_output.to_vec(), stored_secret.to_vec()).unwrap();
    assert!(has_contacts_session());

    drop_contacts_session();
    assert!(!has_contacts_session());
}

#[test]
fn test_contacts_encrypt_decrypt_round_trip_prf() {
    reset_contacts_session();

    let prf_output = b"32-byte-fake-prf-output-for-test";
    let stored_secret = b"32-byte-fake-stored-secret-test!";
    init_contacts_session_with_prf(prf_output.to_vec(), stored_secret.to_vec()).unwrap();

    let plaintext = b"[{\"keyId\":\"abc123\",\"name\":\"Alice\"}]";
    let packed = encrypt_contacts(plaintext.to_vec()).unwrap();

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

    let result = encrypt_contacts(b"should fail".to_vec());
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
    init_contacts_session_with_prf(prf_output_a.to_vec(), stored_secret_a.to_vec()).unwrap();

    let packed = encrypt_contacts(b"secret contacts".to_vec()).unwrap();
    let iv = &packed[..12];
    let ciphertext = &packed[12..];

    // Switch to a different key
    let prf_output_b = b"bbbb-fake-prf-output-32-bytes!!!";
    let stored_secret_b = b"bbbb-fake-stored-secret-32bytes!";
    init_contacts_session_with_prf(prf_output_b.to_vec(), stored_secret_b.to_vec()).unwrap();

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
    init_contacts_session_with_prf(prf_a.to_vec(), secret_a.to_vec()).unwrap();
    let packed_a = encrypt_contacts(b"data-a".to_vec()).unwrap();

    // Re-init with key B (should replace, not accumulate)
    let prf_b = b"bbbb-fake-prf-output-32-bytes!!!";
    let secret_b = b"bbbb-fake-stored-secret-32bytes!";
    init_contacts_session_with_prf(prf_b.to_vec(), secret_b.to_vec()).unwrap();
    let packed_b = encrypt_contacts(b"data-b".to_vec()).unwrap();

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
    let ct = encrypt_contacts(b"test contacts".to_vec()).unwrap();
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
    let contacts_packed = encrypt_contacts(b"[{\"keyId\":\"def456\"}]".to_vec()).unwrap();
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
    let packed = encrypt_contacts(b"password-contacts".to_vec()).unwrap();
    let iv = &packed[..12];
    let ct = &packed[12..];

    // Switch to a PRF-derived session (different key derivation path)
    let prf_output = b"32-byte-fake-prf-output-for-test";
    let stored_secret = b"32-byte-fake-stored-secret-test!";
    init_contacts_session_with_prf(prf_output.to_vec(), stored_secret.to_vec()).unwrap();

    // Should NOT be able to decrypt password-encrypted contacts with PRF key
    assert!(decrypt_contacts(ct, iv).is_err());

    reset_contacts_session();
}

#[test]
fn test_empty_contacts_encrypt_decrypt() {
    reset_contacts_session();

    let prf_output = b"32-byte-fake-prf-output-for-test";
    let stored_secret = b"32-byte-fake-stored-secret-test!";
    init_contacts_session_with_prf(prf_output.to_vec(), stored_secret.to_vec()).unwrap();

    // Empty JSON array
    let packed = encrypt_contacts(b"[]".to_vec()).unwrap();
    let iv = &packed[..12];
    let ct = &packed[12..];
    assert_eq!(decrypt_contacts(ct, iv).unwrap(), b"[]");

    // Empty bytes
    let packed2 = encrypt_contacts(b"".to_vec()).unwrap();
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
    init_contacts_session_with_prf(prf_output.to_vec(), stored_secret.to_vec()).unwrap();

    // Simulate ~100 contacts worth of data (~100KB)
    let large_data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    let packed = encrypt_contacts(large_data.clone()).unwrap();
    let iv = &packed[..12];
    let ct = &packed[12..];
    assert_eq!(decrypt_contacts(ct, iv).unwrap(), large_data);

    reset_contacts_session();
}

// ── per-store envelope (domain separation) ──────────────────────────

/// Start a contacts session with a deterministic fake PRF pair.
fn init_test_contacts_session() {
    reset_contacts_session();
    init_contacts_session_with_prf(
        b"32-byte-fake-prf-output-for-test".to_vec(),
        b"32-byte-fake-stored-secret-test!".to_vec(),
    )
    .unwrap();
}

#[test]
fn test_store_envelope_round_trips_within_its_domain() {
    init_test_contacts_session();

    let plaintext = b"[{\"id\":\"entry-1\",\"content\":\"dinner at eight\"}]";
    let packed = encrypt_store("pgp_history_seg_0", plaintext.to_vec()).unwrap();
    assert!(packed.len() > 12);
    let (iv, ct) = packed.split_at(12);

    assert_eq!(
        decrypt_store("pgp_history_seg_0", ct, iv).unwrap(),
        plaintext
    );

    reset_contacts_session();
}

#[test]
fn test_store_envelope_rejects_a_blob_from_another_segment_slot() {
    init_test_contacts_session();

    // Exactly the replay the old scheme accepted: copy seg_0's blob into
    // the seg_1 slot. Same session key, same everything -- only the slot
    // (and so the domain) differs.
    let packed = encrypt_store("pgp_history_seg_0", b"[{\"id\":\"a\"}]".to_vec()).unwrap();
    let (iv, ct) = packed.split_at(12);

    assert!(decrypt_store("pgp_history_seg_1", ct, iv).is_err());
    // ...and the correct slot still opens it, so the failure above is the
    // domain binding rather than a broken blob.
    assert!(decrypt_store("pgp_history_seg_0", ct, iv).is_ok());

    reset_contacts_session();
}

#[test]
fn test_store_envelope_rejects_a_blob_from_another_store() {
    init_test_contacts_session();

    let packed = encrypt_store("pgp_history_seg_0", b"[{\"id\":\"a\"}]".to_vec()).unwrap();
    let (iv, ct) = packed.split_at(12);

    // Substituting a history segment for the contacts / keyring / settings
    // / CRX blob must fail the tag check, not silently decode to something
    // that validates away to an empty list.
    for domain in [
        "pgp_public_contacts",
        "pgp_keyring",
        "pgp_settings",
        "pgp_crx_keys",
    ] {
        assert!(
            decrypt_store(domain, ct, iv).is_err(),
            "a history segment must not open as {domain}"
        );
    }

    reset_contacts_session();
}

#[test]
fn test_store_envelope_is_not_interchangeable_with_the_legacy_envelope() {
    init_test_contacts_session();

    // A legacy blob (shared key + shared CONTACTS_AAD) must not open as a
    // domain-bound one...
    let legacy = encrypt_contacts(b"[{\"id\":\"legacy\"}]".to_vec()).unwrap();
    let (l_iv, l_ct) = legacy.split_at(12);
    assert!(decrypt_store("pgp_public_contacts", l_ct, l_iv).is_err());
    assert!(decrypt_contacts(l_ct, l_iv).is_ok());

    // ...and a domain-bound blob must not open as a legacy one. Together
    // these are what make the JS "try new, fall back to legacy" migration
    // read unambiguous.
    let sealed = encrypt_store("pgp_public_contacts", b"[{\"id\":\"new\"}]".to_vec()).unwrap();
    let (s_iv, s_ct) = sealed.split_at(12);
    assert!(decrypt_contacts(s_ct, s_iv).is_err());
    assert!(decrypt_store("pgp_public_contacts", s_ct, s_iv).is_ok());

    reset_contacts_session();
}

#[test]
fn test_store_envelope_requires_a_session_and_a_domain() {
    reset_contacts_session();
    assert!(encrypt_store("pgp_keyring", b"x".to_vec())
        .unwrap_err()
        .contains("Contacts session not active"));
    assert!(decrypt_store("pgp_keyring", b"fake", &[0u8; 12])
        .unwrap_err()
        .contains("Contacts session not active"));

    init_test_contacts_session();
    // An empty domain would silently collapse every store back onto one
    // subkey, so it is rejected outright rather than defaulted.
    assert!(encrypt_store("", b"x".to_vec())
        .unwrap_err()
        .contains("domain must not be empty"));
    assert!(decrypt_store("", b"fake", &[0u8; 12])
        .unwrap_err()
        .contains("domain must not be empty"));

    reset_contacts_session();
}

#[test]
fn test_store_subkeys_differ_per_domain_and_from_the_session_key() {
    init_test_contacts_session();

    let a = derive_store_subkey("pgp_keyring").unwrap();
    let b = derive_store_subkey("pgp_public_contacts").unwrap();
    let a_again = derive_store_subkey("pgp_keyring").unwrap();

    assert_eq!(a.len(), 32);
    assert_ne!(a.as_slice(), b.as_slice());
    // Deterministic: the same domain must derive the same subkey or stored
    // blobs would be unreadable after a reload.
    assert_eq!(a.as_slice(), a_again.as_slice());
    // And distinct from the session key itself, so a leak of one subkey
    // does not hand over the others.
    let session_key = CONTACTS_KEY.with(|slot| slot.borrow().clone().unwrap());
    assert_ne!(a.as_slice(), session_key.as_slice());

    reset_contacts_session();
}

#[test]
fn test_store_envelope_handles_empty_and_large_plaintexts() {
    init_test_contacts_session();

    let packed = encrypt_store("pgp_settings", Vec::new()).unwrap();
    let (iv, ct) = packed.split_at(12);
    assert_eq!(decrypt_store("pgp_settings", ct, iv).unwrap(), Vec::<u8>::new());

    // A full history segment is ~64 KB; go past it.
    let large: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    let packed = encrypt_store("pgp_history_seg_3", large.clone()).unwrap();
    let (iv, ct) = packed.split_at(12);
    assert_eq!(decrypt_store("pgp_history_seg_3", ct, iv).unwrap(), large);

    reset_contacts_session();
}

#[test]
fn test_store_envelope_unreadable_after_the_session_drops() {
    init_test_contacts_session();
    let packed = encrypt_store("pgp_history_seg_0", b"[{\"id\":\"a\"}]".to_vec()).unwrap();
    let (iv, ct) = packed.split_at(12);
    assert!(decrypt_store("pgp_history_seg_0", ct, iv).is_ok());

    // Master lock: the subkey has no independent lifetime, so dropping the
    // session makes every domain unreadable.
    drop_contacts_session();
    assert!(decrypt_store("pgp_history_seg_0", ct, iv).is_err());
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

// ── parse_key_details ────────────────────────────────────────────────

#[test]
fn test_parse_key_details_breakdown() {
    let json = gen_test_key();
    let result: serde_json::Value = serde_json::from_str(&json).unwrap();
    let pub_armor = result["publicKeyArmored"].as_str().unwrap();

    let details: serde_json::Value =
        serde_json::from_str(&parse_key_details(pub_armor).unwrap()).unwrap();
    assert_eq!(details["truncated"], false);
    let rows = details["keys"].as_array().unwrap();

    // CertBuilder adds signing + transport-enc + storage-enc subkeys.
    assert_eq!(rows.len(), 4);

    // Primary first: certification-capable, active, matches cert fingerprint.
    assert_eq!(rows[0]["isPrimary"], true);
    assert_eq!(rows[0]["canCertify"], true);
    assert_eq!(rows[0]["status"], "active");
    let key_info: serde_json::Value =
        serde_json::from_str(&parse_key(pub_armor).unwrap()).unwrap();
    assert_eq!(rows[0]["fingerprint"], key_info["keyId"]);

    // Subkeys: exactly one signing, two encryption, all active, none primary.
    let subkeys: Vec<_> = rows.iter().skip(1).collect();
    assert!(subkeys.iter().all(|r| r["isPrimary"] == false));
    assert!(subkeys.iter().all(|r| r["status"] == "active"));
    assert_eq!(subkeys.iter().filter(|r| r["canSign"] == true).count(), 1);
    assert_eq!(subkeys.iter().filter(|r| r["canEncrypt"] == true).count(), 2);

    // Every row carries a distinct fingerprint and a creation time.
    let mut fps: Vec<&str> = rows.iter().map(|r| r["fingerprint"].as_str().unwrap()).collect();
    fps.sort_unstable();
    fps.dedup();
    assert_eq!(fps.len(), 4);
    assert!(rows.iter().all(|r| r["createdAt"].as_f64().unwrap() > 0.0));
}

#[test]
fn test_parse_key_details_accepts_private_armor() {
    let json = gen_test_key();
    let result: serde_json::Value = serde_json::from_str(&json).unwrap();
    let priv_armor = result["privateKeyArmored"].as_str().unwrap();

    let details: serde_json::Value =
        serde_json::from_str(&parse_key_details(priv_armor).unwrap()).unwrap();
    assert_eq!(details["keys"].as_array().unwrap().len(), 4);
}

#[test]
fn test_parse_key_details_expired() {
    let opts = r#"{"name":"Short Lived","email":"exp@test.com","type":"ecc","expiresIn":1}"#;
    let json = generate_key(opts).unwrap();
    let result: serde_json::Value = serde_json::from_str(&json).unwrap();
    let pub_armor = result["publicKeyArmored"].as_str().unwrap();

    std::thread::sleep(std::time::Duration::from_secs(2));

    let details: serde_json::Value =
        serde_json::from_str(&parse_key_details(pub_armor).unwrap()).unwrap();
    let rows = details["keys"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    for row in rows {
        assert_eq!(row["status"], "expired", "row: {row}");
        assert!(row["expiresAt"].as_f64().is_some());
    }
}

#[test]
fn test_parse_key_details_cert_revocation_propagates_to_subkeys() {
    let json = gen_test_key();
    let result: serde_json::Value = serde_json::from_str(&json).unwrap();
    let pub_armor = result["publicKeyArmored"].as_str().unwrap();
    let rev_armor = result["revocationCertificate"].as_str().unwrap();

    // Merge the revocation certificate into the public cert -- this is
    // what "publishing a revocation" means. Only the *primary* key is
    // revoked; the subkeys' own binding/revocation state stays clean.
    let cert = openpgp::Cert::from_bytes(pub_armor.as_bytes()).unwrap();
    let rev_packet = openpgp::Packet::from_bytes(rev_armor.as_bytes()).unwrap();
    let revoked_cert = cert.insert_packets(rev_packet).unwrap().0;
    let revoked_armor = String::from_utf8(revoked_cert.armored().to_vec().unwrap()).unwrap();

    let details: serde_json::Value =
        serde_json::from_str(&parse_key_details(&revoked_armor).unwrap()).unwrap();
    let rows = details["keys"].as_array().unwrap();
    assert_eq!(rows.len(), 4);

    // Every row -- primary AND subkeys -- must read revoked; a subkey
    // cannot outlive its certificate.
    for row in rows {
        assert_eq!(row["status"], "revoked", "row: {row}");
    }
    // Subkey rows carry the cert-level explanation.
    assert!(rows[1]["revocationReason"]
        .as_str()
        .unwrap()
        .starts_with("Certificate revoked:"));
}

#[test]
fn test_parse_key_details_garbage_input() {
    assert!(parse_key_details("not a key").is_err());
}

// ── zeroize-on-free global allocator ─────────────────────────────────

#[test]
fn test_allocator_zeroizes_freed_block() {
    use std::alloc::{alloc, dealloc, Layout};

    // A page-ish block, large enough that the allocator services it from
    // a predictable free list rather than inline metadata games.
    let layout = Layout::from_size_align(4096, 16).unwrap();
    unsafe {
        let p1 = alloc(layout);
        assert!(!p1.is_null());
        // Stamp a sentinel across the whole block.
        std::ptr::write_bytes(p1, 0xAB, layout.size());
        // Free it -- our GlobalAlloc::dealloc must wipe it first.
        dealloc(p1, layout);

        // Re-request the same layout. dlmalloc's LIFO free list hands the
        // just-freed block straight back, so we can observe its bytes.
        let p2 = alloc(layout);
        assert!(!p2.is_null());
        if p2 == p1 {
            let block = std::slice::from_raw_parts(p2, layout.size());
            assert!(
                block.iter().all(|&b| b == 0),
                "freed block was not zeroized before reuse",
            );
        }
        dealloc(p2, layout);
    }
}

/// Regression: GnuPG/libgcrypt pads ECC secret scalars to the field
/// size when protecting them (this key's Ed25519 scalar starts 0x15, so
/// its 253 actual bits are declared as 256). Sequoia's strict secret-MPI
/// parser rejects that, which used to fail the import of ~half of all
/// gpg-exported protected ECC keys; `decrypt_gpg_padded_secret` redoes
/// the decryption manually. Throwaway test key, passphrase below.
#[test]
fn decrypts_gpg_padded_ecc_secret() {
    let armored = r#"-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEakrr7RYJKwYBBAHaRw8BAQdA0zkntIfC/CAmEj8YVi6qBxgQaearoPS+Qytk
2w3UrC/+BwMCaAiwap3+RRX/QYwbCCBXEFCRTEFTGcFgFfPLtD/6iGSKXyh6ut7Y
UIcmS724t4p5LX7cUL7RpKn6rvnDAe4pe/tQGO9uHj92u7Q7N5JnWbQTVCBFZCA8
dDJAeC5leGFtcGxlPoiZBBMWCgBBFiEEAK6HPeVeFmRR4zOXo/26X5NJGfIFAmpK
6+0CGwMFCQHhM4AFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQo/26X5NJ
GfKSvQD/Xdgv3wTcxuIR+Kc9jZllB4qtvFCJH3j5Mey4li11gsIBANxaXn0mQlPW
OO5a/hK/DR12WoUg1lFspDebSz2rFz0A
=fKk9
-----END PGP PRIVATE KEY BLOCK-----"#;
    let cert = openpgp::Cert::from_bytes(armored.as_bytes()).unwrap();

    let decrypted =
        crate::decrypt_cert_secrets(cert.clone(), b"super secret passphrase 42").unwrap();
    assert!(
        decrypted
            .keys()
            .secret()
            .all(|ka| !ka.key().secret().is_encrypted()),
        "all secrets should be decrypted",
    );

    let err = crate::decrypt_cert_secrets(cert, b"wrong passphrase").unwrap_err();
    assert_eq!(err, "Incorrect passphrase");
}

/// A revocation certificate minted on demand for a stored key (the
/// imported-key backfill path) must actually revoke the cert when
/// applied, and must be recognized by our own import policy.
#[test]
fn minted_revocation_certificate_revokes_the_cert() {
    let generated: serde_json::Value =
        serde_json::from_str(&gen_test_key()).unwrap();
    let private_armor = generated["privateKeyArmored"].as_str().unwrap();

    let handle = store_key(private_armor).unwrap();
    let revocation = revocation_certificate_with_handle(handle).unwrap();
    drop_key(handle).unwrap();
    assert!(revocation.contains("BEGIN PGP SIGNATURE"));

    // Apply the revocation to the cert, as a recipient's tooling would.
    let cert = openpgp::Cert::from_bytes(private_armor.as_bytes()).unwrap();
    let sig = openpgp::Packet::from_bytes(revocation.as_bytes()).unwrap();
    let (revoked, _) = cert.insert_packets(vec![sig]).unwrap();

    let info = extract_key_info(&revoked, false);
    assert!(!info.usable_for_encryption && !info.usable_for_signing);
    assert!(
        info.policy_error
            .as_deref()
            .unwrap_or_default()
            .contains("revoked"),
        "policy error should name the revocation: {:?}",
        info.policy_error,
    );
}


// =====================================================================
// Entropy: behaviour under a poisoned platform RNG. See src/rng.rs.
// =====================================================================

/// AES-GCM nonce reuse under a fixed key is the catastrophic failure this
/// buys back. With `crypto.getRandomValues` pinned to a constant, the old
/// per-call `getrandom` gave every ciphertext the same 12-byte IV.
#[test]
fn constant_platform_rng_no_longer_repeats_aes_gcm_nonces() {
    let key = [7u8; 32];
    crate::rng::poison_platform_rng_for_test(0xAB);

    let mut nonces = Vec::new();
    for i in 0..16u8 {
        let ct = aes_gcm_encrypt(&key, &[i; 8], b"aad").unwrap();
        let nonce = ct[0..12].to_vec();
        assert_ne!(nonce, vec![0xABu8; 12], "must not pass the constant through");
        nonces.push(nonce);
    }
    crate::rng::restore_platform_rng_for_test();

    for i in 0..nonces.len() {
        for j in (i + 1)..nonces.len() {
            assert_ne!(nonces[i], nonces[j], "nonce {i} and {j} collided");
        }
    }
}

/// The Argon2id salt on a password-protected cert blob must stay fresh
/// even when the platform RNG is degenerate; a fixed salt collapses every
/// vault sealed by this build into one KDF output space.
#[test]
fn constant_platform_rng_no_longer_repeats_argon2_salts() {
    let generated: serde_json::Value = serde_json::from_str(&gen_test_key()).unwrap();
    let cert =
        openpgp::Cert::from_bytes(generated["privateKeyArmored"].as_str().unwrap().as_bytes())
            .unwrap();

    crate::rng::poison_platform_rng_for_test(0x00);
    let blob_a = encrypt_cert_with_password(&cert, b"pw", 4096, 3, 1).unwrap();
    let blob_b = encrypt_cert_with_password(&cert, b"pw", 4096, 3, 1).unwrap();
    crate::rng::restore_platform_rng_for_test();

    assert_ne!(&blob_a[0..16], &blob_b[0..16], "salt must be fresh");
    assert_ne!(&blob_a[0..16], &[0u8; 16], "must not pass the constant through");
    assert_ne!(&blob_a[16..28], &blob_b[16..28], "iv must be fresh");
    assert_ne!(blob_a, blob_b);
}

/// Draft session keys must not collide across re-initialisation.
#[test]
fn constant_platform_rng_no_longer_repeats_draft_session_keys() {
    crate::rng::poison_platform_rng_for_test(0x5A);

    drop_draft_session();
    init_draft_session_if_unset().unwrap();
    let key_a = with_draft_key(|k| k.to_vec()).unwrap();

    drop_draft_session();
    init_draft_session_if_unset().unwrap();
    let key_b = with_draft_key(|k| k.to_vec()).unwrap();

    drop_draft_session();
    crate::rng::restore_platform_rng_for_test();

    assert_ne!(key_a, key_b, "two draft sessions must not share a key");
    assert_ne!(key_a, vec![0x5Au8; 32], "must not pass the constant through");
}
