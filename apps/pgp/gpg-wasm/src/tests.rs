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
    let ciphertext = encrypt(b"Hello, Sequoia!", &recipients, None, None).unwrap();
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
        encrypt(b"Signed message", &recipients, Some(priv_armor.to_string()), None).unwrap();

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
        encrypt(b"Message from a stranger", &recipients, Some(signer_priv.to_string()), None)
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
    let ciphertext = encrypt(b"pick me", &recipients, None, None).unwrap();

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
    let ciphertext = encrypt(&binary_data, &recipients, None, None).unwrap();

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
        encrypt(b"Ed25519 round trip", &recipients, Some(priv_armor.to_string()), None).unwrap();

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
    let handle_ct = encrypt(b"Handle decrypt", &recipients, None, None).unwrap();
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
    let ct = encrypt(b"RSA test", &recipients, None, None).unwrap();
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

    let packed = encrypt_canary_and_init_session(password.to_vec(), salt, 4096, 3, 1).unwrap();
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
    let packed = encrypt_canary_and_init_session(password.to_vec(), salt, 4096, 3, 1).unwrap();
    let canary_iv = &packed[..12];
    let canary_ct = &packed[12..];

    // Drop session to simulate app restart
    drop_contacts_session();
    assert!(!has_contacts_session());

    // Verify with correct password should succeed and init session
    let ok = verify_canary_and_init_session(canary_ct, canary_iv, password.to_vec(), salt, 4096, 3, 1).unwrap();
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
    let packed = encrypt_canary_and_init_session(password.to_vec(), salt, 4096, 3, 1).unwrap();
    let canary_iv = &packed[..12];
    let canary_ct = &packed[12..];

    drop_contacts_session();

    // Verify with wrong password should return false and NOT init session
    let ok = verify_canary_and_init_session(canary_ct, canary_iv, wrong_password.to_vec(), salt, 4096, 3, 1).unwrap();
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
    let packed = encrypt_canary_and_init_session(password.to_vec(), salt, 4096, 3, 1).unwrap();
    let canary_iv = &packed[..12];
    let canary_ct = &packed[12..];

    // Encrypt some contacts while session is active
    let contacts_packed = encrypt_contacts(b"[{\"keyId\":\"def456\"}]".to_vec()).unwrap();
    let contacts_iv = &contacts_packed[..12];
    let contacts_ct = &contacts_packed[12..];

    // Simulate app restart
    drop_contacts_session();

    // Re-verify password → session should be restored
    let ok = verify_canary_and_init_session(canary_ct, canary_iv, password.to_vec(), salt, 4096, 3, 1).unwrap();
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
    encrypt_canary_and_init_session(password.to_vec(), salt, 4096, 3, 1).unwrap();
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

    let packed = encrypt_canary_and_init_session(password.to_vec(), salt, 4096, 3, 1).unwrap();
    let canary_iv = &packed[..12];
    let mut canary_ct = packed[12..].to_vec();

    drop_contacts_session();

    // Tamper with the ciphertext
    if let Some(byte) = canary_ct.last_mut() {
        *byte ^= 0xFF;
    }

    // Should fail gracefully (return false, not panic/error)
    let ok = verify_canary_and_init_session(&canary_ct, canary_iv, password.to_vec(), salt, 4096, 3, 1).unwrap();
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

/// The CFB fallback takes its cipher, key and IV from an untrusted key
/// file, so every size mismatch must come back as an `Err`, never a
/// panic -- in wasm a panic aborts the module and takes the side panel,
/// with its unlocked keys, down with it. The hand-rolled feedback loop
/// this replaced was panic-free only because the caller never handed it
/// an 8-byte-block cipher or an empty IV; now the guarantee comes from
/// `cfb-mode`'s own `Result`-returning constructor, so it holds
/// regardless of what the caller does.
#[test]
fn cfb_decrypt_rejects_bad_sizes_instead_of_panicking() {
    let ct = [0u8; 48];

    // Key too short for AES256 (needs 32 bytes).
    assert!(crate::cfb_decrypt(SymmetricAlgorithm::AES256, &[0u8; 16], &[0u8; 16], &ct).is_err());
    // Key too long for AES128 (needs 16).
    assert!(crate::cfb_decrypt(SymmetricAlgorithm::AES128, &[0u8; 32], &[0u8; 16], &ct).is_err());
    // IV that is not one AES block. An 8-byte IV is exactly what a
    // 64-bit-block legacy cipher would have produced, and is what used
    // to make `Block::clone_from_slice` panic.
    assert!(crate::cfb_decrypt(SymmetricAlgorithm::AES256, &[0u8; 32], &[0u8; 8], &ct).is_err());
    // Empty IV: the old loop's `chunks(0)` panicked outright.
    assert!(crate::cfb_decrypt(SymmetricAlgorithm::AES256, &[0u8; 32], &[], &ct).is_err());

    // Non-AES ciphers stay refused, with the re-export advice intact.
    let err =
        crate::cfb_decrypt(SymmetricAlgorithm::Twofish, &[0u8; 32], &[0u8; 16], &ct).unwrap_err();
    assert!(err.contains("--s2k-cipher-algo AES256"), "{err}");

    // Well-formed sizes still work, including a ciphertext that is not
    // a whole number of blocks and an empty one (both reachable from a
    // truncated key packet).
    for len in [0usize, 1, 15, 16, 17, 48] {
        assert!(crate::cfb_decrypt(
            SymmetricAlgorithm::AES256,
            &[0u8; 32],
            &[0u8; 16],
            &vec![0u8; len],
        )
        .is_ok());
    }
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

// ── Owned-credential params on the canary exports ───────────────────
//
// `encryptCanaryAndInitSession` / `verifyCanaryAndInitSession` take the
// master password as an owned `Vec<u8>` (SECURITY.md §8.4,
// T-UNLOCK-PARAM-NOT-OWNED). That change moves the wasm-bindgen boundary,
// and these two functions gate master unlock: a regression in either does
// not degrade gracefully, it locks every existing user out of their vault.
// So the round trip is asserted through the new signatures, and — as with
// the CRX unlock exports — a canary blob emitted by the PRE-change code is
// frozen below and must still verify.

#[test]
fn test_canary_round_trip_through_owned_password_params() {
    reset_contacts_session();

    let password = b"owned-param-master-password";
    let salt = b"16-byte-salt!!!!";

    // Each call gets its own `Vec`, exactly as wasm-bindgen would hand over
    // a fresh marshalled copy per call; nothing may depend on the caller
    // still holding the bytes afterwards.
    let packed = encrypt_canary_and_init_session(password.to_vec(), salt, 4096, 3, 1).unwrap();
    let canary_iv = &packed[..12];
    let canary_ct = &packed[12..];

    drop_contacts_session();
    assert!(!has_contacts_session());

    assert!(
        verify_canary_and_init_session(canary_ct, canary_iv, password.to_vec(), salt, 4096, 3, 1)
            .unwrap(),
        "a canary sealed through the owned-param signature must verify through it"
    );
    assert!(has_contacts_session());

    // And the wrong password must still be rejected without a session.
    drop_contacts_session();
    assert!(
        !verify_canary_and_init_session(
            canary_ct,
            canary_iv,
            b"not-the-master-password".to_vec(),
            salt,
            4096,
            3,
            1
        )
        .unwrap()
    );
    assert!(!has_contacts_session());

    reset_contacts_session();
}

/// A canary blob produced by the shipped, PRE-change build (when
/// `encrypt_canary_and_init_session` still took `password: &[u8]`), captured
/// verbatim as `[12-byte IV][ciphertext||tag]`. Regenerating this defeats
/// its purpose: it exists to prove the at-rest format did not move when the
/// param went from borrowed to owned. Only the marshalling changed, so a
/// vault sealed by the shipped build must still unlock.
const PRE_CHANGE_CANARY_PACKED: [u8; 47] = [
    0xe5, 0x24, 0xf3, 0xed, 0x95, 0x14, 0xb5, 0x68, 0x93, 0x18, 0x25, 0x48, 0x52, 0xed, 0xc8, 0xfa,
    0x7e, 0x99, 0x5e, 0x7e, 0x9c, 0x4f, 0x2b, 0x23, 0xc4, 0xbf, 0xa9, 0xc5, 0x04, 0xb2, 0xb0, 0x61,
    0xfa, 0xdb, 0x4b, 0x0c, 0x6a, 0xe6, 0x69, 0x93, 0x69, 0x1f, 0x59, 0xd0, 0x9d, 0x96, 0x1f,
];
const PRE_CHANGE_CANARY_PASSWORD: &[u8] = b"pre-change-master-password";
const PRE_CHANGE_CANARY_SALT: &[u8] = b"canary-fixture!!";

#[test]
fn test_pre_change_canary_still_verifies() {
    reset_contacts_session();

    let canary_iv = &PRE_CHANGE_CANARY_PACKED[..12];
    let canary_ct = &PRE_CHANGE_CANARY_PACKED[12..];

    assert!(
        verify_canary_and_init_session(
            canary_ct,
            canary_iv,
            PRE_CHANGE_CANARY_PASSWORD.to_vec(),
            PRE_CHANGE_CANARY_SALT,
            4096,
            3,
            1
        )
        .unwrap(),
        "a canary sealed by the pre-change build no longer verifies - existing \
         vaults would be permanently unopenable"
    );
    // Verification must also restore a usable session, not merely report true.
    assert!(has_contacts_session());
    let sealed = encrypt_contacts(b"post-unlock".to_vec()).unwrap();
    assert_eq!(
        decrypt_contacts(&sealed[12..], &sealed[..12]).unwrap(),
        b"post-unlock"
    );

    reset_contacts_session();
}

#[test]
fn test_argon2_derive_owned_matches_borrowed_helper() {
    let password = b"argon2-owned-vs-borrowed";
    let salt = b"16-byte-salt!!!!";

    // The exported wrapper only changes how the secret is marshalled; the
    // derivation it delegates to must produce identical bytes.
    let owned = argon2_derive_owned(password.to_vec(), salt, 4096, 3, 1).unwrap();
    let borrowed = argon2_derive(password, salt, 4096, 3, 1).unwrap();
    assert_eq!(owned, borrowed);
    assert_eq!(owned.len(), 32);

    // Input validation must survive the split.
    assert!(argon2_derive_owned(password.to_vec(), b"short", 4096, 3, 1).is_err());
}

// =====================================================================
// Symmetric (password) decryption -- `gpg --symmetric` / `gpg -c`
// =====================================================================
//
// CROSS-TOOL COMPATIBILITY IS THE ONLY SPECIFICATION HERE, the same
// position `age.rs` takes: these vectors were produced by the real GnuPG
// CLI (2.5.21) rather than by our own encryptor, because a round-trip
// against ourselves would pass just as happily if we had implemented the
// format wrong in a self-consistent way. Symmetric encryption is the one
// PGP operation this app CANNOT produce (decrypt-only by design), so
// without pinned foreign vectors there is nothing to test against at all.
//
// All three decrypt to `SYMMETRIC_PLAINTEXT` under `symmetric_password()`.
// The password is in the clear on purpose: it guards nothing, and a
// reader has to be able to see that the fixture is a fixture.

/// Owned per call: the export takes `Vec<u8>` so it can `Zeroizing`-wrap
/// it, which means each test hands over its own copy.
fn symmetric_password() -> Vec<u8> {
    b"correct horse battery staple".to_vec()
}
const SYMMETRIC_PLAINTEXT: &[u8] = b"the password is the key";

/// `gpg -c --rfc4880`: v4 SKESK, AES-256-CFB, MDC. What most tools in the
/// wild still emit, and the case where a WRONG password is not detected
/// at the SKESK at all -- it fails later, as an MDC mismatch.
const GPG_SYMMETRIC_V4: &str = "-----BEGIN PGP MESSAGE-----\n\n\
jA0ECQMIgYlslpAs65D/0lEB7S0K0+CFdt0IhAB8VpcBcK/6SkSMUGzegcLuFyBj\n\
KAFUrRe5nBt9CNXSIRuIDsj+k2V4YT+ZnsBO4kx2F3RFv3sKEN8v1cKMq86Qif+p\n\
wjg=\n\
=AEHv\n\
-----END PGP MESSAGE-----\n";

/// `gpg -c --force-ocb`: AEAD. The modern path, where a wrong password
/// DOES fail at the session-key unwrap. Both ends must produce the same
/// user-facing answer, which is why both are pinned.
const GPG_SYMMETRIC_OCB: &str = "-----BEGIN PGP MESSAGE-----\n\n\
jE0FCQIDCFDkvEpE6tIy/xwgVAOzARqn7B1V/V0igvN9GNaewd51FLEE94tolfSs\n\
tDn7/sE05fHil10ZCdhTAnGx7bVB6yGRd7UX5yttXNRbAQkCEFu+HvJvMd14ux7U\n\
BAvbQR/CoZcWMx90z36ymHrm5LUALjtjcYkd3M0qyXdT2V1xx22/z/fY7vH/vASM\n\
ZEoKujuEOCe/thf7tS6NbpbbXH2lOPGdUySXjA==\n\
=u+/p\n\
-----END PGP MESSAGE-----\n";

/// `gpg -c --sign`: symmetric AND signed. A password-encrypted message
/// can carry a signature, so the password path must run the same
/// signature classification the key path does -- and must NOT report
/// "unsigned" for this one.
const GPG_SYMMETRIC_SIGNED: &str = "-----BEGIN PGP MESSAGE-----\n\n\
jA0ECQMIGI2S2lO8Ow//0sA6AZNUChy/HdmSVtZ1OomQSmWGl4iQkkxbBNgAE/Gs\n\
85JsksQ735CORnLNEZsgxQDcwPGSkZGEaeexL5H9ShMxBOqNBvfkX1AI80b04oz9\n\
A5rY4+cULCTlVRtCNvEQxBjxev308EIiUgwfsuixT3KW3/EgQIid62q4sSFMwuWu\n\
WiBxZq2I/AWd5FGNMs589tVMeRTdfaIEg5i79MoovtNILe+ZdDnGeThg890vZUIo\n\
wmk8j9C8z6U/hZzCmdF5zUX2I0RLhhF7sB/Xbp085L7ZRGiK6EFkelNIpPkaVB+e\n\
C3K0w4Vhhii7ewxRfBHAJDjD+C88gOP6D71FRA==\n\
=mTY0\n\
-----END PGP MESSAGE-----\n";

/// The signer of `GPG_SYMMETRIC_SIGNED`, so the signature has something
/// to verify against. A public half only.
const GPG_SYMMETRIC_SIGNER: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\
mDMEapBj+RYJKwYBBAHaRw8BAQdADK/m+TiE39BTvOnrevM5ZRBr5FLywpXfnvNa\n\
LGXZjSW0HFN5bSBUZXN0ZXIgPHN5bUBleGFtcGxlLmNvbT6ItQQTFgoAXRYhBPh3\n\
rp5NlKEkUyjYtVaANUzeCGrsBQJqkGP5GxSAAAAAAAQADm1hbnUyLDIuNSsxLjEy\n\
LDAsMwIbAwUJBaOagAULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRBWgDVM\n\
3ghq7NNnAP4xvjE6iWb4K4T0+2fc9Htrktm6AJ822zkVQpfuInMizQD/ZfvFjcyH\n\
q5wr07KTsVKIOf8NZ9563BA2VmWN/bKk8Ao=\n\
=6IJK\n\
-----END PGP PUBLIC KEY BLOCK-----\n";

/// Unpack the shared `[len][sig_json][plaintext]` return.
fn unpack(packed: &[u8]) -> (Vec<u8>, serde_json::Value) {
    let sig_len = u32::from_le_bytes([packed[0], packed[1], packed[2], packed[3]]) as usize;
    let sig: serde_json::Value =
        serde_json::from_str(std::str::from_utf8(&packed[4..4 + sig_len]).unwrap()).unwrap();
    (packed[4 + sig_len..].to_vec(), sig)
}

#[test]
fn test_decrypt_password_gpg_v4() {
    let packed =
        decrypt_with_password(GPG_SYMMETRIC_V4.as_bytes(), symmetric_password(), None).unwrap();
    let (plaintext, sig) = unpack(&packed);
    assert_eq!(plaintext, SYMMETRIC_PLAINTEXT);
    assert_eq!(sig["signatureStatus"], "unsigned");
}

#[test]
fn test_decrypt_password_names_the_unreadable_aead_format() {
    // `gpg -c --force-ocb` writes the pre-RFC-9580 AED packet, which
    // Sequoia's policy rejects. NOT READABLE, and the message must say
    // so: folded into the wrong-password wording it would send a user
    // with a perfectly good password off to check their password, and no
    // password will ever open this.
    //
    // The RIGHT password is used here on purpose -- the point is that the
    // answer does not depend on it.
    let err =
        decrypt_with_password(GPG_SYMMETRIC_OCB.as_bytes(), symmetric_password(), None).unwrap_err();
    assert!(err.contains("AEAD (OCB)"), "unexpected error: {err}");
    assert!(!err.contains("Wrong password"), "unexpected error: {err}");
}

#[test]
fn test_decrypt_password_verifies_a_signature() {
    // A symmetric message can be signed. If the password path skipped
    // signature classification, this would come back "unsigned" and the
    // UI would silently drop a signer it could have shown.
    let certs = serde_json::to_string(&vec![GPG_SYMMETRIC_SIGNER]).unwrap();
    let packed = decrypt_with_password(
        GPG_SYMMETRIC_SIGNED.as_bytes(),
        symmetric_password(),
        Some(certs),
    )
    .unwrap();
    let (plaintext, sig) = unpack(&packed);
    assert_eq!(plaintext, SYMMETRIC_PLAINTEXT);
    assert_eq!(sig["signatureStatus"], "valid");
    assert_eq!(sig["signatureValid"], true);
}

#[test]
fn test_decrypt_password_signed_without_the_signer_key() {
    // Same message, no certs supplied. Decryption must still SUCCEED --
    // a signature we cannot check is a status, never a reason to withhold
    // the plaintext (the rule `DecryptHelper::check` already keeps).
    let packed = decrypt_with_password(
        GPG_SYMMETRIC_SIGNED.as_bytes(),
        symmetric_password(),
        None,
    )
    .unwrap();
    let (plaintext, sig) = unpack(&packed);
    assert_eq!(plaintext, SYMMETRIC_PLAINTEXT);
    assert_eq!(sig["signatureStatus"], "unknown_key");
    assert_eq!(sig["signatureValid"], false);
}

#[test]
fn test_decrypt_password_wrong_password_is_one_message() {
    // A v4 SKESK unwraps the session key with NO integrity check, so a
    // wrong password does not fail where it is used -- it fails much
    // later, as an MDC mismatch inside the reader. This is the test that
    // the one `map_err` around the whole parse catches that, rather than
    // letting a raw "Malformed MDC packet" reach the user as "the data is
    // corrupted" when the data is fine and the password is not.
    let err =
        decrypt_with_password(GPG_SYMMETRIC_V4.as_bytes(), b"not the password".to_vec(), None).unwrap_err();
    assert!(
        err.starts_with("Wrong password, or this message is damaged:"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_decrypt_password_refuses_a_key_encrypted_message() {
    // A message with no SKESK at all. It must fail rather than fall back
    // to some other route -- the helper ignores PKESKs by construction.
    let key = gen_test_key();
    let parsed: serde_json::Value = serde_json::from_str(&key).unwrap();
    let public = parsed["publicKeyArmored"].as_str().unwrap();
    let recipients = serde_json::to_string(&vec![public]).unwrap();
    let ciphertext = encrypt(b"hello", &recipients, None, None).unwrap();

    let err = decrypt_with_password(&ciphertext, symmetric_password(), None).unwrap_err();
    assert!(err.contains("Wrong password, or this message is damaged"));
}

#[test]
fn test_message_encryption_tells_the_two_apart() {
    let password_only: serde_json::Value =
        serde_json::from_str(&message_encryption(GPG_SYMMETRIC_V4.as_bytes()).unwrap()).unwrap();
    assert_eq!(password_only["password"], true);
    assert_eq!(password_only["publicKey"], false);

    let key = gen_test_key();
    let parsed: serde_json::Value = serde_json::from_str(&key).unwrap();
    let recipients =
        serde_json::to_string(&vec![parsed["publicKeyArmored"].as_str().unwrap()]).unwrap();
    let ciphertext = encrypt(b"hello", &recipients, None, None).unwrap();
    let key_only: serde_json::Value =
        serde_json::from_str(&message_encryption(&ciphertext).unwrap()).unwrap();
    assert_eq!(key_only["password"], false);
    assert_eq!(key_only["publicKey"], true);
}

#[test]
fn test_message_encryption_stops_at_the_container() {
    // The detector must not need the password, the key, or any ability to
    // read the body -- it answers from the packets in FRONT of the
    // encrypted container. Proven by the fact that it answers at all for
    // a message nothing here can open.
    //
    // The OCB vector is the one that proves it: its SKESK is a version
    // Sequoia does not implement, so it parses as `Packet::Unknown` and a
    // match on the `Packet::SKESK` VARIANT reported it as having no
    // password. Matching the TAG is what makes the detector describe the
    // message rather than describe our parser.
    let json = message_encryption(GPG_SYMMETRIC_OCB.as_bytes()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["password"], true);
    assert_eq!(parsed["publicKey"], false);
}

#[test]
fn test_message_encryption_rejects_non_pgp_input() {
    assert!(message_encryption(b"not a pgp message at all").is_err());
}



// =====================================================================
// Symmetric (password) ENCRYPTION
// =====================================================================

#[test]
fn test_encrypt_with_password_round_trips() {
    let ct = encrypt(
        b"symmetric hello",
        "[]",
        None,
        Some(symmetric_password()),
    )
    .unwrap();
    let packed = decrypt_with_password(&ct, symmetric_password(), None).unwrap();
    let (plaintext, sig) = unpack(&packed);
    assert_eq!(plaintext, b"symmetric hello");
    assert_eq!(sig["signatureStatus"], "unsigned");
}

#[test]
fn test_encrypt_with_password_produces_a_password_only_message() {
    // No recipients means no PKESK: the detector the UI routes on must
    // see a message that wants a password and nothing else.
    let ct = encrypt(b"x", "[]", None, Some(symmetric_password())).unwrap();
    let enc: serde_json::Value =
        serde_json::from_str(&message_encryption(&ct).unwrap()).unwrap();
    assert_eq!(enc["password"], true);
    assert_eq!(enc["publicKey"], false);
}

#[test]
fn test_encrypt_with_password_is_additive_not_a_mode() {
    // A password ADDS an SKESK; it does not replace the recipients. The
    // message must then open BOTH ways -- this is what makes the badge
    // sitting next to "Also encrypt to me" honest rather than a mode
    // switch that silently drops the recipient list.
    let gen: serde_json::Value = serde_json::from_str(&gen_test_key()).unwrap();
    let pub_armor = gen["publicKeyArmored"].as_str().unwrap();
    let priv_armor = gen["privateKeyArmored"].as_str().unwrap();
    let recipients = serde_json::to_string(&vec![pub_armor]).unwrap();

    let ct = encrypt(b"both ways", &recipients, None, Some(symmetric_password()))
        .unwrap();

    let enc: serde_json::Value =
        serde_json::from_str(&message_encryption(&ct).unwrap()).unwrap();
    assert_eq!(enc["password"], true);
    assert_eq!(enc["publicKey"], true);

    // ...by password,
    let (by_password, _) =
        unpack(&decrypt_with_password(&ct, symmetric_password(), None).unwrap());
    assert_eq!(by_password, b"both ways");

    // ...and by key.
    let (by_key, _) = test_decrypt(&ct, priv_armor, None);
    assert_eq!(by_key, b"both ways");
}

#[test]
fn test_encrypt_with_password_and_a_signature() {
    // Signing and password-encrypting are independent knobs, so the
    // combination has to work -- and the signature has to verify on the
    // password path, which is a different helper from the key path.
    let gen: serde_json::Value = serde_json::from_str(&gen_test_key()).unwrap();
    let pub_armor = gen["publicKeyArmored"].as_str().unwrap();
    let priv_armor = gen["privateKeyArmored"].as_str().unwrap();

    let ct = encrypt(
        b"signed and sealed",
        "[]",
        Some(priv_armor.to_string()),
        Some(symmetric_password()),
    )
    .unwrap();

    let certs = serde_json::to_string(&vec![pub_armor]).unwrap();
    let (plaintext, sig) =
        unpack(&decrypt_with_password(&ct, symmetric_password(), Some(certs)).unwrap());
    assert_eq!(plaintext, b"signed and sealed");
    assert_eq!(sig["signatureStatus"], "valid");
}

#[test]
fn test_encrypt_refuses_a_message_nobody_could_open() {
    // No recipients AND no password is a valid OpenPGP message that
    // nothing can decrypt. Silently producing one would look like a
    // success and fail hours later, in someone else's hands.
    let err = encrypt(b"x", "[]", None, None).unwrap_err();
    assert!(err.contains("nothing could open this message"), "{err}");
}

#[test]
fn test_encrypt_with_password_rejects_the_wrong_password() {
    let ct = encrypt(b"x", "[]", None, Some(symmetric_password())).unwrap();
    let err = decrypt_with_password(&ct, b"not it".to_vec(), None).unwrap_err();
    assert!(err.starts_with("Wrong password, or this message is damaged:"), "{err}");
}

#[test]
fn test_encrypt_with_password_uses_aes256_and_the_max_s2k() {
    // The two parameters this app picks on the user's behalf, asserted
    // rather than trusted to a dependency's `Default`.
    //
    // The S2K count is the LARGEST the OpenPGP wire format can encode
    // (0x3e00000). There is no stronger value available, which is the
    // whole reason this feature was comfortable to ship: the app is
    // taking the format's maximum, not choosing a number.
    use openpgp::crypto::S2K;
    use openpgp::parse::{PacketParser, PacketParserResult};

    let ct = encrypt(b"x", "[]", None, Some(symmetric_password())).unwrap();
    let mut ppr = PacketParser::from_bytes(&ct).unwrap();
    let mut checked = false;
    while let PacketParserResult::Some(pp) = ppr {
        if let openpgp::Packet::SKESK(openpgp::packet::SKESK::V4(skesk)) = &pp.packet {
            assert_eq!(skesk.symmetric_algo(), SymmetricAlgorithm::AES256);
            match skesk.s2k() {
                S2K::Iterated { hash, hash_bytes, .. } => {
                    assert_eq!(*hash, HashAlgorithm::SHA256);
                    assert_eq!(*hash_bytes, 0x3e00000);
                }
                other => panic!("expected an iterated S2K, got {other:?}"),
            }
            checked = true;
        }
        let (_p, next) = pp.next().unwrap();
        ppr = next;
    }
    assert!(checked, "no SKESK packet found");
}

/// The other direction: our password-encrypted message must open in real
/// GnuPG.
///
/// Skipped when `gpg` is not installed -- the pinned vectors above cover
/// GnuPG -> us unconditionally, but us -> GnuPG can only be proven
/// against a live CLI. Same shape, and the same reasoning, as
/// `age_cli_decrypts_our_ciphertext`.
///
/// This matters more than a round-trip against ourselves: symmetric
/// encryption is the one thing here whose whole point is that someone
/// ELSE opens it, usually with the tool we did not write.
#[test]
fn gpg_cli_decrypts_our_symmetric_message() {
    use std::process::Command;

    if Command::new("gpg").arg("--version").output().is_err() {
        eprintln!("skipping: the `gpg` CLI is not installed");
        return;
    }

    let dir = std::env::temp_dir().join(format!("gpg-wasm-sym-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let ct_path = dir.join("ours.asc");
    let home = dir.join("gnupghome");
    std::fs::create_dir_all(&home).unwrap();

    std::fs::write(
        &ct_path,
        encrypt(SYMMETRIC_PLAINTEXT, "[]", None, Some(symmetric_password())).unwrap(),
    )
    .unwrap();

    let out = Command::new("gpg")
        .env("GNUPGHOME", &home)
        .args(["--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase"])
        .arg(std::str::from_utf8(&symmetric_password()).unwrap())
        .arg("--decrypt")
        .arg(&ct_path)
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "gpg could not decrypt our message: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, SYMMETRIC_PLAINTEXT);
    let _ = std::fs::remove_dir_all(&dir);
}

// =====================================================================
// ADVERSARIAL TESTS
//
// Everything above this line asks "does the happy path work". These ask
// "what does a hostile input get out of us". They are written against
// the properties the README and SECURITY.md actually claim, because
// those are the claims a user relies on:
//
//   - a tampered or truncated ciphertext yields NO plaintext, not
//     partial plaintext (a streaming decryptor that emits before the
//     integrity check is the classic way this goes wrong);
//   - a signature is bound to the bytes it signed, so it cannot be
//     transplanted onto other text;
//   - `signatureValid: true` is never reachable from key material an
//     attacker chose;
//   - hostile bytes produce an Err, never a panic -- a panic in wasm
//     aborts the module, which is a denial of service on the whole
//     extension rather than a failed parse.
// =====================================================================

/// A fresh ECC keypair as (public_armor, private_armor).
fn adv_keypair() -> (String, String) {
    let gen: serde_json::Value = serde_json::from_str(&gen_test_key()).unwrap();
    (
        gen["publicKeyArmored"].as_str().unwrap().to_string(),
        gen["privateKeyArmored"].as_str().unwrap().to_string(),
    )
}

fn adv_recipients(pub_armor: &str) -> String {
    serde_json::to_string(&vec![pub_armor]).unwrap()
}

// ── ciphertext integrity ─────────────────────────────────────────────

/// De-armor a message so corruption lands on real ciphertext bytes
/// rather than on base64 framing. Flipping a bit in the ASCII armor is
/// not the attack -- it mostly hits the CRC, a newline, or a character
/// whose low bits are padding, and it makes an integrity test look
/// stricter than it is.
fn dearmor(armored: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut raw = Vec::new();
    openpgp::armor::Reader::from_bytes(armored, None)
        .read_to_end(&mut raw)
        .unwrap();
    raw
}

#[test]
fn no_single_bit_corruption_ever_yields_altered_plaintext() {
    // THE property, stated the way an attacker would have to break it:
    // flip any one bit anywhere in the ciphertext and the caller either
    // gets an error or gets the message that was actually sent. Never a
    // third thing.
    //
    // Exhaustive over every byte, not a sample: the interesting bits are
    // exactly the ones nobody thought to poke. Most flips in the body are
    // caught outright; a flip in the PKESK's advisory recipient key ID is
    // *expected* to still decrypt, because Sequoia falls back to trying
    // the keys it holds. Both outcomes are safe. Altered plaintext is not.
    let (pub_armor, priv_armor) = adv_keypair();
    let expected = "SECRET-".repeat(24);
    let ciphertext = encrypt(
        expected.as_bytes(),
        &adv_recipients(&pub_armor),
        None,
        None,
    )
    .unwrap();

    let raw = dearmor(&ciphertext);
    let handle = store_key(&priv_armor).unwrap();

    let mut detected = 0;
    for offset in 0..raw.len() {
        for bit in [0u8, 3, 7] {
            let mut corrupted = raw.clone();
            corrupted[offset] ^= 1 << bit;

            match decrypt_with_handle(&corrupted, handle, None) {
                Err(_) => detected += 1,
                Ok(packed) => {
                    let sig_len =
                        u32::from_le_bytes([packed[0], packed[1], packed[2], packed[3]]) as usize;
                    assert_eq!(
                        &packed[4 + sig_len..],
                        expected.as_bytes(),
                        "bit {bit} at offset {offset} produced ALTERED plaintext",
                    );
                }
            }
        }
    }

    // Sanity on the test itself: if corruption stopped being detected at
    // all, the loop above would pass vacuously against a broken build.
    assert!(
        detected > raw.len(),
        "integrity checks fired on only {detected} of {} corruptions -- \
         suspiciously few, the test may no longer be corrupting ciphertext",
        raw.len() * 3,
    );

    drop_key(handle).unwrap();
}

#[test]
fn truncating_the_ciphertext_never_yields_plaintext() {
    // Removing the tail removes the integrity check. A decryptor that
    // streamed plaintext out before validating would hand back the
    // surviving prefix -- the "no TOCTOU window" claim failing exactly
    // where it matters. Every truncation must be an error.
    //
    // The plaintext spans many reads on purpose: a short message can sit
    // entirely in one buffer and get validated before any of it is
    // written, which would hide the bug this is looking for.
    let (pub_armor, priv_armor) = adv_keypair();
    let plaintext = "SECRET-".repeat(4096);
    let ciphertext = encrypt(
        plaintext.as_bytes(),
        &adv_recipients(&pub_armor),
        None,
        None,
    )
    .unwrap();

    let raw = dearmor(&ciphertext);
    let handle = store_key(&priv_armor).unwrap();

    for cut in [1usize, 2, 8, 32, 128, 512, raw.len() / 2] {
        let truncated = &raw[..raw.len() - cut];
        assert!(
            decrypt_with_handle(truncated, handle, None).is_err(),
            "truncating {cut} bytes still produced output",
        );
    }

    drop_key(handle).unwrap();
}

#[test]
fn decrypt_with_a_non_recipient_handle_fails() {
    // Holding *a* private key must not open a message encrypted to
    // someone else -- and the failure must be an error, not an empty
    // success that a caller could mistake for an empty message.
    let (recipient_pub, _recipient_priv) = adv_keypair();
    let (_other_pub, other_priv) = adv_keypair();

    let ciphertext = encrypt(
        b"for the recipient only",
        &adv_recipients(&recipient_pub),
        None,
        None,
    )
    .unwrap();

    let wrong_handle = store_key(&other_priv).unwrap();
    let result = decrypt_with_handle(&ciphertext, wrong_handle, None);
    drop_key(wrong_handle).unwrap();

    assert!(result.is_err(), "a non-recipient key decrypted the message");
}

// ── signature binding ────────────────────────────────────────────────

#[test]
fn cleartext_signature_does_not_transfer_to_other_text() {
    // The signature covers the bytes it was made over. Swapping the body
    // underneath it is the whole attack, so "valid" here would mean the
    // signature asserts nothing at all.
    let (pub_armor, priv_armor) = adv_keypair();
    let signed = sign_message("transfer 10 to alice", &priv_armor).unwrap();
    let keys = serde_json::to_string(&vec![&pub_armor]).unwrap();

    let swapped = signed.replace("transfer 10 to alice", "transfer 99 to mallory");
    assert_ne!(swapped, signed, "test did not actually alter the body");

    // Either the parse rejects it outright or it verifies as invalid --
    // both are safe. What must never happen is `valid`.
    match verify_message(&swapped, &keys) {
        Ok(json) => {
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_ne!(v["signatureStatus"], "valid", "swapped body verified");
            assert_eq!(v["signatureValid"], false);
        }
        Err(_) => {}
    }
}

#[test]
fn cleartext_signature_rejects_a_single_character_edit() {
    // The minimal tamper. A one-character edit that still verifies would
    // mean the digest is not covering the text.
    let (pub_armor, priv_armor) = adv_keypair();
    let signed = sign_message("balance: 100", &priv_armor).unwrap();
    let keys = serde_json::to_string(&vec![&pub_armor]).unwrap();

    let edited = signed.replace("balance: 100", "balance: 900");

    match verify_message(&edited, &keys) {
        Ok(json) => {
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            assert_ne!(v["signatureStatus"], "valid");
        }
        Err(_) => {}
    }
}

#[test]
fn verification_against_an_attacker_chosen_key_is_never_valid() {
    // `valid` must mean "this key signed this", so supplying a DIFFERENT
    // key must never produce it. An attacker who can influence which
    // public keys are offered for verification (a contact import, a
    // GitHub lookup) otherwise gets to mint trust.
    let (_signer_pub, signer_priv) = adv_keypair();
    let (attacker_pub, _attacker_priv) = adv_keypair();

    let signed = sign_message("authentic notice", &signer_priv).unwrap();
    let attacker_keys = serde_json::to_string(&vec![&attacker_pub]).unwrap();

    let json = verify_message(&signed, &attacker_keys).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_ne!(v["signatureStatus"], "valid");
    assert_eq!(v["signatureValid"], false);
    // "we don't hold the signer's key" is the honest answer here.
    assert_eq!(v["signatureStatus"], "unknown_key");
}

#[test]
fn signed_and_encrypted_body_tamper_is_never_reported_valid() {
    // The combined path: if the body is altered, the caller must not be
    // told `signatureValid: true` alongside whatever came out.
    let (pub_armor, priv_armor) = adv_keypair();
    let ciphertext = encrypt(
        b"the original statement",
        &adv_recipients(&pub_armor),
        Some(priv_armor.clone()),
        None,
    )
    .unwrap();

    let handle = store_key(&priv_armor).unwrap();
    let keys = serde_json::to_string(&vec![&pub_armor]).unwrap();

    let len = ciphertext.len();
    for offset in [len * 7 / 10, len * 8 / 10] {
        let mut corrupted = ciphertext.clone();
        corrupted[offset] ^= 0x01;

        if let Ok(packed) = decrypt_with_handle(&corrupted, handle, Some(keys.clone())) {
            let sig_len =
                u32::from_le_bytes([packed[0], packed[1], packed[2], packed[3]]) as usize;
            let sig: serde_json::Value =
                serde_json::from_str(std::str::from_utf8(&packed[4..4 + sig_len]).unwrap())
                    .unwrap();
            assert_ne!(
                sig["signatureValid"], true,
                "tampered message reported a valid signature",
            );
        }
    }

    drop_key(handle).unwrap();
}

// ── hostile input must not panic ─────────────────────────────────────

#[test]
fn hostile_bytes_return_errors_rather_than_panicking() {
    // A panic inside wasm aborts the module: the extension's whole crypto
    // engine dies until reload, from nothing more than a pasted string.
    // Every one of these must come back as Err.
    //
    // `#[test]` turns a panic into a failure, so this catches the thing
    // it is looking for without any harness of its own.
    let hostile: Vec<&[u8]> = vec![
        b"",
        b"\x00",
        b"\xff\xff\xff\xff",
        b"not armor at all",
        b"-----BEGIN PGP MESSAGE-----",
        b"-----BEGIN PGP MESSAGE-----\n\n-----END PGP MESSAGE-----",
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----",
        b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n////\n-----END PGP PRIVATE KEY BLOCK-----",
        // A length header claiming far more than follows.
        b"\xc2\xff\xff\xff\xff\x01",
        // Valid base64, structurally meaningless as packets.
        b"-----BEGIN PGP MESSAGE-----\n\nSGVsbG8gd29ybGQh\n-----END PGP MESSAGE-----",
    ];

    for input in hostile {
        let text = String::from_utf8_lossy(input).to_string();

        // Parsers.
        let _ = parse_key(&text);
        let _ = parse_keys(&text);
        let _ = parse_key_details(&text);
        let _ = extract_public_key(&text);
        let _ = is_secret_encrypted(&text);

        // Message-shaped entry points.
        let _ = message_encryption(input);
        let _ = verify_message(&text, "[]");
        let _ = decrypt_with_password(input, b"password".to_vec(), None);
        let _ = select_decryption_key(input, "[]");
    }
}

#[test]
fn a_dropped_handle_cannot_be_reused() {
    // Use-after-free at the API level: once a key is locked, its handle
    // must be dead. A stale handle that still resolves would keep a
    // "locked" key usable for as long as the number is remembered.
    let (pub_armor, priv_armor) = adv_keypair();
    let ciphertext = encrypt(b"secret", &adv_recipients(&pub_armor), None, None).unwrap();

    let handle = store_key(&priv_armor).unwrap();
    assert!(decrypt_with_handle(&ciphertext, handle, None).is_ok());

    drop_key(handle).unwrap();

    assert!(
        decrypt_with_handle(&ciphertext, handle, None).is_err(),
        "a dropped handle still decrypted",
    );
    assert!(get_key_armored(handle).is_err(), "a dropped handle still exported");
}

#[test]
fn an_unissued_handle_is_never_valid() {
    // Guessing handle numbers must not reach a key.
    for handle in [0u32, 1, 2, 42, u32::MAX] {
        let _ = decrypt_with_handle(b"whatever", handle, None);
        assert!(
            get_key_armored(handle).is_err(),
            "handle {handle} resolved to a key without being issued",
        );
    }
}

/// REGRESSION -- decompression bomb (was: no output cap).
///
/// `decrypt_with_handle`, `decrypt_with_password` and `verify_message`
/// each do a bare `std::io::copy` from the reader into a `Vec`, and the
/// crate is built with `compression-deflate`. Nothing bounds the result.
/// A message the user PASTES or DROPS is fully attacker-controlled, so
/// the expansion factor is theirs to choose: measured at 756x here, and
/// deflate reaches ~1000x, so a few MB of pasted text is several GB of
/// allocation inside a 32-bit wasm linear memory. That aborts the module
/// -- the extension's whole crypto engine, not just this operation.
///
/// Now capped by `MAX_DECRYPTED_BYTES`. The bomb is cheap to build
/// (a small ciphertext), so this costs almost nothing to run: the cap
/// refuses it long before 64 MiB is materialised.
#[test]
fn decompression_bomb_is_refused_by_the_expansion_ratio() {
    use openpgp::serialize::stream::{Armorer, Compressor, Encryptor, LiteralWriter, Message};
    use openpgp::types::CompressionAlgorithm;

    // Comfortably past MIN_EXPANSION_ALLOWANCE, so the ratio is what
    // refuses it rather than any flat ceiling.
    const EXPANDED: usize = 256 * 1024 * 1024;

    let (pub_armor, priv_armor) = adv_keypair();
    let cert = openpgp::Cert::from_bytes(pub_armor.as_bytes()).unwrap();
    let vc = cert.with_policy(policy(), None).unwrap();
    let recipient_keys: Vec<_> = vc
        .keys()
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption()
        .collect();

    let mut sink = Vec::new();
    {
        let message = Message::new(&mut sink);
        let message = Armorer::new(message).build().unwrap();
        let message = Encryptor::for_recipients(message, recipient_keys)
            .build()
            .unwrap();
        let message = Compressor::new(message)
            .algo(CompressionAlgorithm::Zip)
            .build()
            .unwrap();
        let mut message = LiteralWriter::new(message).build().unwrap();
        let chunk = vec![0u8; 1024 * 1024];
        for _ in 0..(EXPANDED / chunk.len()) {
            std::io::Write::write_all(&mut message, &chunk).unwrap();
        }
        message.finalize().unwrap();
    }

    let ratio = EXPANDED as f64 / sink.len() as f64;
    println!(
        "bomb: {} byte ciphertext -> {} bytes ({ratio:.0}x amplification)",
        sink.len(),
        EXPANDED,
    );
    assert!(ratio > 100.0, "expected large amplification, got {ratio:.0}x");

    let handle = store_key(&priv_armor).unwrap();
    let outcome = decrypt_with_handle(&sink, handle, None);
    drop_key(handle).unwrap();

    match outcome {
        Ok(packed) => panic!(
            "decrypted {} bytes from a {} byte message with no cap -- \
             an attacker picks this number",
            packed.len(),
            sink.len(),
        ),
        Err(e) => {
            // The state we want: a bounded refusal.
            assert!(
                e.to_lowercase().contains("large") || e.to_lowercase().contains("limit"),
                "rejected, but not with a size error: {e}",
            );
        }
    }
}

/// REGRESSION -- the same bomb on the path that needs NO key.
///
/// `verify_message` is reachable from pasted text alone: no unlock, no
/// private key, no password. It inflates the compressed literal into
/// `content`, then puts that content into a JSON string -- and JSON
/// escaping of NUL bytes costs another 6x on top (`\u0000` per byte).
///
/// Measured: an 88 KB paste produced a 402 MB JSON string, ~4500x, which
/// then has to cross the wasm->JS boundary as a single value. This is a
/// strictly easier target than the decrypt path, and is capped harder
/// (`MAX_VERIFIED_BYTES`) precisely because of that escaping multiplier.
#[test]
fn verify_bomb_is_refused_by_the_size_cap() {
    use openpgp::serialize::stream::{Armorer, Compressor, LiteralWriter, Message, Signer};
    use openpgp::types::CompressionAlgorithm;

    const EXPANDED: usize = 64 * 1024 * 1024;

    let (pub_armor, priv_armor) = adv_keypair();
    let cert = openpgp::Cert::from_bytes(priv_armor.as_bytes()).unwrap();
    let vc = cert.with_policy(policy(), None).unwrap();
    let key = vc
        .keys()
        .secret()
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .unwrap();
    let keypair = key.key().clone().into_keypair().unwrap();

    let mut sink = Vec::new();
    {
        let message = Message::new(&mut sink);
        let message = Armorer::new(message).build().unwrap();
        let message = Compressor::new(message)
            .algo(CompressionAlgorithm::Zip)
            .build()
            .unwrap();
        let message = Signer::new(message, keypair).unwrap().build().unwrap();
        let mut message = LiteralWriter::new(message).build().unwrap();
        let chunk = vec![0u8; 1024 * 1024];
        for _ in 0..(EXPANDED / chunk.len()) {
            std::io::Write::write_all(&mut message, &chunk).unwrap();
        }
        message.finalize().unwrap();
    }

    let keys = serde_json::to_string(&vec![&pub_armor]).unwrap();
    let armored = String::from_utf8_lossy(&sink).to_string();

    match verify_message(&armored, &keys) {
        Ok(json) => panic!(
            "a {} byte paste produced a {} byte result ({:.0}x) with no cap",
            sink.len(),
            json.len(),
            json.len() as f64 / sink.len() as f64,
        ),
        Err(e) => assert!(
            e.to_lowercase().contains("large") || e.to_lowercase().contains("limit"),
            "rejected, but not with a size error: {e}",
        ),
    }
}

#[test]
fn read_capped_admits_exactly_the_limit_and_refuses_one_more() {
    // The boundary itself, away from any crypto: a cap that is off by one
    // either rejects a legitimate message of exactly the maximum size or
    // lets one byte through. Cheap to test exactly, so it is tested
    // exactly rather than inferred from the end-to-end bomb tests.
    let data = vec![b'x'; 1024];

    let exact = read_capped(&data[..], 1024u64, "message").unwrap();
    assert_eq!(exact.len(), 1024, "a message exactly at the limit was refused");

    let under = read_capped(&data[..], 1025u64, "message").unwrap();
    assert_eq!(under.len(), 1024);

    let err = read_capped(&data[..], 1023u64, "message").unwrap_err();
    assert!(err.contains("too large"), "unexpected error: {err}");

    // Empty input is not a special case.
    assert_eq!(read_capped(&[][..], 0u64, "message").unwrap().len(), 0);
}

#[test]
fn the_output_ceiling_follows_the_input_rather_than_a_flat_number() {
    // The property that lets a big FILE through while refusing a bomb.
    // A flat ceiling cannot do both: set it high enough for a 1 GiB file
    // and a 5 MiB paste that expands 750x sails under it.

    // A large legitimate file: ciphertext ~= plaintext, so its own size
    // buys its allowance.
    let one_gib = 1024 * 1024 * 1024usize;
    assert!(
        decrypt_limit(one_gib) >= one_gib as u64,
        "a 1 GiB file would be refused by its own limit",
    );

    // A bomb: a small ciphertext gets a small allowance, however much it
    // wants to expand to.
    let bomb_ciphertext = 89 * 1024usize; // the measured bomb
    assert!(
        decrypt_limit(bomb_ciphertext) < 100 * 1024 * 1024,
        "a tiny ciphertext was granted a huge allowance",
    );

    // Small messages are not squeezed by the ratio -- framing overhead
    // alone exceeds 4x for a short message.
    assert_eq!(decrypt_limit(200), MIN_EXPANSION_ALLOWANCE);
    assert_eq!(decrypt_limit(0), MIN_EXPANSION_ALLOWANCE);

    // Nothing may exceed what wasm32 can address, whatever the input.
    assert_eq!(decrypt_limit(usize::MAX), MAX_DECRYPTED_BYTES);

    // Verify stays far tighter: its output becomes one JSON String.
    assert!(MAX_VERIFIED_BYTES < MAX_DECRYPTED_BYTES);
}

