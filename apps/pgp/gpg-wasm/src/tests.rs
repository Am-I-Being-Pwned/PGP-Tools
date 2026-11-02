use super::*;

use std::time::{Duration, SystemTime};

use openpgp::cert::{CertBuilder, CipherSuite};
use openpgp::parse::Parse;
use openpgp::serialize::Serialize as _;
use openpgp::serialize::SerializeInto as _;
use openpgp::types::SymmetricAlgorithm;

fn gen_test_key() -> String {
    let opts = r#"{"name":"Test User","email":"test@example.com","type":"ecc"}"#;
    generate_key(opts).unwrap()
}

fn test_decrypt(
    ciphertext: &[u8],
    priv_armor: &str,
    verification_keys: Option<String>,
) -> (Vec<u8>, serde_json::Value) {
    let handle = store_key(priv_armor).unwrap();
    let packed = decrypt_with_handle(ciphertext, handle, verification_keys, None).unwrap();
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
fn test_generate_key_without_email() {
    // Email is optional: missing/blank yields a bare-name UID.
    for opts in [
        r#"{"name":"Nomail","type":"ecc"}"#,
        r#"{"name":"Nomail","email":"","type":"ecc"}"#,
        r#"{"name":"Nomail","email":"  ","type":"ecc"}"#,
    ] {
        let json = generate_key(opts).unwrap();
        let result: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(result["keyInfo"]["userIds"][0], "Nomail", "{opts}");
    }
    let opts = r#"{"name":"Nomail","comment":"work","type":"ecc"}"#;
    let json = generate_key(opts).unwrap();
    let result: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(result["keyInfo"]["userIds"][0], "Nomail (work)");
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

/// Created two days ago, valid for one; built directly because
/// `generate_key` can only date validity from now. (public, private) armor.
fn gen_expired_key() -> (String, String) {
    let (cert, _rev) = CertBuilder::new()
        .add_userid("Expired <expired@example.com>")
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .add_storage_encryption_subkey()
        .set_cipher_suite(CipherSuite::Cv25519)
        .set_creation_time(SystemTime::now() - Duration::from_secs(2 * 86_400))
        .set_validity_period(Duration::from_secs(86_400))
        .generate()
        .unwrap();
    (
        armor_cert(&cert, false).unwrap(),
        armor_cert(&cert, true).unwrap(),
    )
}

/// Encrypt-to-self: own key as sole recipient and signer ("Also encrypt to me").
#[test]
fn test_encrypt_to_myself_round_trip() {
    let gen: serde_json::Value = serde_json::from_str(&gen_test_key()).unwrap();
    let pub_armor = gen["publicKeyArmored"].as_str().unwrap();
    let priv_armor = gen["privateKeyArmored"].as_str().unwrap();

    let recipients = serde_json::to_string(&vec![pub_armor]).unwrap();
    let ciphertext = encrypt(
        b"note to self",
        &recipients,
        Some(priv_armor.to_string()),
        None,
    )
    .unwrap();

    let (plaintext, sig) = test_decrypt(&ciphertext, priv_armor, Some(recipients));
    assert_eq!(plaintext, b"note to self");
    assert_eq!(
        sig["signatureStatus"], "valid",
        "own signature should verify: {sig}"
    );
}

/// An expired key alone must fail, not yield an unreadable ciphertext.
#[test]
fn test_encrypt_to_expired_key_alone_fails() {
    let (expired_pub, _expired_priv) = gen_expired_key();
    let info: serde_json::Value =
        serde_json::from_str(&parse_key(&expired_pub).unwrap()).unwrap();
    assert_eq!(
        info["usableForEncryption"], false,
        "fixture should read as unusable: {info}"
    );

    let recipients = serde_json::to_string(&vec![expired_pub.as_str()]).unwrap();
    let err = encrypt(b"secret", &recipients, None, None)
        .expect_err("encrypting to only an expired key must not succeed");
    assert!(
        err.to_lowercase().contains("expired"),
        "error should say why the key was refused, got: {err}"
    );
}

/// Expired next to live: silently dropping the expired key would encrypt to
/// fewer people than asked, so the whole operation must be refused.
#[test]
fn test_encrypt_to_expired_and_live_key_is_refused() {
    let live: serde_json::Value = serde_json::from_str(&gen_test_key()).unwrap();
    let live_pub = live["publicKeyArmored"].as_str().unwrap();
    let (expired_pub, _) = gen_expired_key();

    for order in [
        vec![live_pub, expired_pub.as_str()],
        vec![expired_pub.as_str(), live_pub],
    ] {
        let recipients = serde_json::to_string(&order).unwrap();
        let result = encrypt(b"secret", &recipients, None, None);
        let err = result.expect_err("expired recipient must be refused, not silently dropped");
        assert!(
            err.to_lowercase().contains("expired"),
            "error should name the expiry, got: {err}"
        );
    }
}

/// An expired OWN key appended by "encrypt to me" is refused the same way.
#[test]
fn test_encrypt_to_self_with_expired_own_key_is_refused() {
    let contact: serde_json::Value = serde_json::from_str(&gen_test_key()).unwrap();
    let contact_pub = contact["publicKeyArmored"].as_str().unwrap();
    let (own_expired_pub, _own_expired_priv) = gen_expired_key();

    // Unsigned so the refusal must come from the recipient check, not the signer.
    let recipients =
        serde_json::to_string(&vec![contact_pub, own_expired_pub.as_str()]).unwrap();
    let err = encrypt(b"secret", &recipients, None, None)
        .expect_err("own expired key must not be silently dropped");
    assert!(
        err.contains("expired") && err.contains("Expired <expired@example.com>"),
        "error should name the key and the expiry, got: {err}"
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

/// Regression: a missing signer key means "can't verify", not "fail to decrypt".
#[test]
fn test_decrypt_signed_without_signer_key_succeeds() {
    let recip = serde_json::from_str::<serde_json::Value>(&gen_test_key()).unwrap();
    let recip_pub = recip["publicKeyArmored"].as_str().unwrap();
    let recip_priv = recip["privateKeyArmored"].as_str().unwrap();

    let signer = serde_json::from_str::<serde_json::Value>(&gen_test_key()).unwrap();
    let signer_priv = signer["privateKeyArmored"].as_str().unwrap();

    let recipients = serde_json::to_string(&vec![recip_pub]).unwrap();
    let ciphertext =
        encrypt(b"Message from a stranger", &recipients, Some(signer_priv.to_string()), None)
            .unwrap();

    let (plaintext_bytes, sig) = test_decrypt(&ciphertext, recip_priv, None);
    assert_eq!(
        std::str::from_utf8(&plaintext_bytes).unwrap(),
        "Message from a stranger"
    );
    assert_eq!(sig["signatureValid"], false);
    assert_eq!(sig["signatureStatus"], "unknown_key");
}

#[test]
fn test_select_decryption_key_picks_the_recipient() {
    let a = serde_json::from_str::<serde_json::Value>(&gen_test_key()).unwrap();
    let b = serde_json::from_str::<serde_json::Value>(&gen_test_key()).unwrap();
    let a_pub = a["publicKeyArmored"].as_str().unwrap();
    let a_fpr = a["keyInfo"]["keyId"].as_str().unwrap();
    let b_pub = b["publicKeyArmored"].as_str().unwrap();
    let b_fpr = b["keyInfo"]["keyId"].as_str().unwrap();

    let recipients = serde_json::to_string(&vec![b_pub]).unwrap();
    let ciphertext = encrypt(b"pick me", &recipients, None, None).unwrap();

    // `a` listed first; must still choose `b`.
    let candidates = serde_json::to_string(&vec![a_pub, b_pub]).unwrap();
    let chosen = select_decryption_key(&ciphertext, &candidates).unwrap();
    let chosen: Option<String> = serde_json::from_str(&chosen).unwrap();
    assert_eq!(chosen.as_deref(), Some(b_fpr));
    assert_ne!(chosen.as_deref(), Some(a_fpr));

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
    let result_json = verify_message(&signed, &verification_keys, None).unwrap();
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

    let verify_json = verify_message(&signed, &verification_keys, None).unwrap();
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

    // Mirror JS: Argon2 derive, AES-GCM seal, then unlock in WASM.
    let password = b"test-password-123";
    let salt = b"16-byte-salt!!!!";
    let key_id = "test-key-id";

    let derived = argon2_derive(password, salt, 4096, 3, 1).unwrap();

    use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Nonce}};
    use aes_gcm::aead::Payload;
    let cipher = Aes256Gcm::new_from_slice(&derived).unwrap();
    let iv = [0u8; 12]; // fixed IV for test
    let nonce = &Nonce::<Aes256Gcm>::from(iv);
    let aad = format!("gpg-tools:password:{}", key_id);
    let ciphertext = cipher.encrypt(nonce, Payload {
        msg: priv_armor.as_bytes(),
        aad: aad.as_bytes(),
    }).unwrap();

    let handle = unlock_with_password(
        &ciphertext, &iv, salt, key_id, password.to_vec(), 4096, 3, 1,
    ).unwrap();
    assert!(handle > 0);

    let signed = sign_with_handle("unlock test", handle).unwrap();
    assert!(signed.contains("BEGIN PGP SIGNED MESSAGE"));

    drop_key(handle).unwrap();
}

#[test]
fn test_unlock_with_prf() {
    let gen_json = gen_test_key();
    let gen: serde_json::Value = serde_json::from_str(&gen_json).unwrap();
    let priv_armor = gen["privateKeyArmored"].as_str().unwrap();

    let prf_output = b"32-byte-fake-prf-output-for-test";
    let stored_secret = b"32-byte-fake-stored-secret-test!";
    let key_id = "test-key-id-prf";

    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(stored_secret.as_slice()), prf_output.as_slice());
    let mut derived = vec![0u8; 32];
    hk.expand(b"gpg-tools-prf-v1", &mut derived).unwrap();

    use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, Nonce}};
    use aes_gcm::aead::Payload;
    let cipher = Aes256Gcm::new_from_slice(&derived).unwrap();
    let iv = [1u8; 12];
    let nonce = &Nonce::<Aes256Gcm>::from(iv);
    let aad = format!("gpg-tools:passkey:{}", key_id);
    let ciphertext = cipher.encrypt(nonce, Payload {
        msg: priv_armor.as_bytes(),
        aad: aad.as_bytes(),
    }).unwrap();

    let handle = unlock_with_prf(
        &ciphertext, &iv, prf_output.to_vec(), stored_secret.to_vec(), key_id,
    ).unwrap();
    assert!(handle > 0);

    let signed = sign_with_handle("prf unlock test", handle).unwrap();
    assert!(signed.contains("BEGIN PGP SIGNED MESSAGE"));

    drop_key(handle).unwrap();
}

#[test]
fn test_reprotect_key_with_prf() {
    let gen_json = gen_test_key();
    let gen: serde_json::Value = serde_json::from_str(&gen_json).unwrap();
    let priv_armor = gen["privateKeyArmored"].as_str().unwrap();
    let key_id = gen["keyInfo"]["keyId"].as_str().unwrap();
    let handle = store_key(priv_armor).unwrap();

    let master_prf = vec![42u8; 32];
    let fresh_secret = vec![3u8; 32];
    let packed = reprotect_key_with_prf(handle, master_prf.clone(), fresh_secret.clone()).unwrap();
    // `[u32_le json_len][json][blob]`; metadata names the AAD fingerprint.
    let json_len = u32::from_le_bytes([packed[0], packed[1], packed[2], packed[3]]) as usize;
    let meta: serde_json::Value = serde_json::from_slice(&packed[4..4 + json_len]).unwrap();
    assert_eq!(meta["keyId"].as_str().unwrap(), key_id);
    let blob = packed[4 + json_len..].to_vec();
    assert!(blob.len() > 12);

    // Reprotect reads the source handle, it does not consume it.
    let signed = sign_with_handle("still unlocked", handle).unwrap();
    assert!(signed.contains("BEGIN PGP SIGNED MESSAGE"));

    let h2 = unlock_with_prf(
        &blob[12..],
        &blob[..12],
        master_prf.clone(),
        fresh_secret.clone(),
        key_id,
    )
    .unwrap();
    let signed = sign_with_handle("resealed", h2).unwrap();
    assert!(signed.contains("BEGIN PGP SIGNED MESSAGE"));

    // ...and not with a different PRF, stored secret, or identity.
    assert!(unlock_with_prf(
        &blob[12..],
        &blob[..12],
        vec![1u8; 32],
        fresh_secret.clone(),
        key_id
    )
    .is_err());
    assert!(unlock_with_prf(
        &blob[12..],
        &blob[..12],
        master_prf.clone(),
        vec![4u8; 32],
        key_id
    )
    .is_err());
    assert!(unlock_with_prf(
        &blob[12..],
        &blob[..12],
        master_prf.clone(),
        fresh_secret.clone(),
        "OTHER"
    )
    .is_err());

    drop_key(handle).unwrap();
    drop_key(h2).unwrap();
    assert!(reprotect_key_with_prf(handle, master_prf, fresh_secret).is_err());
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

// ── contacts session ─────────────────────────────────────────────────

/// Tests share a thread in any order, so start from no session.
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

    let prf_output_a = b"aaaa-fake-prf-output-32-bytes!!!";
    let stored_secret_a = b"aaaa-fake-stored-secret-32bytes!";
    init_contacts_session_with_prf(prf_output_a.to_vec(), stored_secret_a.to_vec()).unwrap();

    let packed = encrypt_contacts(b"secret contacts".to_vec()).unwrap();
    let iv = &packed[..12];
    let ciphertext = &packed[12..];

    let prf_output_b = b"bbbb-fake-prf-output-32-bytes!!!";
    let stored_secret_b = b"bbbb-fake-stored-secret-32bytes!";
    init_contacts_session_with_prf(prf_output_b.to_vec(), stored_secret_b.to_vec()).unwrap();

    let result = decrypt_contacts(ciphertext, iv);
    assert!(result.is_err());

    reset_contacts_session();
}

#[test]
fn test_contacts_session_replaced_on_reinit() {
    reset_contacts_session();

    let prf_a = b"aaaa-fake-prf-output-32-bytes!!!";
    let secret_a = b"aaaa-fake-stored-secret-32bytes!";
    init_contacts_session_with_prf(prf_a.to_vec(), secret_a.to_vec()).unwrap();
    let packed_a = encrypt_contacts(b"data-a".to_vec()).unwrap();

    // Re-init replaces the key, never accumulates.
    let prf_b = b"bbbb-fake-prf-output-32-bytes!!!";
    let secret_b = b"bbbb-fake-stored-secret-32bytes!";
    init_contacts_session_with_prf(prf_b.to_vec(), secret_b.to_vec()).unwrap();
    let packed_b = encrypt_contacts(b"data-b".to_vec()).unwrap();

    let iv_b = &packed_b[..12];
    let ct_b = &packed_b[12..];
    assert_eq!(decrypt_contacts(ct_b, iv_b).unwrap(), b"data-b");

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

    assert!(has_contacts_session());

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

    let packed = encrypt_canary_and_init_session(password.to_vec(), salt, 4096, 3, 1).unwrap();
    let canary_iv = &packed[..12];
    let canary_ct = &packed[12..];

    // Simulate app restart.
    drop_contacts_session();
    assert!(!has_contacts_session());

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

    let packed = encrypt_canary_and_init_session(password.to_vec(), salt, 4096, 3, 1).unwrap();
    let canary_iv = &packed[..12];
    let canary_ct = &packed[12..];

    drop_contacts_session();

    // Wrong password returns false and must NOT init the session.
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

    let packed = encrypt_canary_and_init_session(password.to_vec(), salt, 4096, 3, 1).unwrap();
    let canary_iv = &packed[..12];
    let canary_ct = &packed[12..];

    let contacts_packed = encrypt_contacts(b"[{\"keyId\":\"def456\"}]".to_vec()).unwrap();
    let contacts_iv = &contacts_packed[..12];
    let contacts_ct = &contacts_packed[12..];

    drop_contacts_session();

    let ok = verify_canary_and_init_session(canary_ct, canary_iv, password.to_vec(), salt, 4096, 3, 1).unwrap();
    assert!(ok);

    let decrypted = decrypt_contacts(contacts_ct, contacts_iv).unwrap();
    assert_eq!(decrypted, b"[{\"keyId\":\"def456\"}]");

    reset_contacts_session();
}

#[test]
fn test_contacts_key_domain_separation_password_vs_prf() {
    reset_contacts_session();

    let password = b"test-password-for-sep";
    let salt = b"16-byte-salt!!!!";
    encrypt_canary_and_init_session(password.to_vec(), salt, 4096, 3, 1).unwrap();
    let packed = encrypt_contacts(b"password-contacts".to_vec()).unwrap();
    let iv = &packed[..12];
    let ct = &packed[12..];

    // PRF-derived session must not open password-derived contacts.
    let prf_output = b"32-byte-fake-prf-output-for-test";
    let stored_secret = b"32-byte-fake-stored-secret-test!";
    init_contacts_session_with_prf(prf_output.to_vec(), stored_secret.to_vec()).unwrap();

    assert!(decrypt_contacts(ct, iv).is_err());

    reset_contacts_session();
}

#[test]
fn test_empty_contacts_encrypt_decrypt() {
    reset_contacts_session();

    let prf_output = b"32-byte-fake-prf-output-for-test";
    let stored_secret = b"32-byte-fake-stored-secret-test!";
    init_contacts_session_with_prf(prf_output.to_vec(), stored_secret.to_vec()).unwrap();

    let packed = encrypt_contacts(b"[]".to_vec()).unwrap();
    let iv = &packed[..12];
    let ct = &packed[12..];
    assert_eq!(decrypt_contacts(ct, iv).unwrap(), b"[]");

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

    let large_data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    let packed = encrypt_contacts(large_data.clone()).unwrap();
    let iv = &packed[..12];
    let ct = &packed[12..];
    assert_eq!(decrypt_contacts(ct, iv).unwrap(), large_data);

    reset_contacts_session();
}

// ── per-store envelope (domain separation) ──────────────────────────

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

    // The replay the old scheme accepted: seg_0's blob in the seg_1 slot.
    let packed = encrypt_store("pgp_history_seg_0", b"[{\"id\":\"a\"}]".to_vec()).unwrap();
    let (iv, ct) = packed.split_at(12);

    assert!(decrypt_store("pgp_history_seg_1", ct, iv).is_err());
    // The correct slot still opens it, so the failure is the domain binding.
    assert!(decrypt_store("pgp_history_seg_0", ct, iv).is_ok());

    reset_contacts_session();
}

#[test]
fn test_store_envelope_rejects_a_blob_from_another_store() {
    init_test_contacts_session();

    let packed = encrypt_store("pgp_history_seg_0", b"[{\"id\":\"a\"}]".to_vec()).unwrap();
    let (iv, ct) = packed.split_at(12);

    // Cross-store substitution must fail the tag check, not decode to an
    // empty list.
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

    // Legacy (shared CONTACTS_AAD) and domain-bound blobs must not open as each
    // other, so the JS "try new, fall back to legacy" read is unambiguous.
    let legacy = encrypt_contacts(b"[{\"id\":\"legacy\"}]".to_vec()).unwrap();
    let (l_iv, l_ct) = legacy.split_at(12);
    assert!(decrypt_store("pgp_public_contacts", l_ct, l_iv).is_err());
    assert!(decrypt_contacts(l_ct, l_iv).is_ok());

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
    // An empty domain would collapse every store onto one subkey: rejected.
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
    // Deterministic, or stored blobs are unreadable after a reload.
    assert_eq!(a.as_slice(), a_again.as_slice());
    // Distinct from the session key, so one leaked subkey hands over nothing else.
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

    // Past a full ~64 KB history segment.
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

    // Master lock: subkeys have no independent lifetime.
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

    if let Some(byte) = canary_ct.last_mut() {
        *byte ^= 0xFF;
    }

    // Fails gracefully: false, not panic/error.
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

    assert_eq!(rows.len(), 4);

    assert_eq!(rows[0]["isPrimary"], true);
    assert_eq!(rows[0]["canCertify"], true);
    assert_eq!(rows[0]["status"], "active");
    let key_info: serde_json::Value =
        serde_json::from_str(&parse_key(pub_armor).unwrap()).unwrap();
    assert_eq!(rows[0]["fingerprint"], key_info["keyId"]);

    let subkeys: Vec<_> = rows.iter().skip(1).collect();
    assert!(subkeys.iter().all(|r| r["isPrimary"] == false));
    assert!(subkeys.iter().all(|r| r["status"] == "active"));
    assert_eq!(subkeys.iter().filter(|r| r["canSign"] == true).count(), 1);
    assert_eq!(subkeys.iter().filter(|r| r["canEncrypt"] == true).count(), 2);

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

    // "Publishing a revocation": only the primary is revoked.
    let cert = openpgp::Cert::from_bytes(pub_armor.as_bytes()).unwrap();
    let rev_packet = openpgp::Packet::from_bytes(rev_armor.as_bytes()).unwrap();
    let revoked_cert = cert.insert_packets(rev_packet).unwrap().0;
    let revoked_armor = String::from_utf8(revoked_cert.armored().to_vec().unwrap()).unwrap();

    let details: serde_json::Value =
        serde_json::from_str(&parse_key_details(&revoked_armor).unwrap()).unwrap();
    let rows = details["keys"].as_array().unwrap();
    assert_eq!(rows.len(), 4);

    // Every row must read revoked; a subkey cannot outlive its certificate.
    for row in rows {
        assert_eq!(row["status"], "revoked", "row: {row}");
    }
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

    let layout = Layout::from_size_align(4096, 16).unwrap();
    unsafe {
        let p1 = alloc(layout);
        assert!(!p1.is_null());
        std::ptr::write_bytes(p1, 0xAB, layout.size());
        // Our GlobalAlloc::dealloc must wipe it.
        dealloc(p1, layout);

        // dlmalloc's LIFO free list hands the just-freed block back.
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

/// Regression: GnuPG pads ECC secret scalars to field size, which Sequoia's
/// strict MPI parser rejects; `decrypt_gpg_padded_secret` handles it.
/// Throwaway test key.
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
    assert_eq!(error_code::error_code(&err), Some(ErrorCode::WrongPassphrase));
    assert_eq!(error_code::message(&err), "Incorrect passphrase");
}

/// The CFB fallback's cipher/key/IV come from an untrusted key file, so a
/// size mismatch must be `Err`, never a panic (a wasm panic aborts the
/// module and the panel with its unlocked keys).
#[test]
fn cfb_decrypt_rejects_bad_sizes_instead_of_panicking() {
    let ct = [0u8; 48];

    assert!(crate::cfb_decrypt(SymmetricAlgorithm::AES256, &[0u8; 16], &[0u8; 16], &ct).is_err());
    assert!(crate::cfb_decrypt(SymmetricAlgorithm::AES128, &[0u8; 32], &[0u8; 16], &ct).is_err());
    // 8-byte IV (a 64-bit-block cipher's) used to panic.
    assert!(crate::cfb_decrypt(SymmetricAlgorithm::AES256, &[0u8; 32], &[0u8; 8], &ct).is_err());
    assert!(crate::cfb_decrypt(SymmetricAlgorithm::AES256, &[0u8; 32], &[], &ct).is_err());

    let err =
        crate::cfb_decrypt(SymmetricAlgorithm::Twofish, &[0u8; 32], &[0u8; 16], &ct).unwrap_err();
    assert!(err.contains("--s2k-cipher-algo AES256"), "{err}");

    // Partial and empty final blocks are reachable from a truncated key packet.
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

/// Same for the vault AEAD: a JS-supplied IV of the wrong length is `Err`.
#[test]
fn aes_gcm_decrypt_rejects_bad_iv_length_instead_of_panicking() {
    let ct = [0u8; 32];
    for iv_len in [0usize, 8, 11, 13, 16] {
        let err = crate::aes_gcm_decrypt(&[0u8; 32], &vec![0u8; iv_len], &ct, b"").unwrap_err();
        assert!(err.contains("malformed IV"), "{iv_len}: {err}");
    }
}

/// A revocation minted for a stored key (imported-key backfill) must revoke
/// the cert and pass our own import policy.
#[test]
fn minted_revocation_certificate_revokes_the_cert() {
    let generated: serde_json::Value =
        serde_json::from_str(&gen_test_key()).unwrap();
    let private_armor = generated["privateKeyArmored"].as_str().unwrap();

    let handle = store_key(private_armor).unwrap();
    let revocation = revocation_certificate_with_handle(handle).unwrap();
    drop_key(handle).unwrap();
    assert!(revocation.contains("BEGIN PGP SIGNATURE"));

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


// ── entropy under a poisoned platform RNG (src/rng.rs) ───────────────

/// With `getRandomValues` pinned to a constant, GCM nonces must not repeat.
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

/// A fixed Argon2id salt would collapse every vault into one KDF space.
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

// ── owned-credential params on the canary exports ────────────────────
// These gate master unlock (SECURITY.md §8.4, T-UNLOCK-PARAM-NOT-OWNED): a
// regression locks every user out, so a pre-change canary is frozen below.

#[test]
fn test_canary_round_trip_through_owned_password_params() {
    reset_contacts_session();

    let password = b"owned-param-master-password";
    let salt = b"16-byte-salt!!!!";

    // A fresh `Vec` per call, as wasm-bindgen hands over.
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

/// Canary from the shipped build when the param was `&[u8]`, as
/// `[IV][ct||tag]`. Never regenerate: it proves the at-rest format held.
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
    // Must restore a usable session, not merely report true.
    assert!(has_contacts_session());
    let sealed = encrypt_contacts(b"post-unlock".to_vec()).unwrap();
    assert_eq!(
        decrypt_contacts(&sealed[12..], &sealed[..12]).unwrap(),
        b"post-unlock"
    );

    reset_contacts_session();
}

// ── canary domain label ──────────────────────────────────────────────
// Under legacy `CONTACTS_AAD` the canary opened via the legacy store
// fallback, so planted in a store slot it read as a corrupt store.

#[test]
fn test_new_canary_is_not_a_legacy_store_blob() {
    reset_contacts_session();

    let password = b"canary-label-password";
    let salt = b"16-byte-salt!!!!";
    let packed = encrypt_canary_and_init_session(password.to_vec(), salt, 4096, 3, 1).unwrap();

    // Same session key, yet neither store envelope opens it.
    assert!(has_contacts_session());
    assert!(
        decrypt_contacts(&packed[12..], &packed[..12]).is_err(),
        "a new canary must not open as a legacy shared-envelope store blob"
    );
    assert!(decrypt_store("pgp_keyring", &packed[12..], &packed[..12]).is_err());

    drop_contacts_session();
    assert!(
        verify_canary_and_init_session(&packed[12..], &packed[..12], password.to_vec(), salt, 4096, 3, 1)
            .unwrap()
    );
    reset_contacts_session();
}

#[test]
fn test_legacy_label_canary_still_verifies_and_wrong_password_fails() {
    reset_contacts_session();

    let password = b"legacy-label-password";
    let salt = b"16-byte-salt!!!!";
    // What a pre-label build wrote: derived key, CONTACTS_AAD.
    let key = derive_contacts_key_from_password(password, salt, 4096, 3, 1).unwrap();
    let packed = aes_gcm_encrypt(&key, CANARY_PLAINTEXT, CONTACTS_AAD).unwrap();

    assert!(
        verify_canary_and_init_session(&packed[12..], &packed[..12], password.to_vec(), salt, 4096, 3, 1)
            .unwrap()
    );
    assert!(has_contacts_session());

    drop_contacts_session();
    assert!(
        !verify_canary_and_init_session(&packed[12..], &packed[..12], b"wrong".to_vec(), salt, 4096, 3, 1)
            .unwrap()
    );
    assert!(!has_contacts_session());
    reset_contacts_session();
}

#[test]
fn test_argon2_derive_owned_matches_borrowed_helper() {
    let password = b"argon2-owned-vs-borrowed";
    let salt = b"16-byte-salt!!!!";

    // The exported wrapper changes only marshalling; bytes must match.
    let owned = argon2_derive_owned(password.to_vec(), salt, 4096, 3, 1).unwrap();
    let borrowed = argon2_derive(password, salt, 4096, 3, 1).unwrap();
    assert_eq!(owned, borrowed);
    assert_eq!(owned.len(), 32);

    assert!(argon2_derive_owned(password.to_vec(), b"short", 4096, 3, 1).is_err());
}

// ── symmetric decryption (`gpg -c`) ──────────────────────────────────
// Vectors come from real GnuPG 2.5.21: a self round-trip would pass a
// self-consistent wrong implementation, and this app cannot encrypt them.
// All decrypt to `SYMMETRIC_PLAINTEXT`; the fixture password guards nothing.

/// Owned per call: the export takes `Vec<u8>` to zeroize it.
fn symmetric_password() -> Vec<u8> {
    b"correct horse battery staple".to_vec()
}
const SYMMETRIC_PLAINTEXT: &[u8] = b"the password is the key";

/// `gpg -c --rfc4880`: v4 SKESK, AES-256-CFB, MDC. A wrong password fails
/// late, as an MDC mismatch.
const GPG_SYMMETRIC_V4: &str = "-----BEGIN PGP MESSAGE-----\n\n\
jA0ECQMIgYlslpAs65D/0lEB7S0K0+CFdt0IhAB8VpcBcK/6SkSMUGzegcLuFyBj\n\
KAFUrRe5nBt9CNXSIRuIDsj+k2V4YT+ZnsBO4kx2F3RFv3sKEN8v1cKMq86Qif+p\n\
wjg=\n\
=AEHv\n\
-----END PGP MESSAGE-----\n";

/// `gpg -c --force-ocb`: AEAD; a wrong password fails at the unwrap.
const GPG_SYMMETRIC_OCB: &str = "-----BEGIN PGP MESSAGE-----\n\n\
jE0FCQIDCFDkvEpE6tIy/xwgVAOzARqn7B1V/V0igvN9GNaewd51FLEE94tolfSs\n\
tDn7/sE05fHil10ZCdhTAnGx7bVB6yGRd7UX5yttXNRbAQkCEFu+HvJvMd14ux7U\n\
BAvbQR/CoZcWMx90z36ymHrm5LUALjtjcYkd3M0qyXdT2V1xx22/z/fY7vH/vASM\n\
ZEoKujuEOCe/thf7tS6NbpbbXH2lOPGdUySXjA==\n\
=u+/p\n\
-----END PGP MESSAGE-----\n";

/// `gpg -c --sign`: the password path must classify the signature too.
const GPG_SYMMETRIC_SIGNED: &str = "-----BEGIN PGP MESSAGE-----\n\n\
jA0ECQMIGI2S2lO8Ow//0sA6AZNUChy/HdmSVtZ1OomQSmWGl4iQkkxbBNgAE/Gs\n\
85JsksQ735CORnLNEZsgxQDcwPGSkZGEaeexL5H9ShMxBOqNBvfkX1AI80b04oz9\n\
A5rY4+cULCTlVRtCNvEQxBjxev308EIiUgwfsuixT3KW3/EgQIid62q4sSFMwuWu\n\
WiBxZq2I/AWd5FGNMs589tVMeRTdfaIEg5i79MoovtNILe+ZdDnGeThg890vZUIo\n\
wmk8j9C8z6U/hZzCmdF5zUX2I0RLhhF7sB/Xbp085L7ZRGiK6EFkelNIpPkaVB+e\n\
C3K0w4Vhhii7ewxRfBHAJDjD+C88gOP6D71FRA==\n\
=mTY0\n\
-----END PGP MESSAGE-----\n";

/// Public signer of `GPG_SYMMETRIC_SIGNED`.
const GPG_SYMMETRIC_SIGNER: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\
mDMEapBj+RYJKwYBBAHaRw8BAQdADK/m+TiE39BTvOnrevM5ZRBr5FLywpXfnvNa\n\
LGXZjSW0HFN5bSBUZXN0ZXIgPHN5bUBleGFtcGxlLmNvbT6ItQQTFgoAXRYhBPh3\n\
rp5NlKEkUyjYtVaANUzeCGrsBQJqkGP5GxSAAAAAAAQADm1hbnUyLDIuNSsxLjEy\n\
LDAsMwIbAwUJBaOagAULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRBWgDVM\n\
3ghq7NNnAP4xvjE6iWb4K4T0+2fc9Htrktm6AJ822zkVQpfuInMizQD/ZfvFjcyH\n\
q5wr07KTsVKIOf8NZ9563BA2VmWN/bKk8Ao=\n\
=6IJK\n\
-----END PGP PUBLIC KEY BLOCK-----\n";

fn unpack(packed: &[u8]) -> (Vec<u8>, serde_json::Value) {
    let sig_len = u32::from_le_bytes([packed[0], packed[1], packed[2], packed[3]]) as usize;
    let sig: serde_json::Value =
        serde_json::from_str(std::str::from_utf8(&packed[4..4 + sig_len]).unwrap()).unwrap();
    (packed[4 + sig_len..].to_vec(), sig)
}

#[test]
fn test_decrypt_password_gpg_v4() {
    let packed =
        decrypt_with_password(GPG_SYMMETRIC_V4.as_bytes(), symmetric_password(), None, None).unwrap();
    let (plaintext, sig) = unpack(&packed);
    assert_eq!(plaintext, SYMMETRIC_PLAINTEXT);
    assert_eq!(sig["signatureStatus"], "unsigned");
}

#[test]
fn test_decrypt_password_names_the_unreadable_aead_format() {
    // Pre-RFC-9580 AED is rejected by policy. It must read as unreadable, not
    // "wrong password": no password opens it. The right password is used on
    // purpose.
    let err =
        decrypt_with_password(GPG_SYMMETRIC_OCB.as_bytes(), symmetric_password(), None, None).unwrap_err();
    assert!(err.contains("AEAD (OCB)"), "unexpected error: {err}");
    assert!(!err.contains("Wrong password"), "unexpected error: {err}");
}

#[test]
fn test_decrypt_password_verifies_a_signature() {
    let certs = serde_json::to_string(&vec![GPG_SYMMETRIC_SIGNER]).unwrap();
    let packed = decrypt_with_password(
        GPG_SYMMETRIC_SIGNED.as_bytes(),
        symmetric_password(),
        Some(certs),
        None,
    )
    .unwrap();
    let (plaintext, sig) = unpack(&packed);
    assert_eq!(plaintext, SYMMETRIC_PLAINTEXT);
    assert_eq!(sig["signatureStatus"], "valid");
    assert_eq!(sig["signatureValid"], true);
}

#[test]
fn test_decrypt_password_signed_without_the_signer_key() {
    // No certs: decryption still succeeds; an uncheckable signature is a status.
    let packed = decrypt_with_password(
        GPG_SYMMETRIC_SIGNED.as_bytes(),
        symmetric_password(),
        None,
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
    // v4 SKESK has no integrity check, so a wrong password surfaces as an MDC
    // error; it must still read as a password problem, not corruption.
    let err =
        decrypt_with_password(GPG_SYMMETRIC_V4.as_bytes(), b"not the password".to_vec(), None, None).unwrap_err();
    assert_eq!(error_code::error_code(&err), Some(ErrorCode::SymmetricWrongPassword), "{err}");
    assert!(
        error_code::message(&err).starts_with("Wrong password, or this message is damaged:"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_decrypt_password_refuses_a_key_encrypted_message() {
    // No SKESK: fail, never fall back to another route.
    let key = gen_test_key();
    let parsed: serde_json::Value = serde_json::from_str(&key).unwrap();
    let public = parsed["publicKeyArmored"].as_str().unwrap();
    let recipients = serde_json::to_string(&vec![public]).unwrap();
    let ciphertext = encrypt(b"hello", &recipients, None, None).unwrap();

    let err = decrypt_with_password(&ciphertext, symmetric_password(), None, None).unwrap_err();
    assert_eq!(error_code::error_code(&err), Some(ErrorCode::SymmetricWrongPassword), "{err}");
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
    // The detector reads only the packets in front of the container. The OCB
    // SKESK parses as `Packet::Unknown`, so it must match on TAG, not variant.
    let json = message_encryption(GPG_SYMMETRIC_OCB.as_bytes()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["password"], true);
    assert_eq!(parsed["publicKey"], false);
}

#[test]
fn test_message_encryption_rejects_non_pgp_input() {
    assert!(message_encryption(b"not a pgp message at all").is_err());
}



// ── symmetric encryption ─────────────────────────────────────────────

#[test]
fn test_encrypt_with_password_round_trips() {
    let ct = encrypt(
        b"symmetric hello",
        "[]",
        None,
        Some(symmetric_password()),
    )
    .unwrap();
    let packed = decrypt_with_password(&ct, symmetric_password(), None, None).unwrap();
    let (plaintext, sig) = unpack(&packed);
    assert_eq!(plaintext, b"symmetric hello");
    assert_eq!(sig["signatureStatus"], "unsigned");
}

#[test]
fn test_encrypt_with_password_produces_a_password_only_message() {
    // No recipients means no PKESK: the UI's detector sees password-only.
    let ct = encrypt(b"x", "[]", None, Some(symmetric_password())).unwrap();
    let enc: serde_json::Value =
        serde_json::from_str(&message_encryption(&ct).unwrap()).unwrap();
    assert_eq!(enc["password"], true);
    assert_eq!(enc["publicKey"], false);
}

#[test]
fn test_encrypt_with_password_is_additive_not_a_mode() {
    // A password ADDS an SKESK alongside recipients; both must open it.
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

    let (by_password, _) =
        unpack(&decrypt_with_password(&ct, symmetric_password(), None, None).unwrap());
    assert_eq!(by_password, b"both ways");

    let (by_key, _) = test_decrypt(&ct, priv_armor, None);
    assert_eq!(by_key, b"both ways");
}

#[test]
fn test_encrypt_with_password_and_a_signature() {
    // Sign + password: the signature must verify on the password path.
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
        unpack(&decrypt_with_password(&ct, symmetric_password(), Some(certs), None).unwrap());
    assert_eq!(plaintext, b"signed and sealed");
    assert_eq!(sig["signatureStatus"], "valid");
}

#[test]
fn test_encrypt_refuses_a_message_nobody_could_open() {
    // No recipients and no password: a message nothing can open must be refused.
    let err = encrypt(b"x", "[]", None, None).unwrap_err();
    assert!(err.contains("nothing could open this message"), "{err}");
}

#[test]
fn test_encrypt_with_password_rejects_the_wrong_password() {
    let ct = encrypt(b"x", "[]", None, Some(symmetric_password())).unwrap();
    let err = decrypt_with_password(&ct, b"not it".to_vec(), None, None).unwrap_err();
    assert_eq!(error_code::error_code(&err), Some(ErrorCode::SymmetricWrongPassword), "{err}");
}

#[test]
fn test_encrypt_with_password_uses_aes256_and_the_max_s2k() {
    // Asserted, not trusted to a dependency's `Default`. The S2K count is the
    // largest the wire format can encode (0x3e00000).
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

/// Our password-encrypted message must open in real GnuPG; skipped when `gpg`
/// is absent (as `age_cli_decrypts_our_ciphertext`).
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

// ── adversarial ──────────────────────────────────────────────────────
// Against the claims in README/SECURITY.md: tampered or truncated
// ciphertext yields NO plaintext; a signature cannot be transplanted;
// `signatureValid: true` is never reachable from attacker-chosen keys;
// hostile bytes give Err, never a panic (a wasm panic kills the engine).

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

/// De-armor so corruption lands on ciphertext, not base64 framing/CRC.
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
    // Exhaustive single-bit flips: an error or the true message, never altered
    // plaintext. A flip in the PKESK's advisory key ID still decrypts (Sequoia
    // tries held keys); that is safe.
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

            match decrypt_with_handle(&corrupted, handle, None, None) {
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

    // Guards against the loop passing vacuously.
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
    // Every truncation must error: a streaming decryptor emitting before the
    // integrity check would return the prefix. The plaintext spans many reads
    // so it cannot be validated within one buffer.
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
            decrypt_with_handle(truncated, handle, None, None).is_err(),
            "truncating {cut} bytes still produced output",
        );
    }

    drop_key(handle).unwrap();
}

#[test]
fn decrypt_with_a_non_recipient_handle_fails() {
    // The wrong private key must error, not return an empty success.
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
    let result = decrypt_with_handle(&ciphertext, wrong_handle, None, None);
    drop_key(wrong_handle).unwrap();

    assert!(result.is_err(), "a non-recipient key decrypted the message");
}

// ── signature binding ────────────────────────────────────────────────

#[test]
fn cleartext_signature_does_not_transfer_to_other_text() {
    let (pub_armor, priv_armor) = adv_keypair();
    let signed = sign_message("transfer 10 to alice", &priv_armor).unwrap();
    let keys = serde_json::to_string(&vec![&pub_armor]).unwrap();

    let swapped = signed.replace("transfer 10 to alice", "transfer 99 to mallory");
    assert_ne!(swapped, signed, "test did not actually alter the body");

    // Rejected or invalid are both safe; never `valid`.
    if let Ok(json) = verify_message(&swapped, &keys, None) {
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_ne!(v["signatureStatus"], "valid", "swapped body verified");
        assert_eq!(v["signatureValid"], false);
    }
}

#[test]
fn cleartext_signature_rejects_a_single_character_edit() {
    let (pub_armor, priv_armor) = adv_keypair();
    let signed = sign_message("balance: 100", &priv_armor).unwrap();
    let keys = serde_json::to_string(&vec![&pub_armor]).unwrap();

    let edited = signed.replace("balance: 100", "balance: 900");

    if let Ok(json) = verify_message(&edited, &keys, None) {
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_ne!(v["signatureStatus"], "valid");
    }
}

fn inline_signed(text: &str, priv_armor: &str) -> String {
    use openpgp::serialize::stream::{Armorer, LiteralWriter, Message, Signer};

    let cert = openpgp::Cert::from_bytes(priv_armor.as_bytes()).unwrap();
    let keypair = signing_keypair(&cert).unwrap();
    let mut sink = Vec::new();
    {
        let message = Armorer::new(Message::new(&mut sink)).build().unwrap();
        let message = Signer::new(message, keypair).unwrap().build().unwrap();
        let mut message = LiteralWriter::new(message).build().unwrap();
        std::io::Write::write_all(&mut message, text.as_bytes()).unwrap();
        message.finalize().unwrap();
    }
    String::from_utf8(sink).unwrap()
}

#[test]
fn cleartext_text_outside_the_signed_block_is_refused() {
    // A signed post wrapped in an attacker's words must not come back with the
    // signer's name on it.
    let (pub_armor, priv_armor) = adv_keypair();
    let signed = sign_message("The quick brown fox.", &priv_armor).unwrap();
    let keys = serde_json::to_string(&vec![&pub_armor]).unwrap();
    let other = sign_message("A second notice.", &priv_armor).unwrap();
    let with_comment = signed.replacen(
        "-----BEGIN PGP SIGNED MESSAGE-----\n",
        "-----BEGIN PGP SIGNED MESSAGE-----\nComment: pay account 12345678\n",
        1,
    );
    assert_ne!(with_comment, signed, "test did not insert the header");

    let hash_line = signed.lines().nth(1).unwrap().to_string();
    let sig_begin = "-----BEGIN PGP SIGNATURE-----\n";
    let sig_at = signed.find(sig_begin).unwrap();
    let body_at = signed.find("\n\n").unwrap() + 2;
    let end_at = signed.find("-----END PGP SIGNATURE-----").unwrap();
    let inline = inline_signed("A notice.", &priv_armor);
    let in_hash = |extra: &str| signed.replacen(&format!("{hash_line}\n"), &format!("{hash_line}{extra}\n"), 1);
    let in_sig = |extra: &str| signed.replacen(sig_begin, &format!("{sig_begin}{extra}"), 1);

    let wrapped = [
        format!("Pay invoices to account 12345678.\n\n{signed}"),
        format!("{signed}\nP.S. Ignore the old account.\n"),
        format!("Pay 12345678.\n{signed}\nP.S. Ignore the old account."),
        format!("{signed}\n{other}"),
        format!("Pay 12345678.\n{inline}"),
        format!("{inline}\nP.S. Ignore the old account."),
        with_comment,
        in_hash("\nHash: Pay account 12345678 from now on"),
        in_hash("\u{2028}Pay account 12345678\u{2028}"),
        in_hash("\rPay account 12345678"),
        in_hash("\u{85}Pay account 12345678"),
        in_sig("Note: Bob's account changed.\nPay account 12345678 from now on.\n\n"),
        inline.replacen(
            "-----BEGIN PGP MESSAGE-----\n",
            "-----BEGIN PGP MESSAGE-----\nNote: from Alice\nPay account 12345678.\n\n",
            1,
        ),
        // A whitespace "quote prefix" Sequoia strips from every body line.
        format!("  -----BEGIN PGP SIGNED MESSAGE-----\n  \n10{}", &signed[body_at..]),
        format!("\t\t-----BEGIN PGP SIGNED MESSAGE-----\n\t\t\n10{}", &signed[body_at..]),
        format!(
            "{}---BEGIN PGP SIGNATURE ends here\nNote: x\nPay 12345678.\n{}",
            &signed[..sig_at],
            &signed[sig_at..],
        ),
        format!("{}Pay 12345678.\n{}", &signed[..end_at], &signed[end_at..]),
    ];

    for input in wrapped {
        let err = verify_message(&input, &keys, None).expect_err("wrapped message was not refused");
        assert!(err.contains("outside the signed part"), "unexpected error: {err}");
    }
}

#[test]
fn cleartext_whitespace_and_line_endings_around_the_block_still_verify() {
    // Real-world pastes must still verify: blank lines, CRLF, BOM, no `Hash:`,
    // a GPGTools `Comment:`.
    let (pub_armor, priv_armor) = adv_keypair();
    let signed = sign_message("line one\n- dashed line\n-----BEGIN PGP SIGNATURE-----", &priv_armor)
        .unwrap();
    let keys = serde_json::to_string(&vec![&pub_armor]).unwrap();
    let hash_line = signed.lines().nth(1).unwrap().to_string();
    let sig_begin = "\n-----BEGIN PGP SIGNATURE-----\n";

    for input in [
        signed.clone(),
        format!("\n\n{signed}\n\n   \n"),
        signed.replace('\n', "\r\n"),
        format!("\u{feff}{signed}"),
        signed.replacen(&format!("{hash_line}\n"), "", 1),
        signed.replacen(sig_begin, &format!("{sig_begin}Comment: GPGTools - https://gpgtools.org\n"), 1),
        inline_signed("A notice.", &priv_armor),
    ] {
        let json = verify_message(&input, &keys, None).unwrap_or_else(|e| panic!("{e}: {input:?}"));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["signatureStatus"], "valid", "input: {input:?}");
    }
}

#[test]
fn verification_against_an_attacker_chosen_key_is_never_valid() {
    // A different offered key (contact import, GitHub lookup) must never mint
    // `valid`.
    let (_signer_pub, signer_priv) = adv_keypair();
    let (attacker_pub, _attacker_priv) = adv_keypair();

    let signed = sign_message("authentic notice", &signer_priv).unwrap();
    let attacker_keys = serde_json::to_string(&vec![&attacker_pub]).unwrap();

    let json = verify_message(&signed, &attacker_keys, None).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();

    assert_ne!(v["signatureStatus"], "valid");
    assert_eq!(v["signatureValid"], false);
    assert_eq!(v["signatureStatus"], "unknown_key");
}

#[test]
fn signed_and_encrypted_body_tamper_is_never_reported_valid() {
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

        if let Ok(packed) = decrypt_with_handle(&corrupted, handle, Some(keys.clone()), None) {
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
    // A wasm panic aborts the engine until reload; each must be Err.
    let hostile: Vec<&[u8]> = vec![
        b"",
        b"\x00",
        b"\xff\xff\xff\xff",
        b"not armor at all",
        b"-----BEGIN PGP MESSAGE-----",
        b"-----BEGIN PGP MESSAGE-----\n\n-----END PGP MESSAGE-----",
        b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----",
        b"-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n////\n-----END PGP PRIVATE KEY BLOCK-----",
        b"\xc2\xff\xff\xff\xff\x01",
        b"-----BEGIN PGP MESSAGE-----\n\nSGVsbG8gd29ybGQh\n-----END PGP MESSAGE-----",
    ];

    for input in hostile {
        let text = String::from_utf8_lossy(input).to_string();

        let _ = parse_key(&text);
        let _ = parse_keys(&text);
        let _ = parse_key_details(&text);
        let _ = extract_public_key(&text);
        let _ = is_secret_encrypted(&text);

        let _ = message_encryption(input);
        let _ = verify_message(&text, "[]", None);
        let _ = decrypt_with_password(input, b"password".to_vec(), None, None);
        let _ = select_decryption_key(input, "[]");
    }
}

#[test]
fn a_dropped_handle_cannot_be_reused() {
    // A locked key's handle must be dead, not usable by remembered number.
    let (pub_armor, priv_armor) = adv_keypair();
    let ciphertext = encrypt(b"secret", &adv_recipients(&pub_armor), None, None).unwrap();

    let handle = store_key(&priv_armor).unwrap();
    assert!(decrypt_with_handle(&ciphertext, handle, None, None).is_ok());

    drop_key(handle).unwrap();

    assert!(
        decrypt_with_handle(&ciphertext, handle, None, None).is_err(),
        "a dropped handle still decrypted",
    );
    assert!(get_key_armored(handle).is_err(), "a dropped handle still exported");
}

#[test]
fn an_unissued_handle_is_never_valid() {
    for handle in [0u32, 1, 2, 42, u32::MAX] {
        let _ = decrypt_with_handle(b"whatever", handle, None, None);
        assert!(
            get_key_armored(handle).is_err(),
            "handle {handle} resolved to a key without being issued",
        );
    }
}

/// Regression: decompression bomb. Pasted input picks the expansion factor
/// (~1000x for deflate), enough to abort 32-bit wasm. Capped by
/// `MAX_DECRYPTED_BYTES` and the expansion ratio.
#[test]
fn decompression_bomb_is_refused_by_the_expansion_ratio() {
    use openpgp::serialize::stream::{Armorer, Compressor, Encryptor, LiteralWriter, Message};
    use openpgp::types::CompressionAlgorithm;

    // Past MIN_EXPANSION_ALLOWANCE, so the ratio refuses it, not a flat ceiling.
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
    let outcome = decrypt_with_handle(&sink, handle, None, None);
    drop_key(handle).unwrap();

    match outcome {
        Ok(packed) => panic!(
            "decrypted {} bytes from a {} byte message with no cap -- \
             an attacker picks this number",
            packed.len(),
            sink.len(),
        ),
        Err(e) => {
            assert!(
                e.to_lowercase().contains("large") || e.to_lowercase().contains("limit"),
                "rejected, but not with a size error: {e}",
            );
        }
    }
}

/// Regression: the same bomb on the keyless verify path, where JSON escaping
/// of NULs adds ~6x more (88 KB paste -> 402 MB string). Hence the tighter
/// `MAX_VERIFIED_BYTES`.
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

    match verify_message(&armored, &keys, None) {
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
    // Off-by-one at the cap, tested exactly.
    let data = vec![b'x'; 1024];

    let exact = read_capped(&data[..], 1024u64).unwrap();
    assert_eq!(exact.len(), 1024, "a message exactly at the limit was refused");

    let under = read_capped(&data[..], 1025u64).unwrap();
    assert_eq!(under.len(), 1024);

    let err = read_capped(&data[..], 1023u64).unwrap_err();
    assert_eq!(err, too_large_to_open());

    assert_eq!(read_capped(&[][..], 0u64).unwrap().len(), 0);
}

#[test]
fn the_output_ceiling_follows_the_input_rather_than_a_flat_number() {
    // A flat ceiling cannot both admit a 1 GiB file and refuse a 5 MiB bomb;
    // the ratio can.

    let one_gib = 1024 * 1024 * 1024usize;
    assert!(
        decrypt_limit(one_gib) >= one_gib as u64,
        "a 1 GiB file would be refused by its own limit",
    );

    let bomb_ciphertext = 89 * 1024usize; // the measured bomb
    assert!(
        decrypt_limit(bomb_ciphertext) < 100 * 1024 * 1024,
        "a tiny ciphertext was granted a huge allowance",
    );

    // Short messages are not squeezed: framing alone exceeds 4x.
    assert_eq!(decrypt_limit(200), MIN_EXPANSION_ALLOWANCE);
    assert_eq!(decrypt_limit(0), MIN_EXPANSION_ALLOWANCE);

    assert_eq!(decrypt_limit(usize::MAX), MAX_DECRYPTED_BYTES);

    // Verify stays tighter: its output becomes one JSON String.
    const { assert!(MAX_VERIFIED_BYTES < MAX_DECRYPTED_BYTES) };
}


// ── error codes: each site the UI classifies yields its code ─────────

fn code(err: &str) -> Option<ErrorCode> {
    error_code::error_code(err)
}

#[test]
fn vault_aead_failure_is_wrong_passphrase() {
    let sealed = crate::aes_gcm_encrypt(&[1u8; 32], b"x", b"aad").unwrap();
    let (iv, ct) = sealed.split_at(12);
    let err = crate::aes_gcm_decrypt(&[2u8; 32], iv, ct, b"aad").unwrap_err();
    assert_eq!(code(&err), Some(ErrorCode::WrongPassphrase), "{err}");
    let err = crate::aes_gcm_decrypt(&[1u8; 32], &[0u8; 8], ct, b"aad").unwrap_err();
    assert_eq!(code(&err), None, "{err}");
}

#[test]
fn ocb_message_is_ocb_unsupported() {
    let err =
        decrypt_with_password(GPG_SYMMETRIC_OCB.as_bytes(), symmetric_password(), None, None).unwrap_err();
    assert_eq!(code(&err), Some(ErrorCode::OcbUnsupported), "{err}");
}

#[test]
fn non_recipient_key_is_no_decryption_key() {
    let (recipient_pub, _) = adv_keypair();
    let (_, other_priv) = adv_keypair();
    let ct = encrypt(b"x", &adv_recipients(&recipient_pub), None, None).unwrap();
    let h = store_key(&other_priv).unwrap();
    let err = decrypt_with_handle(&ct, h, None, None).unwrap_err();
    drop_key(h).unwrap();
    assert_eq!(code(&err), Some(ErrorCode::NoDecryptionKey), "{err}");
}

#[test]
fn expired_recipient_is_key_expired() {
    let (expired_pub, _) = gen_expired_key();
    let err = encrypt(b"x", &adv_recipients(&expired_pub), None, None).unwrap_err();
    assert_eq!(code(&err), Some(ErrorCode::KeyExpired), "{err}");
}

#[test]
fn revoked_recipient_is_key_revoked() {
    let generated: serde_json::Value = serde_json::from_str(&gen_test_key()).unwrap();
    let private_armor = generated["privateKeyArmored"].as_str().unwrap();
    let h = store_key(private_armor).unwrap();
    let revocation = revocation_certificate_with_handle(h).unwrap();
    drop_key(h).unwrap();
    let cert = openpgp::Cert::from_bytes(private_armor.as_bytes()).unwrap();
    let sig = openpgp::Packet::from_bytes(revocation.as_bytes()).unwrap();
    let (revoked, _) = cert.insert_packets(vec![sig]).unwrap();
    let revoked_pub = armor_cert(&revoked, false).unwrap();

    let err = encrypt(b"x", &adv_recipients(&revoked_pub), None, None).unwrap_err();
    assert_eq!(code(&err), Some(ErrorCode::KeyRevoked), "{err}");
}

#[test]
fn input_without_pgp_data_is_not_pgp_data() {
    let mut marker = Vec::new();
    let mut w = openpgp::armor::Writer::new(&mut marker, openpgp::armor::Kind::PublicKey).unwrap();
    openpgp::Packet::from(openpgp::packet::Marker::default()).serialize(&mut w).unwrap();
    w.finalize().unwrap();
    let generated: serde_json::Value = serde_json::from_str(&gen_test_key()).unwrap();
    let public = generated["publicKeyArmored"].as_str().unwrap();
    for err in [
        parse_keys(&String::from_utf8(marker).unwrap()).unwrap_err(),
        revocation_signatures(public).unwrap_err(),
        verify_message("hello", "[]", None).unwrap_err(),
    ] {
        assert_eq!(code(&err), Some(ErrorCode::NotPgpData), "{err}");
    }
}

#[test]
fn oversized_signed_input_is_too_large() {
    let big = "a".repeat(MAX_SIGNED_INPUT_BYTES + 1);
    let err = verify_message(&big, "[]", None).unwrap_err();
    assert_eq!(code(&err), Some(ErrorCode::TooLarge), "{err}");
}
