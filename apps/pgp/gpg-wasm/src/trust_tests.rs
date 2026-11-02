//! Each test pins one way a "verified" verdict or stored contact could say
//! more than the cryptography does.

use super::*;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::UserID;
use openpgp::parse::{PacketParser, PacketParserResult};
use openpgp::types::{ReasonForRevocation, SignatureType};

const DAY: Duration = Duration::from_secs(86_400);

/// A cert created `age` ago, so signatures can be dated inside its life.
fn aged_cert(name: &str, age: Duration) -> openpgp::Cert {
    CertBuilder::new()
        .add_userid(format!("{name} <{}@example.com>", name.to_lowercase()))
        .add_signing_subkey()
        .add_transport_encryption_subkey()
        .set_cipher_suite(CipherSuite::Cv25519)
        .set_creation_time(SystemTime::now() - age)
        .generate()
        .unwrap()
        .0
}

fn public(cert: &openpgp::Cert) -> String {
    armor_cert(cert, false).unwrap()
}

fn keys_json(certs: &[&openpgp::Cert]) -> String {
    serde_json::to_string(&certs.iter().map(|c| public(c)).collect::<Vec<_>>()).unwrap()
}

fn primary_keypair(cert: &openpgp::Cert) -> openpgp::crypto::KeyPair {
    cert.primary_key().key().clone().parts_into_secret().unwrap().into_keypair().unwrap()
}

fn key_info(armored: &str) -> serde_json::Value {
    serde_json::from_str(&parse_key(armored).unwrap()).unwrap()
}

fn verdict(json: &str) -> serde_json::Value {
    serde_json::from_str(json).unwrap()
}

fn unpack(packed: &[u8]) -> (serde_json::Value, Vec<u8>) {
    let n = u32::from_le_bytes([packed[0], packed[1], packed[2], packed[3]]) as usize;
    (
        serde_json::from_str(std::str::from_utf8(&packed[4..4 + n]).unwrap()).unwrap(),
        packed[4 + n..].to_vec(),
    )
}

fn cleartext_at(text: &str, cert: &openpgp::Cert, t: SystemTime) -> String {
    let mut sink = Vec::new();
    {
        let mut s = Signer::new(Message::new(&mut sink), signing_keypair(cert).unwrap())
            .unwrap()
            .cleartext()
            .creation_time(t)
            .build()
            .unwrap();
        s.write_all(text.as_bytes()).unwrap();
        s.finalize().unwrap();
    }
    String::from_utf8(sink).unwrap()
}

fn revoke(cert: &openpgp::Cert, reason: ReasonForRevocation) -> openpgp::Cert {
    let rev = cert.revoke(&mut primary_keypair(cert), reason, b"test").unwrap();
    cert.clone().insert_packets(rev).unwrap().0
}

// ── User IDs ─────────────────────────────────────────────────────────

#[test]
fn an_unbound_user_id_is_never_the_contact_name() {
    // An unbound User ID is not Bob's claim and must not name him.
    let bob = aged_cert("Bob", DAY);
    let (forged, _) = bob
        .clone()
        .insert_packets(vec![openpgp::Packet::from(UserID::from("Aaron CEO <ceo@corp.test>"))])
        .unwrap();

    let info = key_info(&public(&forged));
    assert_eq!(info["userIds"], serde_json::json!(["Bob <bob@example.com>"]));
}

#[test]
fn a_revoked_user_id_is_dropped_and_the_primary_comes_first() {
    let cert = aged_cert("Alice", DAY);
    let old = cert.userids().next().unwrap().userid().clone();
    let mut kp = primary_keypair(&cert);
    let new = UserID::from("Alice New <alice@new.example>");
    let bind = new
        .bind(
            &mut kp,
            &cert,
            SignatureBuilder::new(SignatureType::PositiveCertification).set_primary_userid(true).unwrap(),
        )
        .unwrap();
    let rev = UserIDRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"left")
        .unwrap()
        .build(&mut kp, &cert, &old, None)
        .unwrap();
    let (cert, _) = cert
        .insert_packets(vec![openpgp::Packet::from(new), bind.into(), rev.into()])
        .unwrap();

    let info = key_info(&public(&cert));
    assert_eq!(info["userIds"], serde_json::json!(["Alice New <alice@new.example>"]));
}

#[test]
fn a_lookalike_user_id_is_flagged() {
    // "Аlice" with a Cyrillic А renders exactly like the real Alice.
    let fake = aged_cert("\u{410}lice", DAY);
    let info = key_info(&public(&fake));
    assert!(info["securityWarning"].as_str().unwrap().contains("different alphabets"));

    // Judged per word: a Cyrillic name with a Latin address is ordinary.
    for honest in [
        "Alice",
        "Иван Петров <ivan@example.ru>",
        "Νίκος Παπάς <nikos@example.gr>",
        "José Müller <jose@example.de>",
        "Ani Հայ <ani@example.am>",
    ] {
        assert!(!mixes_scripts(honest), "{honest} flagged");
    }
    for fake in [
        "\u{ff21}lice",
        "\u{0251}lice",
        "\u{13aa}lice",
        "Bob <\u{0430}lice@example.com>",
        "\u{1d00}lice",
        "\u{1d400}lice",
        "\u{212a}evin",
        "\u{a4ee}lice",
        "Tim <tim@\u{0430}\u{0440}\u{0440}\u{04cf}\u{0435}.com>",
    ] {
        assert!(mixes_scripts(fake), "{fake:?} missed");
    }
    assert!(!mixes_scripts("Иван <иван@пример.рф>"));
}

#[test]
fn invisible_characters_are_stripped_from_user_ids() {
    for hidden in ["\u{200b}", "\u{200e}", "\u{200f}", "\u{061c}", "\u{2060}", "\u{feff}", "\u{00ad}"] {
        assert_eq!(sanitize_untrusted(&format!("Al{hidden}ice"), 300), "Alice", "{hidden:?}");
    }
}

// ── signature verdicts ───────────────────────────────────────────────

#[test]
fn a_signature_dated_before_its_key_existed_is_invalid_not_unknown() {
    // UnboundKey at the claimed time is a forgery signal, not "unknown signer".
    let bob = aged_cert("Bob", 10 * DAY);
    let signed = cleartext_at("Pay account 111.", &bob, SystemTime::now() - 400 * DAY);
    let forged = signed.replace("Pay account 111.", "Pay account 999.");

    for input in [signed, forged] {
        let v = verdict(&verify_message(&input, &keys_json(&[&bob]), None).unwrap());
        assert_eq!(v["signatureStatus"], "invalid");
        assert_eq!(v["signerKeyId"], serde_json::Value::Null);
    }
}

#[test]
fn a_good_signature_reports_when_it_was_made_and_whether_the_key_is_still_current() {
    let bob = aged_cert("Bob", 10 * DAY);
    let at = SystemTime::now() - 5 * DAY;
    let signed = cleartext_at("Old notice.", &bob, at);

    let v = verdict(&verify_message(&signed, &keys_json(&[&bob]), None).unwrap());
    assert_eq!(v["signatureStatus"], "valid");
    assert_eq!(v["signerKeyCurrent"], true);
    let signed_at = v["signedAt"].as_f64().unwrap();
    assert!((signed_at - system_time_to_millis(at)).abs() < 1_000.0);

    // Superseded: still verifies, but the UI must be told the key is gone.
    let superseded = revoke(&bob, ReasonForRevocation::KeySuperseded);
    let v = verdict(&verify_message(&signed, &keys_json(&[&superseded]), None).unwrap());
    assert_eq!(v["signatureStatus"], "valid");
    assert_eq!(v["signerKeyCurrent"], false);

    let compromised = revoke(&bob, ReasonForRevocation::KeyCompromised);
    let v = verdict(&verify_message(&signed, &keys_json(&[&compromised]), None).unwrap());
    assert_eq!(v["signatureStatus"], "invalid");
}

fn inline_multi(text: &str, signers: &[&openpgp::Cert]) -> String {
    let mut sink = Vec::new();
    {
        let m = Armorer::new(Message::new(&mut sink)).build().unwrap();
        let mut s = Signer::new(m, signing_keypair(signers[0]).unwrap()).unwrap();
        for cert in &signers[1..] {
            s = s.add_signer(signing_keypair(cert).unwrap()).unwrap();
        }
        let mut l = LiteralWriter::new(s.build().unwrap()).build().unwrap();
        l.write_all(text.as_bytes()).unwrap();
        l.finalize().unwrap();
    }
    String::from_utf8(sink).unwrap()
}

#[test]
fn a_bad_signature_next_to_a_good_one_makes_the_message_invalid() {
    // A verdict naming only Alice would hide Mallory's failed signature.
    let alice = aged_cert("Alice", 10 * DAY);
    let mallory = aged_cert("Mallory", 10 * DAY);
    let msg = inline_multi("pay 1000", &[&alice, &mallory]);
    let compromised = revoke(&mallory, ReasonForRevocation::KeyCompromised);

    let v = verdict(&verify_message(&msg, &keys_json(&[&alice, &mallory]), None).unwrap());
    assert_eq!(v["signatureStatus"], "valid", "control: both good");

    let v = verdict(&verify_message(&msg, &keys_json(&[&alice, &compromised]), None).unwrap());
    assert_eq!(v["signatureStatus"], "invalid");
}

#[test]
fn every_good_signer_and_every_unchecked_signature_is_reported() {
    let alice = aged_cert("Alice", 10 * DAY);
    let bob = aged_cert("Bob", 10 * DAY);
    let carol = aged_cert("Carol", 10 * DAY);
    let msg = inline_multi("joint statement", &[&alice, &bob, &carol]);

    // An unheld signer is counted, not silently dropped.
    let v = verdict(&verify_message(&msg, &keys_json(&[&alice, &bob]), None).unwrap());
    assert_eq!(v["signatureStatus"], "valid");
    let mut all: Vec<String> = vec![v["signerKeyId"].as_str().unwrap().into()];
    all.extend(v["otherSignerKeyIds"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().into()));
    all.sort();
    let mut want = vec![alice.fingerprint().to_hex(), bob.fingerprint().to_hex()];
    want.sort();
    assert_eq!(all, want);
    assert_eq!(v["unverifiedSignatures"], 1);
}

#[test]
fn a_cleartext_charset_header_must_name_a_charset() {
    let bob = aged_cert("Bob", DAY);
    let signed = sign_message("Notice.", &armor_cert(&bob, true).unwrap()).unwrap();
    let sig_begin = "-----BEGIN PGP SIGNATURE-----\n";
    let keys = keys_json(&[&bob]);

    let prose = signed.replacen(sig_begin, &format!("{sig_begin}Charset: PAY ACCOUNT 999\n"), 1);
    assert!(verify_message(&prose, &keys, None).unwrap_err().contains("outside the signed part"));

    for charset in ["UTF-8", "ISO-8859-1"] {
        let real = signed.replacen(sig_begin, &format!("{sig_begin}Charset: {charset}\n"), 1);
        assert_eq!(verdict(&verify_message(&real, &keys, None).unwrap())["signatureStatus"], "valid");
    }
}

// ── forwarding ───────────────────────────────────────────────────────

/// The signed packets Bob sees after decrypting, ready to re-encrypt.
fn signatures_inside(ct: &[u8], recipient: &openpgp::Cert) -> Vec<openpgp::packet::Signature> {
    let mut session: Option<(Option<SymmetricAlgorithm>, SessionKey)> = None;
    let mut sigs = Vec::new();
    let mut ppr = PacketParser::from_bytes(ct).unwrap();
    while let PacketParserResult::Some(mut pp) = ppr {
        match &pp.packet {
            openpgp::Packet::PKESK(pkesk) => {
                for ka in recipient.keys().secret().subkeys() {
                    let mut kp = ka.key().clone().into_keypair().unwrap();
                    if let Some(r) = pkesk.decrypt(&mut kp, None) {
                        session = Some(r);
                    }
                }
            }
            openpgp::Packet::SEIP(_) => {
                let (algo, key) = session.clone().unwrap();
                pp.decrypt(algo, &key).unwrap();
            }
            openpgp::Packet::Signature(sig) => sigs.push(sig.clone()),
            _ => {}
        }
        ppr = pp.recurse().unwrap().1;
    }
    sigs
}

#[test]
fn signed_mail_names_its_recipients_so_it_cannot_be_forwarded_as_addressed_to_another() {
    let alice = aged_cert("Alice", DAY);
    let bob = aged_cert("Bob", DAY);
    let ct = encrypt_impl(b"hi bob", &keys_json(&[&bob]), Some(&alice), None).unwrap();

    let sigs = signatures_inside(&ct, &bob);
    assert_eq!(sigs.len(), 1);
    let named: Vec<_> = sigs[0].intended_recipients().map(|f| f.to_hex()).collect();
    assert_eq!(named, vec![bob.fingerprint().to_hex()]);

    let h = insert_key(&bob).unwrap();
    let (sig, pt) = unpack(&decrypt_with_handle(&ct, h, Some(keys_json(&[&alice])), None).unwrap());
    drop_key(h).unwrap();
    assert_eq!(sig["signatureStatus"], "valid");
    assert_eq!(pt, b"hi bob");

    let carol = aged_cert("Carol", DAY);
    let mut sink = Vec::new();
    {
        let vc = carol.with_policy(policy(), None).unwrap();
        let rks: Vec<_> = vc.keys().for_transport_encryption().collect();
        let e = Encryptor::for_recipients(Message::new(&mut sink), rks).build().unwrap();
        let s = Signer::new(e, signing_keypair(&alice).unwrap())
            .unwrap()
            .add_intended_recipient(&bob)
            .build()
            .unwrap();
        let mut l = LiteralWriter::new(s).build().unwrap();
        l.write_all(b"hi bob").unwrap();
        l.finalize().unwrap();
    }
    let h = insert_key(&carol).unwrap();
    let (sig, _) = unpack(&decrypt_with_handle(&sink, h, Some(keys_json(&[&alice])), None).unwrap());
    drop_key(h).unwrap();
    assert_eq!(sig["signatureStatus"], "invalid");
}

// ── own keys ─────────────────────────────────────────────────────────

#[test]
fn mail_sent_to_a_key_before_it_expired_or_was_revoked_still_decrypts_for_its_owner() {
    let now = SystemTime::now();
    let (cert, _) = CertBuilder::new()
        .add_userid("Old <old@example.com>")
        .add_transport_encryption_subkey()
        .set_creation_time(now - 3 * DAY)
        .set_validity_period(DAY)
        .generate()
        .unwrap();
    let vc = cert.with_policy(policy(), now - 2 * DAY).unwrap();
    let rks: Vec<_> = vc.keys().for_transport_encryption().collect();
    let mut sink = Vec::new();
    {
        let e = Encryptor::for_recipients(Message::new(&mut sink), rks).build().unwrap();
        let mut l = LiteralWriter::new(e).build().unwrap();
        l.write_all(b"old mail").unwrap();
        l.finalize().unwrap();
    }

    for owner in [cert.clone(), revoke(&cert, ReasonForRevocation::KeySuperseded)] {
        let h = insert_key(&owner).unwrap();
        let (_, pt) = unpack(&decrypt_with_handle(&sink, h, None, None).unwrap());
        drop_key(h).unwrap();
        assert_eq!(pt, b"old mail");
    }
}

// ── importing a contact again ────────────────────────────────────────

#[test]
fn an_older_copy_cannot_undo_a_subkey_revocation() {
    // A pre-rotation copy imported over the stored cert must not resurrect a
    // revoked subkey.
    let alice = aged_cert("Alice", 10 * DAY);
    let before = public(&alice);
    let vc = alice.with_policy(policy(), None).unwrap();
    let sub = vc.keys().subkeys().for_transport_encryption().next().unwrap();
    let rev = SubkeyRevocationBuilder::new()
        .set_reason_for_revocation(ReasonForRevocation::KeyCompromised, b"leaked")
        .unwrap()
        .build(&mut primary_keypair(&alice), &alice, sub.key(), None)
        .unwrap();
    let (rotated, _) = alice.clone().insert_packets(vec![openpgp::Packet::from(rev)]).unwrap();
    let stored = public(&rotated);
    assert_eq!(key_info(&stored)["usableForEncryption"], false);

    let merged = merge_public_key(&stored, &before).unwrap();
    assert_eq!(key_info(&merged)["usableForEncryption"], false);
}

#[test]
fn importing_a_revoked_copy_revokes_the_stored_contact() {
    let alice = aged_cert("Alice", DAY);
    let revoked = revoke(&alice, ReasonForRevocation::KeyCompromised);

    let merged = merge_public_key(&public(&alice), &public(&revoked)).unwrap();
    let info = key_info(&merged);
    assert_eq!(info["revoked"], true);
    assert_eq!(info["usableForEncryption"], false);
}

#[test]
fn a_bare_revocation_certificate_revokes_the_contact_it_names() {
    let gen: serde_json::Value = serde_json::from_str(
        &generate_key(r#"{"name":"Rita","email":"rita@example.com","type":"ecc"}"#).unwrap(),
    )
    .unwrap();
    let pub_armor = gen["publicKeyArmored"].as_str().unwrap();
    let rev_armor = gen["revocationCertificate"].as_str().unwrap();
    let fpr = key_info(pub_armor)["keyId"].as_str().unwrap().to_string();

    let issuers: Vec<String> = serde_json::from_str(&revocation_issuers(rev_armor).unwrap()).unwrap();
    assert!(issuers.iter().any(|i| fpr.ends_with(i.as_str())), "{issuers:?} vs {fpr}");

    let merged = merge_public_key(pub_armor, rev_armor).unwrap();
    assert_eq!(key_info(&merged)["revoked"], true);
}

#[test]
fn a_revocation_signed_by_someone_else_is_ignored() {
    let alice = aged_cert("Alice", DAY);
    let mallory = aged_cert("Mallory", DAY);
    let forged = SignatureBuilder::new(SignatureType::KeyRevocation)
        .set_reason_for_revocation(ReasonForRevocation::KeyCompromised, b"")
        .unwrap()
        .sign_direct_key(&mut primary_keypair(&mallory), alice.primary_key().key())
        .unwrap();
    let armored = String::from_utf8(
        openpgp::Packet::from(forged).to_vec().map(|b| {
            let mut w = openpgp::armor::Writer::new(Vec::new(), openpgp::armor::Kind::Signature).unwrap();
            w.write_all(&b).unwrap();
            w.finalize().unwrap()
        }).unwrap(),
    )
    .unwrap();

    let merged = merge_public_key(&public(&alice), &armored).unwrap();
    assert_eq!(key_info(&merged)["revoked"], false);
    // The forged signature is dropped: the import reads as "nothing changed".
    assert_eq!(merged, public(&alice));
}

#[test]
fn a_different_key_cannot_be_merged_into_a_contact() {
    let alice = aged_cert("Alice", DAY);
    let mallory = aged_cert("Mallory", DAY);
    assert!(merge_public_key(&public(&alice), &public(&mallory)).is_err());
}

#[test]
fn third_party_certifications_are_stripped_on_import() {
    // No web of trust: third-party certifications only cost parse time.
    let alice = aged_cert("Alice", DAY);
    let bob = aged_cert("Bob", DAY);
    let uid = alice.userids().next().unwrap().userid().clone();
    let cert_sig = uid
        .certify(&mut primary_keypair(&bob), &alice, SignatureType::GenericCertification, None, None)
        .unwrap();
    let (certified, _) = alice.clone().insert_packets(vec![openpgp::Packet::from(cert_sig)]).unwrap();
    assert_eq!(certified.userids().next().unwrap().certifications().count(), 1);

    let parsed: Vec<serde_json::Value> = serde_json::from_str(&parse_keys(&public(&certified)).unwrap()).unwrap();
    let stored = openpgp::Cert::from_bytes(parsed[0]["armored"].as_str().unwrap().as_bytes()).unwrap();
    assert_eq!(stored.userids().next().unwrap().certifications().count(), 0);
    assert_eq!(key_info(&public(&stored))["usableForEncryption"], true);

    let merged = merge_public_key(&public(&alice), &public(&certified)).unwrap();
    let merged = openpgp::Cert::from_bytes(merged.as_bytes()).unwrap();
    assert_eq!(merged.userids().next().unwrap().certifications().count(), 0);
}

#[test]
fn flooding_with_third_party_revocations_or_an_appended_subkey_is_stripped() {
    let alice = aged_cert("Alice", DAY);
    let bob = aged_cert("Bob", DAY);
    let uid = alice.userids().next().unwrap().userid().clone();
    let mut bkp = primary_keypair(&bob);

    let mut flood: Vec<openpgp::Packet> = Vec::new();
    for _ in 0..20 {
        let sig = SignatureBuilder::new(SignatureType::CertificationRevocation)
            .sign_userid_binding(&mut bkp, alice.primary_key().key(), &uid)
            .unwrap();
        flood.push(sig.into());
    }
    // An appended unbound subkey must not make its certifications count as "own".
    flood.push(openpgp::Packet::from(
        bob.primary_key().key().clone().role_into_subordinate(),
    ));
    for _ in 0..20 {
        let sig = uid
            .certify(&mut bkp, &alice, SignatureType::GenericCertification, None, None)
            .unwrap();
        flood.push(sig.into());
    }
    let (flooded, _) = alice.clone().insert_packets(flood).unwrap();

    let merged = merge_public_key(&public(&alice), &public(&flooded)).unwrap();
    let merged = openpgp::Cert::from_bytes(merged.as_bytes()).unwrap();
    let ua = merged.userids().next().unwrap();
    assert_eq!(ua.certifications().count(), 0);
    assert_eq!(ua.other_revocations().count(), 0);
    assert_eq!(key_info(&public(&merged))["usableForEncryption"], true);
}

#[test]
fn a_signature_names_who_it_was_signed_for() {
    // Verify has no "us" to check intended recipients against; the UI does it.
    let alice = aged_cert("Alice", DAY);
    let bob = aged_cert("Bob", DAY);
    let mut sink = Vec::new();
    {
        let m = Armorer::new(Message::new(&mut sink)).build().unwrap();
        let s = Signer::new(m, signing_keypair(&alice).unwrap())
            .unwrap()
            .add_intended_recipient(&bob)
            .build()
            .unwrap();
        let mut l = LiteralWriter::new(s).build().unwrap();
        l.write_all(b"for bob").unwrap();
        l.finalize().unwrap();
    }
    let v = verdict(&verify_message(std::str::from_utf8(&sink).unwrap(), &keys_json(&[&alice]), None).unwrap());
    assert_eq!(v["signatureStatus"], "valid");
    assert_eq!(v["intendedRecipients"], serde_json::json!([bob.fingerprint().to_hex()]));
}

#[test]
fn stripping_a_key_flooded_with_forged_signatures_stays_fast() {
    // Thousands of bad signatures used to make the strip quadratic.
    let alice = aged_cert("Alice", DAY);
    let mallory = aged_cert("Mallory", DAY);
    let mut mkp = primary_keypair(&mallory);
    let forged: Vec<openpgp::Packet> = (0..3000)
        .map(|i| {
            SignatureBuilder::new(SignatureType::DirectKey)
                .set_notation("n@example.com", format!("{i}").as_bytes(), None, false)
                .unwrap()
                .sign_direct_key(&mut mkp, alice.primary_key().key())
                .unwrap()
                .into()
        })
        .collect();
    let (flooded, _) = alice.clone().insert_packets(forged).unwrap();
    let started = std::time::Instant::now();
    let stripped = strip_third_party(flooded).unwrap();
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    assert_eq!(stripped.bad_signatures().count(), 0);
}

#[test]
fn a_flood_of_lines_or_bytes_is_refused_before_the_framing_check_walks_it() {
    // 200 MB of newlines in a signed block once aborted the engine (per-line
    // entries before any cap).
    let lines = format!(
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{}x\n-----BEGIN PGP SIGNATURE-----\n\niQ==\n-----END PGP SIGNATURE-----\n",
        "\n".repeat(MAX_SIGNED_LINES + 1),
    );
    assert!(verify_message(&lines, "[]", None).unwrap_err().contains("too many lines"));

    let bytes = "a".repeat(MAX_SIGNED_INPUT_BYTES + 1);
    assert!(verify_message(&bytes, "[]", None).unwrap_err().contains("too large"));
}

// ── a "message" that was never encrypted ─────────────────────────────

/// Inline-signed, no encryption layer, as `gpg --sign` writes it.
fn signed_only(text: &[u8], signer: &openpgp::Cert, armor: bool) -> Vec<u8> {
    let mut sink = Vec::new();
    {
        let m = Message::new(&mut sink);
        let m = if armor { Armorer::new(m).build().unwrap() } else { m };
        let s = Signer::new(m, signing_keypair(signer).unwrap()).unwrap().build().unwrap();
        let mut l = LiteralWriter::new(s).build().unwrap();
        l.write_all(text).unwrap();
        l.finalize().unwrap();
    }
    sink
}

/// A bare literal packet armored as a PGP MESSAGE; it used to "decrypt".
fn literal_only(text: &[u8]) -> Vec<u8> {
    let mut sink = Vec::new();
    {
        let m = Armorer::new(Message::new(&mut sink)).build().unwrap();
        let mut l = LiteralWriter::new(m).build().unwrap();
        l.write_all(text).unwrap();
        l.finalize().unwrap();
    }
    sink
}

#[test]
fn a_message_with_no_encryption_layer_is_never_decrypted() {
    let alice = aged_cert("Alice", DAY);
    let victim = aged_cert("Victim", DAY);
    let keys = keys_json(&[&alice, &victim]);
    let h = insert_key(&victim).unwrap();
    for msg in [
        signed_only(b"Alice's public statement", &alice, true),
        signed_only(b"Alice's public statement", &alice, false),
        literal_only(b"Totally secret, only for you"),
    ] {
        let err = decrypt_with_handle(&msg, h, Some(keys.clone()), None).unwrap_err();
        assert_eq!(err, not_encrypted());
        let err = decrypt_with_password(&msg, b"pw".to_vec(), Some(keys.clone()), None).unwrap_err();
        assert_eq!(err, not_encrypted());
        let shape: serde_json::Value =
            serde_json::from_str(&message_encryption(&msg).unwrap()).unwrap();
        assert_eq!(shape["encrypted"], false);
    }
    drop_key(h).unwrap();
}

#[test]
fn an_encrypted_message_reports_itself_encrypted_and_still_decrypts() {
    let alice = aged_cert("Alice", DAY);
    let bob = aged_cert("Bob", DAY);
    let ct = encrypt_impl(b"hi bob", &keys_json(&[&bob]), Some(&alice), None).unwrap();
    let shape: serde_json::Value = serde_json::from_str(&message_encryption(&ct).unwrap()).unwrap();
    assert_eq!(shape["encrypted"], true);
    assert_eq!(shape["publicKey"], true);
    let h = insert_key(&bob).unwrap();
    let (sig, pt) = unpack(&decrypt_with_handle(&ct, h, Some(keys_json(&[&alice])), None).unwrap());
    drop_key(h).unwrap();
    assert_eq!(sig["signatureStatus"], "valid");
    assert_eq!(pt, b"hi bob");

    let pw = encrypt_impl(b"by password", "[]", None, Some(Zeroizing::new(b"pw".to_vec()))).unwrap();
    let (_, pt) = unpack(&decrypt_with_password(&pw, b"pw".to_vec(), None, None).unwrap());
    assert_eq!(pt, b"by password");
}

#[test]
fn an_unencrypted_message_opens_with_its_verdict_and_no_key() {
    let alice = aged_cert("Alice", DAY);
    let keys = Some(keys_json(&[&alice]));

    for armor in [true, false] {
        let msg = signed_only(b"Alice's public statement", &alice, armor);
        let (sig, pt) = unpack(&open_unencrypted(&msg, keys.clone(), None).unwrap());
        assert_eq!(sig["signatureStatus"], "valid", "armor={armor}");
        assert_eq!(pt, b"Alice's public statement");
    }

    let (sig, pt) = unpack(&open_unencrypted(&literal_only(b"plain"), keys.clone(), None).unwrap());
    assert_eq!(sig["signatureStatus"], "unsigned");
    assert_eq!(pt, b"plain");

    // Cleartext-signed text on the decrypt tab gets Verify's framing check.
    let csf = cleartext_sign("Line one\nLine two", &alice).unwrap();
    let (sig, pt) = unpack(&open_unencrypted(csf.as_bytes(), keys.clone(), None).unwrap());
    assert_eq!(sig["signatureStatus"], "valid");
    assert_eq!(pt, b"Line one\nLine two");
}

#[test]
fn opening_unencrypted_refuses_encrypted_input_and_text_around_the_block() {
    let alice = aged_cert("Alice", DAY);
    let bob = aged_cert("Bob", DAY);
    let keys = Some(keys_json(&[&alice]));

    let ct = encrypt_impl(b"hi bob", &keys_json(&[&bob]), None, None).unwrap();
    assert!(open_unencrypted(&ct, keys.clone(), None).unwrap_err().contains("is encrypted"));

    let signed = String::from_utf8(signed_only(b"ALICE GENUINE", &alice, true)).unwrap();
    for wrapped in [
        format!("Approved: wire 50k\n\n{signed}"),
        format!("{signed}\nSee also: acct 999\n"),
        format!("{}\n{signed}", String::from_utf8(literal_only(b"MALLORY FAKE")).unwrap()),
    ] {
        assert_eq!(open_unencrypted(wrapped.as_bytes(), keys.clone(), None).unwrap_err(), outside_signed());
    }
}

/// Re-armor `signed` with its literal body swapped, keeping the signatures.
fn with_body(signed: &[u8], body: &[u8]) -> String {
    let pile = openpgp::PacketPile::from_bytes(signed).unwrap();
    let mut out = Vec::new();
    {
        let mut w = openpgp::armor::Writer::new(&mut out, openpgp::armor::Kind::Message).unwrap();
        for p in pile.into_children() {
            match p {
                openpgp::Packet::Literal(mut l) => {
                    l.set_body(body.to_vec());
                    openpgp::Packet::from(l).serialize(&mut w).unwrap();
                }
                p => p.serialize(&mut w).unwrap(),
            }
        }
        w.finalize().unwrap();
    }
    String::from_utf8(out).unwrap()
}

#[test]
fn a_text_signature_reads_a_lone_cr_as_a_line_break() {
    // Pinned, not endorsed: text-mode hashing canonicalises \r, \n and \r\n to
    // CRLF, so a lone CR is covered by the signature. The UI flags it amber; if
    // this fails, Sequoia changed canonicalisation and that caveat can go.
    let alice = aged_cert("Alice", DAY);
    let mut sink = Vec::new();
    {
        let m = Armorer::new(Message::new(&mut sink)).build().unwrap();
        let s = Signer::with_template(
            m,
            signing_keypair(&alice).unwrap(),
            SignatureBuilder::new(SignatureType::Text),
        )
        .unwrap()
        .build()
        .unwrap();
        let mut l = LiteralWriter::new(s)
            .format(openpgp::types::DataFormat::Unicode)
            .build()
            .unwrap();
        l.write_all(b"Approved:\nNO").unwrap();
        l.finalize().unwrap();
    }
    let swapped = with_body(&sink, b"Approved:\rNO");
    let v = verdict(&verify_message(&swapped, &keys_json(&[&alice]), None).unwrap());
    assert_eq!(v["signatureStatus"], "valid");
    assert_eq!(v["text"], "Approved:\rNO");

    // The cleartext framing check refuses a CR not before a LF.
    let csf = cleartext_sign("Approved:\nNO", &alice).unwrap().replace("Approved:\nNO", "Approved:\rNO");
    assert_eq!(verify_message(&csf, &keys_json(&[&alice]), None).unwrap_err(), outside_signed());
}

#[test]
fn every_default_ignorable_and_format_character_is_stripped() {
    let hidden = [
        '\u{00ad}', '\u{034f}', '\u{0600}', '\u{0605}', '\u{061c}', '\u{06dd}', '\u{070f}',
        '\u{0890}', '\u{08e2}', '\u{115f}', '\u{1160}', '\u{17b4}', '\u{17b5}', '\u{180b}',
        '\u{180d}', '\u{180e}', '\u{180f}', '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}',
        '\u{200f}', '\u{2028}', '\u{2029}', '\u{202a}', '\u{202e}', '\u{2060}', '\u{2064}',
        '\u{2065}', '\u{2066}', '\u{2069}', '\u{206a}', '\u{206f}', '\u{3164}', '\u{fe00}',
        '\u{fe0f}', '\u{feff}', '\u{ffa0}', '\u{fff0}', '\u{fff9}', '\u{fffb}', '\u{110bd}',
        '\u{110cd}', '\u{13430}', '\u{1343f}', '\u{1bca0}', '\u{1bca3}', '\u{1d173}',
        '\u{1d17a}', '\u{e0000}', '\u{e0001}', '\u{e0041}', '\u{e007f}', '\u{e0100}',
        '\u{e01ef}', '\u{e0fff}',
    ];
    for c in hidden {
        assert_eq!(sanitize_untrusted(&format!("Al{c}ice"), 300), "Alice", "{c:?}");
    }
    let tags: String = "evil".chars().map(|c| char::from_u32(0xE0000 + c as u32).unwrap()).collect();
    assert_eq!(sanitize_untrusted(&format!("alice{tags}@example.com"), 300), "alice@example.com");

    for name in [
        "José Müller <jose@example.com>",
        "Иван Петров",
        "李小龙",
        "김민준",
        "محمد",
        "Ana 😀",
        "\u{034e}\u{0606}\u{1161}\u{fe10}\u{fffd}",
        "\u{2801}\u{1d158}\u{1d15a}",
    ] {
        assert_eq!(sanitize_untrusted(name, 300), name);
    }
}

#[test]
fn blank_looking_symbols_are_stripped_from_names_and_addresses() {
    // Not ignorable/format chars, but each draws as an empty cell.
    for c in ['\u{2800}', '\u{fffc}', '\u{1d159}'] {
        assert_eq!(sanitize_untrusted(&format!("Al{c}ice"), 300), "Alice", "{c:?}");
        assert_eq!(
            sanitize_untrusted(&format!("<alice@corp.com{c}>"), 300),
            "<alice@corp.com>",
            "{c:?}"
        );
    }
}

// ── an unattended run's output ceiling ───────────────────────────────

struct Counted<R> {
    inner: R,
    pulled: u64,
}

impl<R: std::io::Read> std::io::Read for Counted<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.pulled += n as u64;
        Ok(n)
    }
}

#[test]
fn a_capped_read_stops_one_byte_past_the_cap() {
    let mut src = Counted { inner: std::io::repeat(0x41), pulled: 0 };
    let err = read_within(&mut src, MAX_DECRYPTED_BYTES, Some(1024)).unwrap_err();
    assert_eq!(err, OUTPUT_CAP_REACHED);
    assert_eq!(src.pulled, 1025);

    let out = read_within(&b"x".repeat(1024)[..], MAX_DECRYPTED_BYTES, Some(1024)).unwrap();
    assert_eq!(out.len(), 1024);

    // A cap above the engine's own limit changes nothing.
    let err = read_within(&b"x".repeat(11)[..], 10, Some(1024)).unwrap_err();
    assert_eq!(err, too_large_to_open());
}

#[test]
fn every_unattended_entry_point_holds_back_a_message_over_the_cap() {
    let alice = aged_cert("Alice", DAY);
    let bob = aged_cert("Bob", DAY);
    let big = vec![b'a'; 4096];
    let cap = Some(1024u32);
    let room = Some(4096u32);

    let ct = encrypt_impl(&big, &keys_json(&[&bob]), Some(&alice), None).unwrap();
    let h = insert_key(&bob).unwrap();
    assert_eq!(decrypt_with_handle(&ct, h, None, cap).unwrap_err(), OUTPUT_CAP_REACHED);
    let (_, pt) = unpack(&decrypt_with_handle(&ct, h, None, room).unwrap());
    assert_eq!(pt, big);
    let (_, pt) = unpack(&decrypt_with_handle(&ct, h, None, None).unwrap());
    assert_eq!(pt, big);
    drop_key(h).unwrap();

    // Not folded into "Wrong password": JS matches it by value.
    let pw = encrypt_impl(&big, "[]", None, Some(Zeroizing::new(b"pw".to_vec()))).unwrap();
    assert_eq!(decrypt_with_password(&pw, b"pw".to_vec(), None, cap).unwrap_err(), OUTPUT_CAP_REACHED);
    let (_, pt) = unpack(&decrypt_with_password(&pw, b"pw".to_vec(), None, room).unwrap());
    assert_eq!(pt, big);
    assert_eq!(
        error_code::error_code(&decrypt_with_password(&pw, b"no".to_vec(), None, cap).unwrap_err()),
        Some(ErrorCode::SymmetricWrongPassword)
    );

    let text = "a".repeat(4096);
    let csf = cleartext_sign(&text, &alice).unwrap();
    assert_eq!(verify_message(&csf, &keys_json(&[&alice]), cap).unwrap_err(), OUTPUT_CAP_REACHED);
    let v = verdict(&verify_message(&csf, &keys_json(&[&alice]), room).unwrap());
    assert_eq!(v["signatureStatus"], "valid");

    let signed = signed_only(&big, &alice, true);
    assert_eq!(open_unencrypted(&signed, None, cap).unwrap_err(), OUTPUT_CAP_REACHED);
    let (_, pt) = unpack(&open_unencrypted(&signed, None, room).unwrap());
    assert_eq!(pt, big);
}

#[test]
fn a_small_bomb_is_held_back_without_expanding_to_the_flat_allowance() {
    // Inflates to 32 MiB, inside the uncapped 64 MiB allowance, so only the
    // caller's cap stops it.
    let bob = aged_cert("Bob", DAY);
    let mut ct = Vec::new();
    {
        let recipients: Vec<_> = bob
            .keys()
            .with_policy(policy(), None)
            .supported()
            .for_transport_encryption()
            .collect();
        let m = Armorer::new(Message::new(&mut ct)).build().unwrap();
        let m = Encryptor::for_recipients(m, recipients).build().unwrap();
        let m = openpgp::serialize::stream::Compressor::new(m).build().unwrap();
        let mut l = LiteralWriter::new(m).build().unwrap();
        let chunk = vec![0u8; 1 << 20];
        for _ in 0..32 {
            l.write_all(&chunk).unwrap();
        }
        l.finalize().unwrap();
    }
    assert!(ct.len() < 256 * 1024, "{}", ct.len());
    let h = insert_key(&bob).unwrap();
    let started = std::time::Instant::now();
    assert_eq!(decrypt_with_handle(&ct, h, None, Some(1 << 20)).unwrap_err(), OUTPUT_CAP_REACHED);
    let capped = started.elapsed();
    drop_key(h).unwrap();
    let h = insert_key(&bob).unwrap();
    let (_, pt) = unpack(&decrypt_with_handle(&ct, h, None, None).unwrap());
    drop_key(h).unwrap();
    assert_eq!(pt.len(), 32 << 20);
    assert!(capped < Duration::from_secs(5), "{capped:?}");
}

// ── review regressions: framing, compression, concatenation, size ────

fn encrypted_to(cert: &openpgp::Cert, text: &[u8]) -> Vec<u8> {
    let mut ct = Vec::new();
    {
        let recipients: Vec<_> = cert
            .keys()
            .with_policy(policy(), None)
            .supported()
            .for_transport_encryption()
            .collect();
        let m = Encryptor::for_recipients(Message::new(&mut ct), recipients).build().unwrap();
        let mut l = LiteralWriter::new(m).build().unwrap();
        l.write_all(text).unwrap();
        l.finalize().unwrap();
    }
    ct
}

fn compressed(inner: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut m = openpgp::serialize::stream::Compressor::new(Message::new(&mut out))
            .build()
            .unwrap();
        m.write_all(inner).unwrap();
        m.finalize().unwrap();
    }
    out
}

/// Password-encrypted, compressed `zeros` zero bytes: a small inflating file.
fn password_bomb(password: &str, zeros: usize) -> Vec<u8> {
    let mut ct = Vec::new();
    {
        let m = Encryptor::with_passwords(Message::new(&mut ct), Some(password)).build().unwrap();
        let m = openpgp::serialize::stream::Compressor::new(m).build().unwrap();
        let mut l = LiteralWriter::new(m).build().unwrap();
        let chunk = vec![0u8; 1 << 20];
        let mut left = zeros;
        while left > 0 {
            let n = left.min(chunk.len());
            l.write_all(&chunk[..n]).unwrap();
            left -= n;
        }
        l.finalize().unwrap();
    }
    ct
}

#[test]
fn prose_starting_with_a_non_ascii_character_still_gets_the_framing_check() {
    // A curly quote's lead byte looks like a packet header; that once skipped
    // the check and the prose above the block opened as "valid".
    let alice = aged_cert("Alice", DAY);
    let keys = Some(keys_json(&[&alice]));
    let signed = String::from_utf8(signed_only(b"ALICE GENUINE", &alice, true)).unwrap();
    for lead in [
        "\u{201c}Approved: wire 50k to acct 999\u{201d}\n\n",
        "\u{a0}Approved\n\n",
        "\u{e9}Approved\n\n",
    ] {
        let wrapped = format!("{lead}{signed}\nTrailer prose\n");
        assert!(open_unencrypted(wrapped.as_bytes(), keys.clone(), None).is_err(), "{lead:?}");
    }
    let curly = format!("\u{201c}Approved\u{201d}\n\n{signed}");
    assert_eq!(open_unencrypted(curly.as_bytes(), keys.clone(), None).unwrap_err(), outside_signed());

    let mut latin1 = b"\xe9Approved\n\n".to_vec();
    latin1.extend_from_slice(signed.as_bytes());
    assert!(open_unencrypted(&latin1, keys.clone(), None).is_err());

    let (sig, pt) = unpack(&open_unencrypted(signed.as_bytes(), keys.clone(), None).unwrap());
    assert_eq!((sig["signatureStatus"].as_str(), pt.as_slice()), (Some("valid"), &b"ALICE GENUINE"[..]));
    let binary = signed_only(b"ALICE GENUINE", &alice, false);
    let (sig, _) = unpack(&open_unencrypted(&binary, keys, None).unwrap());
    assert_eq!(sig["signatureStatus"], "valid");
}

#[test]
fn an_encrypted_message_inside_a_compressed_packet_still_decrypts() {
    let alice = aged_cert("Alice", DAY);
    let bob = aged_cert("Bob", DAY);
    let msg = compressed(&encrypted_to(&bob, b"compressed-wrapped secret"));

    let shape: serde_json::Value = serde_json::from_str(&message_encryption(&msg).unwrap()).unwrap();
    assert_eq!(shape["encrypted"], true);
    assert_eq!(shape["publicKey"], true);
    let picked: Option<String> = serde_json::from_str(
        &select_decryption_key(&msg, &serde_json::to_string(&[public(&bob)]).unwrap()).unwrap(),
    )
    .unwrap();
    assert!(picked.is_some());

    let h = insert_key(&bob).unwrap();
    let (_, pt) = unpack(&decrypt_with_handle(&msg, h, Some(keys_json(&[&alice])), None).unwrap());
    drop_key(h).unwrap();
    assert_eq!(pt, b"compressed-wrapped secret");
    assert!(open_unencrypted(&msg, None, None).unwrap_err().contains("is encrypted"));

    let pw = encrypt_impl(b"by password", "[]", None, Some(Zeroizing::new(b"pw".to_vec()))).unwrap();
    let pw = compressed(&openpgp::PacketPile::from_bytes(&pw).unwrap().to_vec().unwrap());
    let shape: serde_json::Value = serde_json::from_str(&message_encryption(&pw).unwrap()).unwrap();
    assert_eq!(shape["password"], true);
    let (_, pt) = unpack(&decrypt_with_password(&pw, b"pw".to_vec(), None, None).unwrap());
    assert_eq!(pt, b"by password");
}

#[test]
fn a_compressed_signed_message_is_still_unencrypted() {
    // `gpg --sign` output, Compressed{ OPS, Literal, Sig }.
    let alice = aged_cert("Alice", DAY);
    let keys = Some(keys_json(&[&alice]));
    let msg = compressed(&signed_only(b"Alice's public statement", &alice, false));
    let shape: serde_json::Value = serde_json::from_str(&message_encryption(&msg).unwrap()).unwrap();
    assert_eq!(shape["encrypted"], false);
    let h = insert_key(&alice).unwrap();
    assert_eq!(decrypt_with_handle(&msg, h, keys.clone(), None).unwrap_err(), not_encrypted());
    drop_key(h).unwrap();
    let (sig, pt) = unpack(&open_unencrypted(&msg, keys, None).unwrap());
    assert_eq!(sig["signatureStatus"], "valid");
    assert_eq!(pt, b"Alice's public statement");
}

#[test]
fn spliced_messages_never_open_as_something_they_are_not() {
    // Concatenation probes: none may decrypt to the signed half, nor open
    // "unencrypted" past a session-key packet.
    let alice = aged_cert("Alice", DAY);
    let bob = aged_cert("Bob", DAY);
    let keys = Some(keys_json(&[&alice, &bob]));
    let enc = encrypted_to(&bob, b"real secret");
    let public_signed = signed_only(b"ALICE PUBLIC", &alice, false);
    let pkesks: Vec<u8> = {
        let mut out = Vec::new();
        for p in openpgp::PacketPile::from_bytes(&enc).unwrap().into_children() {
            if let openpgp::Packet::PKESK(_) = p {
                p.serialize(&mut out).unwrap();
            }
        }
        out
    };
    let cat = |a: &[u8], b: &[u8]| [a, b].concat();
    let h = insert_key(&bob).unwrap();

    for (label, msg) in [
        ("enc+signed", cat(&enc, &public_signed)),
        ("signed+enc", cat(&public_signed, &enc)),
        ("pkesk+signed", cat(&pkesks, &public_signed)),
        ("signed+pkesk", cat(&public_signed, &pkesks)),
    ] {
        assert!(decrypt_with_handle(&msg, h, keys.clone(), None).is_err(), "{label}");
        if label != "enc+signed" {
            let shape: serde_json::Value =
                serde_json::from_str(&message_encryption(&msg).unwrap()).unwrap();
            assert_eq!(shape["encrypted"], true, "{label}");
            assert!(open_unencrypted(&msg, keys.clone(), None).is_err(), "{label}");
        }
    }
    let err = decrypt_with_password(&cat(&pkesks, &public_signed), b"pw".to_vec(), keys.clone(), None)
        .unwrap_err();
    assert!(!err.contains("ALICE"), "{err}");

    let mut marked = Vec::new();
    openpgp::Packet::from(openpgp::packet::Marker::default()).serialize(&mut marked).unwrap();
    marked.extend_from_slice(&public_signed);
    assert_eq!(decrypt_with_handle(&marked, h, keys.clone(), None).unwrap_err(), not_encrypted());
    let (sig, pt) = unpack(&open_unencrypted(&marked, keys.clone(), None).unwrap());
    assert_eq!((sig["signatureStatus"].as_str(), pt.as_slice()), (Some("valid"), &b"ALICE PUBLIC"[..]));

    let mut outer = Vec::new();
    {
        let recipients: Vec<_> = bob
            .keys()
            .with_policy(policy(), None)
            .supported()
            .for_transport_encryption()
            .collect();
        let m = Signer::new(Message::new(&mut outer), signing_keypair(&alice).unwrap())
            .unwrap()
            .build()
            .unwrap();
        let m = Encryptor::for_recipients(m, recipients).build().unwrap();
        let mut l = LiteralWriter::new(m).build().unwrap();
        l.write_all(b"sig outside encryption").unwrap();
        l.finalize().unwrap();
    }
    let (sig, pt) = unpack(&decrypt_with_handle(&outer, h, keys.clone(), None).unwrap());
    assert_eq!((sig["signatureStatus"].as_str(), pt.as_slice()), (Some("valid"), &b"sig outside encryption"[..]));
    assert!(open_unencrypted(&outer, keys, None).unwrap_err().contains("is encrypted"));
    drop_key(h).unwrap();

    // The cap is inclusive.
    let lit = literal_only(b"0123456789");
    assert!(open_unencrypted(&lit, None, Some(10)).is_ok());
    assert_eq!(open_unencrypted(&lit, None, Some(9)).unwrap_err(), OUTPUT_CAP_REACHED);
    assert_eq!(open_unencrypted(&lit, None, Some(0)).unwrap_err(), OUTPUT_CAP_REACHED);
}

#[test]
fn the_right_password_on_a_file_too_large_to_open_is_not_called_wrong() {
    // Past the 64 MiB allowance with the right password: the error must say size.
    let ct = password_bomb("pw", (MIN_EXPANSION_ALLOWANCE + 1) as usize);
    assert!(ct.len() < 1 << 20, "{}", ct.len());
    assert_eq!(decrypt_with_password(&ct, b"pw".to_vec(), None, None).unwrap_err(), too_large_to_open());
    assert_eq!(
        error_code::error_code(&decrypt_with_password(&ct, b"no".to_vec(), None, None).unwrap_err()),
        Some(ErrorCode::SymmetricWrongPassword)
    );
}

#[test]
fn an_unattended_cap_bounds_what_the_engine_inflates_not_just_what_it_returns() {
    // 40 MiB exceeds Sequoia's 25 MiB read-ahead, filled at construction; under
    // a 1 MiB cap the engine must hold only a few MiB.
    const CAP: u32 = 1 << 20;
    assert_eq!(stream_buffer(Some(CAP), MAX_DECRYPTED_BYTES), Some(CAP as usize + 1));
    assert_eq!(stream_buffer(None, MAX_DECRYPTED_BYTES), None);
    assert_eq!(stream_buffer(Some(64), 64), None, "a cap read_within ignores is ignored here too");

    let ct = password_bomb("pw", 40 << 20);
    let (err, peak) =
        alloc_meter::peak_during(|| decrypt_with_password(&ct, b"pw".to_vec(), None, Some(CAP)));
    assert_eq!(err.unwrap_err(), OUTPUT_CAP_REACHED);
    assert!(peak < 8 * CAP as usize, "decrypt held {peak} bytes under a {CAP} byte cap");

    let mut lit = Vec::new();
    {
        let m = openpgp::serialize::stream::Compressor::new(Message::new(&mut lit)).build().unwrap();
        let mut l = LiteralWriter::new(m).build().unwrap();
        let chunk = vec![0u8; 1 << 20];
        for _ in 0..40 {
            l.write_all(&chunk).unwrap();
        }
        l.finalize().unwrap();
    }
    let (err, peak) = alloc_meter::peak_during(|| open_unencrypted(&lit, None, Some(CAP)));
    assert_eq!(err.unwrap_err(), OUTPUT_CAP_REACHED);
    assert!(peak < 8 * CAP as usize, "open held {peak} bytes under a {CAP} byte cap");

    // Uncapped, the message is held whole, so the bound above is not vacuous.
    let (ok, peak) = alloc_meter::peak_during(|| open_unencrypted(&lit, None, None));
    assert_eq!(unpack(&ok.unwrap()).1.len(), 40 << 20);
    assert!(peak > 25 << 20, "{peak}");
}
