//! Who signed this, is it still them, and what does an import change?
//!
//! Each test pins one way a "verified" verdict or a stored contact could
//! say more than the cryptography does: unbound or lookalike User IDs, a
//! backdated or partial signature, a forwarded message, an import that
//! rolls a contact back or drops its revocation.

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
    // Anyone can append a User ID packet to Bob's real cert. With no
    // self-signature it is not Bob's claim, and it must not name him --
    // "Aaron CEO" sorts first and would otherwise head every signer card.
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

    // Judged per word: a Cyrillic or Greek name with a Latin address is
    // ordinary, and must not be flagged.
    for honest in [
        "Alice",
        "Иван Петров <ivan@example.ru>",
        "Νίκος Παπάς <nikos@example.gr>",
        "José Müller <jose@example.de>",
        "Ani Հայ <ani@example.am>",
    ] {
        assert!(!mixes_scripts(honest), "{honest} flagged");
    }
    // Letters that pass for Latin ones: fullwidth, IPA, Cherokee, small
    // capitals, math bold, the Kelvin sign, Lisu.
    for fake in [
        "\u{ff21}lice",
        "\u{0251}lice",
        "\u{13aa}lice",
        "Bob <\u{0430}lice@example.com>",
        "\u{1d00}lice",
        "\u{1d400}lice",
        "\u{212a}evin",
        "\u{a4ee}lice",
        // A domain label in another script next to a Latin one.
        "Tim <tim@\u{0430}\u{0440}\u{0440}\u{04cf}\u{0435}.com>",
    ] {
        assert!(mixes_scripts(fake), "{fake:?} missed");
    }
    // ...while an all-Cyrillic address is a Cyrillic address.
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
    // Sequoia refuses the key at the claimed time (UnboundKey). We hold
    // that key, so this is a forgery signal: amber "unknown signer" would
    // show the forged text instead of hiding it.
    let bob = aged_cert("Bob", 10 * DAY);
    let signed = cleartext_at("Pay account 111.", &bob, SystemTime::now() - 400 * DAY);
    let forged = signed.replace("Pay account 111.", "Pay account 999.");

    for input in [signed, forged] {
        let v = verdict(&verify_message(&input, &keys_json(&[&bob])).unwrap());
        assert_eq!(v["signatureStatus"], "invalid");
        assert_eq!(v["signerKeyId"], serde_json::Value::Null);
    }
}

#[test]
fn a_good_signature_reports_when_it_was_made_and_whether_the_key_is_still_current() {
    let bob = aged_cert("Bob", 10 * DAY);
    let at = SystemTime::now() - 5 * DAY;
    let signed = cleartext_at("Old notice.", &bob, at);

    let v = verdict(&verify_message(&signed, &keys_json(&[&bob])).unwrap());
    assert_eq!(v["signatureStatus"], "valid");
    assert_eq!(v["signerKeyCurrent"], true);
    let signed_at = v["signedAt"].as_f64().unwrap();
    assert!((signed_at - system_time_to_millis(at)).abs() < 1_000.0);

    // Superseded since: the old signature still verifies (it was made
    // while the key was good) -- but the UI must be told the key is gone.
    let superseded = revoke(&bob, ReasonForRevocation::KeySuperseded);
    let v = verdict(&verify_message(&signed, &keys_json(&[&superseded])).unwrap());
    assert_eq!(v["signatureStatus"], "valid");
    assert_eq!(v["signerKeyCurrent"], false);

    // Compromised: every signature is suspect, whatever its date.
    let compromised = revoke(&bob, ReasonForRevocation::KeyCompromised);
    let v = verdict(&verify_message(&signed, &keys_json(&[&compromised])).unwrap());
    assert_eq!(v["signatureStatus"], "invalid");
}

/// An armored inline-signed message with one signature per cert.
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
    // Mallory's key is revoked as compromised, so his signature fails --
    // and a verdict naming only Alice would hide that failure.
    let alice = aged_cert("Alice", 10 * DAY);
    let mallory = aged_cert("Mallory", 10 * DAY);
    let msg = inline_multi("pay 1000", &[&alice, &mallory]);
    let compromised = revoke(&mallory, ReasonForRevocation::KeyCompromised);

    let v = verdict(&verify_message(&msg, &keys_json(&[&alice, &mallory])).unwrap());
    assert_eq!(v["signatureStatus"], "valid", "control: both good");

    let v = verdict(&verify_message(&msg, &keys_json(&[&alice, &compromised])).unwrap());
    assert_eq!(v["signatureStatus"], "invalid");
}

#[test]
fn every_good_signer_and_every_unchecked_signature_is_reported() {
    let alice = aged_cert("Alice", 10 * DAY);
    let bob = aged_cert("Bob", 10 * DAY);
    let carol = aged_cert("Carol", 10 * DAY);
    let msg = inline_multi("joint statement", &[&alice, &bob, &carol]);

    // Carol's key is not held: still valid, but the extra signature is
    // counted rather than silently dropped.
    let v = verdict(&verify_message(&msg, &keys_json(&[&alice, &bob])).unwrap());
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
    assert!(verify_message(&prose, &keys).unwrap_err().contains("outside the signed part"));

    for charset in ["UTF-8", "ISO-8859-1"] {
        let real = signed.replacen(sig_begin, &format!("{sig_begin}Charset: {charset}\n"), 1);
        assert_eq!(verdict(&verify_message(&real, &keys).unwrap())["signatureStatus"], "valid");
    }
}

// ── forwarding ───────────────────────────────────────────────────────

/// What Bob sees inside a message once he has decrypted it: the signed
/// packets, ready to be re-encrypted to someone else.
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

    // Bob still reads it as valid.
    let h = insert_key(&bob).unwrap();
    let (sig, pt) = unpack(&decrypt_with_handle(&ct, h, Some(keys_json(&[&alice]))).unwrap());
    drop_key(h).unwrap();
    assert_eq!(sig["signatureStatus"], "valid");
    assert_eq!(pt, b"hi bob");

    // The same signature re-encrypted to Carol does not verify for her.
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
    let (sig, _) = unpack(&decrypt_with_handle(&sink, h, Some(keys_json(&[&alice]))).unwrap());
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
    // Encrypted while the key was alive.
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
        let (_, pt) = unpack(&decrypt_with_handle(&sink, h, None).unwrap());
        drop_key(h).unwrap();
        assert_eq!(pt, b"old mail");
    }
}

// ── importing a contact again ────────────────────────────────────────

#[test]
fn an_older_copy_cannot_undo_a_subkey_revocation() {
    // Alice revoked a leaked encryption subkey. A pre-rotation copy of her
    // cert, imported over the stored one, must not bring it back.
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
    // Mallory signs a "revocation" of Alice's key with his own key.
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
    // ...and leaves no trace: the forged signature is dropped, so the
    // import reads as "nothing changed", not as an empty update.
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
    // No web of trust here: other people's certifications only cost
    // parse time, and a flooded cert carries tens of thousands.
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
    // ...while the owner's own binding survives.
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

    // Bob "revokes his certification" of Alice's User ID, over and over.
    let mut flood: Vec<openpgp::Packet> = Vec::new();
    for _ in 0..20 {
        let sig = SignatureBuilder::new(SignatureType::CertificationRevocation)
            .sign_userid_binding(&mut bkp, alice.primary_key().key(), &uid)
            .unwrap();
        flood.push(sig.into());
    }
    // And an unbound subkey -- Bob's own primary, appended -- so its
    // certifications would count as "own" if appended keys counted.
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
    // Sequoia only enforces intended recipients when a message is opened
    // with a key. Verify (and a password decrypt) has no "us" to check,
    // so the list is handed to the UI to check against the user's keys.
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
    let v = verdict(&verify_message(std::str::from_utf8(&sink).unwrap(), &keys_json(&[&alice])).unwrap());
    assert_eq!(v["signatureStatus"], "valid");
    assert_eq!(v["intendedRecipients"], serde_json::json!([bob.fingerprint().to_hex()]));
}

#[test]
fn stripping_a_key_flooded_with_forged_signatures_stays_fast() {
    // A local key file has no size cap. Thousands of bad signatures used
    // to make the strip quadratic (a list lookup per packet).
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
    // Signed by Mallory's key over Alice's: bad signatures, not certifications.
    let started = std::time::Instant::now();
    let stripped = strip_third_party(flooded).unwrap();
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    assert_eq!(stripped.bad_signatures().count(), 0);
}

#[test]
fn a_flood_of_lines_or_bytes_is_refused_before_the_framing_check_walks_it() {
    // 200 MB of newlines inside a signed block aborted the wasm engine:
    // the framing check kept an entry per line before any cap applied.
    let lines = format!(
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n{}x\n-----BEGIN PGP SIGNATURE-----\n\niQ==\n-----END PGP SIGNATURE-----\n",
        "\n".repeat(MAX_SIGNED_LINES + 1),
    );
    assert!(verify_message(&lines, "[]").unwrap_err().contains("too many lines"));

    let bytes = "a".repeat(MAX_SIGNED_INPUT_BYTES + 1);
    assert!(verify_message(&bytes, "[]").unwrap_err().contains("too large"));
}

// ── a "message" that was never encrypted ─────────────────────────────

/// An inline-signed message with no encryption layer, as `gpg --sign`
/// writes it: what anyone can make of a public statement Alice signed.
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

/// A bare literal packet, armored as a PGP MESSAGE: no signature and no
/// encryption, yet it used to "decrypt".
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
        let err = decrypt_with_handle(&msg, h, Some(keys.clone())).unwrap_err();
        assert_eq!(err, NOT_ENCRYPTED);
        // Not folded into "wrong password": nothing here takes one.
        let err = decrypt_with_password(&msg, b"pw".to_vec(), Some(keys.clone())).unwrap_err();
        assert_eq!(err, NOT_ENCRYPTED);
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
    let (sig, pt) = unpack(&decrypt_with_handle(&ct, h, Some(keys_json(&[&alice]))).unwrap());
    drop_key(h).unwrap();
    assert_eq!(sig["signatureStatus"], "valid");
    assert_eq!(pt, b"hi bob");

    let pw = encrypt_impl(b"by password", "[]", None, Some(Zeroizing::new(b"pw".to_vec()))).unwrap();
    let (_, pt) = unpack(&decrypt_with_password(&pw, b"pw".to_vec(), None).unwrap());
    assert_eq!(pt, b"by password");
}

#[test]
fn an_unencrypted_message_opens_with_its_verdict_and_no_key() {
    let alice = aged_cert("Alice", DAY);
    let keys = Some(keys_json(&[&alice]));

    for armor in [true, false] {
        let msg = signed_only(b"Alice's public statement", &alice, armor);
        let (sig, pt) = unpack(&open_unencrypted(&msg, keys.clone()).unwrap());
        assert_eq!(sig["signatureStatus"], "valid", "armor={armor}");
        assert_eq!(pt, b"Alice's public statement");
    }

    let (sig, pt) = unpack(&open_unencrypted(&literal_only(b"plain"), keys.clone()).unwrap());
    assert_eq!(sig["signatureStatus"], "unsigned");
    assert_eq!(pt, b"plain");

    // Cleartext-signed text reaching the decrypt tab opens the same way,
    // under the same framing check Verify applies.
    let csf = cleartext_sign("Line one\nLine two", &alice).unwrap();
    let (sig, pt) = unpack(&open_unencrypted(csf.as_bytes(), keys.clone()).unwrap());
    assert_eq!(sig["signatureStatus"], "valid");
    assert_eq!(pt, b"Line one\nLine two");
}

#[test]
fn opening_unencrypted_refuses_encrypted_input_and_text_around_the_block() {
    let alice = aged_cert("Alice", DAY);
    let bob = aged_cert("Bob", DAY);
    let keys = Some(keys_json(&[&alice]));

    let ct = encrypt_impl(b"hi bob", &keys_json(&[&bob]), None, None).unwrap();
    assert!(open_unencrypted(&ct, keys.clone()).unwrap_err().contains("is encrypted"));

    // Prose the signer never wrote, around (or in front of) the block.
    let signed = String::from_utf8(signed_only(b"ALICE GENUINE", &alice, true)).unwrap();
    for wrapped in [
        format!("Approved: wire 50k\n\n{signed}"),
        format!("{signed}\nSee also: acct 999\n"),
        format!("{}\n{signed}", String::from_utf8(literal_only(b"MALLORY FAKE")).unwrap()),
    ] {
        assert_eq!(open_unencrypted(wrapped.as_bytes(), keys.clone()).unwrap_err(), OUTSIDE_SIGNED);
    }
}

/// Re-armor `signed` with its literal body swapped for `body`, keeping
/// the original signature packets.
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
    // Pinned, not endorsed: Sequoia's text-mode hashing turns \r, \n and
    // \r\n alike into CRLF, so a 0x01 signature over "Approved:\nNO" also
    // covers "Approved:\rNO" -- which a browser renders as "Approved:NO".
    // The UI marks any lone CR under a good signature (amber, with a
    // note) and draws it visibly; if this test starts failing, Sequoia
    // changed the canonicalisation and that caveat can be revisited.
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
    let v = verdict(&verify_message(&swapped, &keys_json(&[&alice])).unwrap());
    assert_eq!(v["signatureStatus"], "valid");
    assert_eq!(v["text"], "Approved:\rNO");

    // A cleartext-signed paste never gets that far: the framing check
    // refuses a CR anywhere but before a LF.
    let csf = cleartext_sign("Approved:\nNO", &alice).unwrap().replace("Approved:\nNO", "Approved:\rNO");
    assert_eq!(verify_message(&csf, &keys_json(&[&alice])).unwrap_err(), OUTSIDE_SIGNED);
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
    // A whole ASCII string smuggled in tag characters vanishes with them.
    let tags: String = "evil".chars().map(|c| char::from_u32(0xE0000 + c as u32).unwrap()).collect();
    assert_eq!(sanitize_untrusted(&format!("alice{tags}@example.com"), 300), "alice@example.com");

    // Ordinary names in any script are left as they are, and the
    // neighbours of each range survive.
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
    // Not ignorable and not format characters, so neither property
    // covers them -- but each draws as an empty cell, so
    // `alice@corp.com` followed by one reads exactly like the address.
    for c in ['\u{2800}', '\u{fffc}', '\u{1d159}'] {
        assert_eq!(sanitize_untrusted(&format!("Al{c}ice"), 300), "Alice", "{c:?}");
        assert_eq!(
            sanitize_untrusted(&format!("<alice@corp.com{c}>"), 300),
            "<alice@corp.com>",
            "{c:?}"
        );
    }
}
