//! Stripping OpenPGP S2K passphrase protection on import, including the
//! GnuPG padded-MPI fallback.

use openpgp::types::{HashAlgorithm, SymmetricAlgorithm};
use sequoia_openpgp as openpgp;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{coded, ErrorCode, StrErr};

/// Decrypt one S2K-protected component key, falling back to
/// `decrypt_gpg_padded_secret` for GnuPG's fixed-width ECC MPIs.
fn decrypt_key_secret<R>(
    key: openpgp::packet::Key<openpgp::packet::key::SecretParts, R>,
    password: &openpgp::crypto::Password,
) -> Result<openpgp::packet::Key<openpgp::packet::key::SecretParts, R>, String>
where
    R: openpgp::packet::key::KeyRole,
{
    match key.clone().decrypt_secret(password) {
        Ok(k) => Ok(k),
        Err(e) => decrypt_gpg_padded_secret(key, password, &e),
    }
}

/// Is this `decrypt_secret` failure Sequoia's strict MPI parser refusing
/// GnuPG's padded scalar? Only `MalformedMPI` qualifies: `InvalidOperation`
/// (schemes RFC 9580 forbids) must never reach the manual path, which
/// doesn't re-check them -- that would be a validation downgrade. The
/// "checksum wrong" MalformedMPI is excluded by message (the only signal;
/// a mismatch just means falling back more, never less safely). A wrong
/// passphrase can't be told apart here, but the manual path re-checks the
/// checksum, so it still ends as "Incorrect passphrase".
fn is_padded_mpi_failure(e: &anyhow::Error) -> bool {
    match e.downcast_ref::<openpgp::Error>() {
        Some(openpgp::Error::MalformedMPI(msg)) => !msg.contains("checksum"),
        _ => false,
    }
}

/// GnuPG serializes protected ECC secret scalars as fixed-width MPIs
/// (leading zero bits), which Sequoia's strict parser rejects -- about half
/// of exported ECC keys. Redo S2K + CFB + checksum by hand and re-encode
/// the scalar minimally.
fn decrypt_gpg_padded_secret<R>(
    key: openpgp::packet::Key<openpgp::packet::key::SecretParts, R>,
    password: &openpgp::crypto::Password,
    sequoia_err: &anyhow::Error,
) -> Result<openpgp::packet::Key<openpgp::packet::key::SecretParts, R>, String>
where
    R: openpgp::packet::key::KeyRole,
{
    use openpgp::crypto::mpi;
    use openpgp::crypto::S2K;
    use openpgp::types::PublicKeyAlgorithm;

    let wrong = || coded(ErrorCode::WrongPassphrase, "Incorrect passphrase");

    // Only single-scalar ECC needs this; libgcrypt encodes RSA/DSA/ElGamal
    // minimally, so a failure there really is a wrong passphrase.
    let pk_algo = key.pk_algo();
    if !matches!(
        pk_algo,
        PublicKeyAlgorithm::EdDSA | PublicKeyAlgorithm::ECDSA | PublicKeyAlgorithm::ECDH
    ) {
        return Err(wrong());
    }

    let openpgp::packet::key::SecretKeyMaterial::Encrypted(e) = key.secret() else {
        return Err(wrong());
    };
    // GNU-dummy S2K (type 101) from `--export-secret-subkeys`: no secret at all.
    if let S2K::Private { tag: 101, .. } = e.s2k() {
        return Err(
            "This key's primary secret is a stub (offline primary key). \
             Import a full export (gpg --export-secret-keys) instead."
                .into(),
        );
    }
    if e.aead_algo().is_some() {
        return Err(wrong());
    }

    // Everything above is diagnosis only. Redo the crypto by hand ONLY for the
    // padded-MPI failure; a scheme Sequoia refused or a truncated packet gets
    // no second, less strict attempt.
    if !is_padded_mpi_failure(sequoia_err) {
        return Err(wrong());
    }

    let sym = e.algo();
    let key_size = sym.key_size().map_err(|_| wrong())?;
    let block_size = sym.block_size().map_err(|_| wrong())?;
    let derived = e
        .s2k()
        .derive_key(password, key_size)
        .map_err(|_| wrong())?;
    // Sequoia stores the packet's IV prepended to the ciphertext.
    let ct = e.ciphertext().map_err(|_| wrong())?;
    if ct.len() < block_size + 3 {
        return Err(wrong());
    }
    let (iv, data) = ct.split_at(block_size);
    let plaintext = Zeroizing::new(cfb_decrypt(sym, &derived, iv, data)?);

    // Verify the trailing checksum; a mismatch means a wrong passphrase.
    let body = match e.checksum().unwrap_or_default() {
        mpi::SecretKeyChecksum::SHA1 => {
            let split = plaintext.len().checked_sub(20).ok_or_else(wrong)?;
            let (body, want) = plaintext.split_at(split);
            let mut ctx = HashAlgorithm::SHA1
                .context()
                .map_err(|_| wrong())?
                .for_digest();
            ctx.update(body);
            let got = ctx.into_digest().map_err(|_| wrong())?;
            // Constant-time: this IS the passphrase check, so `!=` would leak how many
            // leading bytes matched. Slice `ct_eq` is false (not a panic) on length mismatch.
            if !bool::from(got.as_slice().ct_eq(want)) {
                return Err(wrong());
            }
            body
        }
        mpi::SecretKeyChecksum::Sum16 => {
            let split = plaintext.len().checked_sub(2).ok_or_else(wrong)?;
            let (body, want) = plaintext.split_at(split);
            let got = body
                .iter()
                .fold(0u16, |acc, b| acc.wrapping_add(*b as u16));
            // Constant-time, as the SHA-1 arm.
            if !bool::from(got.to_be_bytes().ct_eq(want)) {
                return Err(wrong());
            }
            body
        }
    };

    // One scalar MPI: 2-byte bit length + (possibly padded) value;
    // `ProtectedMPI::from` trims the leading zeros.
    if body.len() < 2 {
        return Err(wrong());
    }
    let declared_bits = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() != 2 + declared_bits.div_ceil(8) {
        return Err(wrong());
    }
    let scalar: mpi::ProtectedMPI = (&body[2..]).into();
    let material = match pk_algo {
        PublicKeyAlgorithm::EdDSA => mpi::SecretKeyMaterial::EdDSA { scalar },
        PublicKeyAlgorithm::ECDSA => mpi::SecretKeyMaterial::ECDSA { scalar },
        _ => mpi::SecretKeyMaterial::ECDH { scalar },
    };
    Ok(key.parts_into_public().add_secret(material.into()).0)
}

/// CFB-128 decrypt (AES family only) for the padded fallback; the checksum
/// afterwards authenticates it. The mode is RustCrypto's `cfb-mode`, never
/// hand-rolled: a hostile key file picks cipher, IV and length, and
/// `new_from_slices` turns every size mismatch into an `Err` -- a panic
/// would abort the whole wasm module, unlocked keys included. AES-only is a
/// policy choice about untrusted input.
pub(crate) fn cfb_decrypt(
    sym: SymmetricAlgorithm,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    use cfb_mode::cipher::{BlockCipherEncrypt, KeyInit, KeyIvInit};

    fn run<C>(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String>
    where
        C: BlockCipherEncrypt + KeyInit,
    {
        let mut buf = ciphertext.to_vec();
        cfb_mode::Decryptor::<C>::new_from_slices(key, iv)
            .map_err(|_| {
                "This key's protection header is malformed (bad key or IV size)".to_string()
            })?
            .decrypt(&mut buf);
        Ok(buf)
    }

    match sym {
        SymmetricAlgorithm::AES128 => run::<aes::Aes128>(key, iv, ciphertext),
        SymmetricAlgorithm::AES192 => run::<aes::Aes192>(key, iv, ciphertext),
        SymmetricAlgorithm::AES256 => run::<aes::Aes256>(key, iv, ciphertext),
        _ => Err(format!(
            "This key is protected with an unsupported legacy cipher ({sym}). \
             Re-export it with: gpg --export-secret-keys --s2k-cipher-algo AES256"
        )),
    }
}

/// Strip S2K passphrase protection from any encrypted secret packets
/// (returns `cert` unchanged if none are encrypted).
pub(crate) fn decrypt_cert_secrets(
    cert: openpgp::Cert,
    source_passphrase: &[u8],
) -> Result<openpgp::Cert, String> {
    if !cert.keys().secret().any(|ka| ka.key().secret().is_encrypted()) {
        return Ok(cert);
    }

    let password = openpgp::crypto::Password::from(source_passphrase);

    let primary_key = cert
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()
        .map_err(|_| "Primary key has no secret material".to_string())?;
    let primary = if primary_key.secret().is_encrypted() {
        decrypt_key_secret(primary_key, &password)?
    } else {
        primary_key
    };

    let mut packets: Vec<openpgp::Packet> = vec![primary.role_into_primary().into()];
    for subkey in cert.keys().subkeys().secret() {
        let key = subkey.key().clone();
        let decrypted = if key.secret().is_encrypted() {
            decrypt_key_secret(key, &password)?
        } else {
            key
        };
        packets.push(decrypted.role_into_subordinate().into());
    }

    let (decrypted_cert, _) = cert.insert_packets(packets).str_err()?;
    Ok(decrypted_cert)
}
