//! CRX3 (Chrome extension) signing and verification (see `apps/pgp/SECURITY.md`).
//!
//! An RSA-2048 signing key is protected by the same vault envelope as PGP
//! keys and signs a `.zip` into a CRX3 for "Verified CRX Uploads". CRX3 is
//! not OpenPGP: the proof is raw RSA-PKCS#1-v1.5-SHA256 over
//! `"CRX3 SignedData\0" || u32_le(len(signed_header_data)) || signed_header_data || zip`.
//!
//! Keys live as PKCS#8 DER in `CRX_KEY_STORE`, separate from `KEY_STORE` so
//! that store stays OpenPGP-only and unlock-only; only the public half
//! crosses to JS.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use rsa::sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use wasm_bindgen::prelude::*;

use crate::error_code::{coded, ErrorCode};
use crate::protected;
use crate::StrErr;

/// CRX3 file magic ("Cr24").
const CRX_MAGIC: &[u8; 4] = b"Cr24";
/// CRX format version this module reads and writes.
const CRX_VERSION: u32 = 3;
/// Domain-separation prefix: "CRX3 SignedData" + NUL (16 bytes).
const SIGNED_DATA_MAGIC: &[u8; 16] = b"CRX3 SignedData\0";

/// AAD prefixes binding a stored CRX key to its extension id. Kept in sync
/// with `lib/crx/`.
const CRX_PASSWORD_AAD_PREFIX: &str = "gpg-tools:crx-password:";
const CRX_PASSKEY_AAD_PREFIX: &str = "gpg-tools:crx-passkey:";
/// HKDF info string for the PRF-derived AES key (distinct from the PGP one).
const CRX_PRF_HKDF_INFO: &[u8] = b"gpg-tools-crx-prf-v1";

// RSA keygen draws from the crate's ChaCha20 CSPRNG (`rng::VaultRng`), see `src/rng.rs`.

// Minimal protobuf writer/reader (length-delimited + varint only).

fn write_varint(buf: &mut Vec<u8>, mut n: u64) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            buf.push(byte | 0x80);
        } else {
            buf.push(byte);
            break;
        }
    }
}

/// Write a length-delimited (wire type 2) field.
fn write_field_bytes(buf: &mut Vec<u8>, field: u64, data: &[u8]) {
    write_varint(buf, (field << 3) | 2);
    write_varint(buf, data.len() as u64);
    buf.extend_from_slice(data);
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *buf.get(*pos).ok_or("protobuf: varint truncated")?;
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err("protobuf: varint too long".to_string());
        }
    }
    Ok(result)
}

/// Read one field: `(field, Some(bytes))` for wire type 2, `(field, None)`
/// for skipped scalar types.
fn read_field<'a>(buf: &'a [u8], pos: &mut usize) -> Result<(u64, Option<&'a [u8]>), String> {
    let tag = read_varint(buf, pos)?;
    let field = tag >> 3;
    match tag & 7 {
        2 => {
            let len = read_varint(buf, pos)?;
            // Reject an absurd length before the u64->usize cast (truncates on wasm32).
            if len > buf.len() as u64 {
                return Err("protobuf: field length exceeds input".to_string());
            }
            let len = len as usize;
            let end = pos.checked_add(len).ok_or("protobuf: length overflow")?;
            let slice = buf.get(*pos..end).ok_or("protobuf: field truncated")?;
            *pos = end;
            Ok((field, Some(slice)))
        }
        0 => {
            read_varint(buf, pos)?;
            Ok((field, None))
        }
        5 => {
            *pos = pos.checked_add(4).ok_or("protobuf: i32 truncated")?;
            Ok((field, None))
        }
        1 => {
            *pos = pos.checked_add(8).ok_or("protobuf: i64 truncated")?;
            Ok((field, None))
        }
        other => Err(format!("protobuf: unsupported wire type {other}")),
    }
}

/// The 16-byte CRX id: first 128 bits of SHA-256 over the SPKI DER, as Chrome derives it.
fn crx_id_from_spki(spki_der: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(spki_der);
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

/// Render a CRX id as Chrome's 32-char `a`..`p` extension id.
fn extension_id(crx_id: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for byte in crx_id {
        s.push((b'a' + (byte >> 4)) as char);
        s.push((b'a' + (byte & 0x0f)) as char);
    }
    s
}

/// SubjectPublicKeyInfo DER for a private key's public half.
fn spki_der(private_key: &RsaPrivateKey) -> Result<Vec<u8>, String> {
    let public_key = RsaPublicKey::from(private_key);
    Ok(public_key.to_public_key_der().str_err()?.as_bytes().to_vec())
}

/// `SignedData { crx_id = 1 }`.
fn encode_signed_data(crx_id: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();
    write_field_bytes(&mut out, 1, crx_id);
    out
}

/// `AsymmetricKeyProof { public_key = 1, signature = 2 }`.
fn encode_proof(public_key: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_field_bytes(&mut out, 1, public_key);
    write_field_bytes(&mut out, 2, signature);
    out
}

/// `CrxFileHeader { sha256_with_rsa = 2, signed_header_data = 10000 }`.
fn encode_header(proof: &[u8], signed_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_field_bytes(&mut out, 2, proof);
    write_field_bytes(&mut out, 10000, signed_data);
    out
}

/// The exact byte string an RSA/ECDSA proof signs, per CRX3.
fn signing_payload(signed_data: &[u8], archive: &[u8]) -> Vec<u8> {
    let mut msg =
        Vec::with_capacity(SIGNED_DATA_MAGIC.len() + 4 + signed_data.len() + archive.len());
    msg.extend_from_slice(SIGNED_DATA_MAGIC);
    msg.extend_from_slice(&(signed_data.len() as u32).to_le_bytes());
    msg.extend_from_slice(signed_data);
    msg.extend_from_slice(archive);
    msg
}

/// Pack a ZIP archive into a signed CRX3 file using `private_key`.
fn assemble_crx(archive: &[u8], private_key: &RsaPrivateKey) -> Result<Vec<u8>, String> {
    let spki = spki_der(private_key)?;
    let crx_id = crx_id_from_spki(&spki);
    let signed_data = encode_signed_data(&crx_id);

    let payload = signing_payload(&signed_data, archive);
    let digest = Sha256::digest(&payload);
    // Deterministic (unblinded) PKCS#1 v1.5 -- no RNG needed to sign.
    let signature = private_key
        .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
        .str_err()?;

    let proof = encode_proof(&spki, &signature);
    let header = encode_header(&proof, &signed_data);

    let mut out = Vec::with_capacity(12 + header.len() + archive.len());
    out.extend_from_slice(CRX_MAGIC);
    out.extend_from_slice(&CRX_VERSION.to_le_bytes());
    out.extend_from_slice(&(header.len() as u32).to_le_bytes());
    out.extend_from_slice(&header);
    out.extend_from_slice(archive);
    Ok(out)
}

struct VerifyOutcome {
    valid: bool,
    extension_id: Option<String>,
    algorithm: Option<String>,
    error: Option<String>,
}

impl VerifyOutcome {
    fn failure(msg: impl Into<String>) -> Self {
        VerifyOutcome {
            valid: false,
            extension_id: None,
            algorithm: None,
            error: Some(msg.into()),
        }
    }
}

fn read_u32_le(buf: &[u8], pos: usize) -> Result<u32, String> {
    let end = pos.checked_add(4).ok_or("CRX: offset overflow")?;
    let bytes = buf
        .get(pos..end)
        .ok_or("CRX: truncated (expected 4-byte little-endian field)")?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Verify a CRX3: some `sha256_with_rsa` proof must verify AND its key must
/// hash to the signed crx id. Malformed input yields `valid:false`, never a
/// hard failure.
fn verify_crx_inner(crx: &[u8]) -> VerifyOutcome {
    match verify_crx_checked(crx) {
        Ok(outcome) => outcome,
        Err(e) => VerifyOutcome::failure(e),
    }
}

fn verify_crx_checked(crx: &[u8]) -> Result<VerifyOutcome, String> {
    if crx.get(0..4) != Some(CRX_MAGIC.as_slice()) {
        return Ok(VerifyOutcome::failure(coded(
            ErrorCode::NotCrx,
            "Not a CRX file (missing Cr24 magic)",
        )));
    }
    let version = read_u32_le(crx, 4)?;
    if version != CRX_VERSION {
        return Ok(VerifyOutcome::failure(coded(
            ErrorCode::NotCrx,
            &format!("Unsupported CRX version {version} (only CRX3 is supported)"),
        )));
    }
    let header_len = read_u32_le(crx, 8)? as usize;
    let header_start = 12usize;
    let header_end = header_start
        .checked_add(header_len)
        .ok_or("CRX: header length overflow")?;
    let header = crx
        .get(header_start..header_end)
        .ok_or("CRX: header extends past end of file")?;
    let archive = crx
        .get(header_end..)
        .ok_or("CRX: missing payload after header")?;

    let mut rsa_proofs: Vec<&[u8]> = Vec::new();
    let mut signed_header: Option<&[u8]> = None;
    let mut pos = 0usize;
    while pos < header.len() {
        let (field, bytes) = read_field(header, &mut pos)?;
        match (field, bytes) {
            (2, Some(b)) => rsa_proofs.push(b),
            (10000, Some(b)) => signed_header = Some(b),
            _ => {}
        }
    }
    let signed_header = signed_header.ok_or("CRX: header has no signed_header_data")?;

    let mut signed_crx_id: Option<[u8; 16]> = None;
    let mut pos = 0usize;
    while pos < signed_header.len() {
        let (field, bytes) = read_field(signed_header, &mut pos)?;
        if let (1, Some(b)) = (field, bytes) {
            if b.len() == 16 {
                let mut id = [0u8; 16];
                id.copy_from_slice(b);
                signed_crx_id = Some(id);
            }
        }
    }
    let signed_crx_id = signed_crx_id.ok_or("CRX: signed header has no crx_id")?;

    if rsa_proofs.is_empty() {
        return Ok(VerifyOutcome::failure(
            "CRX: no sha256_with_rsa proofs (only RSA is supported here)",
        ));
    }

    let payload = signing_payload(signed_header, archive);
    let digest = Sha256::digest(&payload);

    for proof in rsa_proofs {
        let mut public_key: Option<&[u8]> = None;
        let mut signature: Option<&[u8]> = None;
        let mut pos = 0usize;
        while pos < proof.len() {
            let (field, bytes) = read_field(proof, &mut pos)?;
            match (field, bytes) {
                (1, Some(b)) => public_key = Some(b),
                (2, Some(b)) => signature = Some(b),
                _ => {}
            }
        }
        let (Some(pk_der), Some(sig)) = (public_key, signature) else {
            continue;
        };
        let Ok(pk) = RsaPublicKey::from_public_key_der(pk_der) else {
            continue;
        };
        // The proving key must be the one that names the extension.
        if crx_id_from_spki(pk_der) != signed_crx_id {
            continue;
        }
        if pk
            .verify(Pkcs1v15Sign::new::<Sha256>(), &digest, sig)
            .is_ok()
        {
            return Ok(VerifyOutcome {
                valid: true,
                extension_id: Some(extension_id(&signed_crx_id)),
                algorithm: Some("sha256_with_rsa".to_string()),
                error: None,
            });
        }
    }

    Ok(VerifyOutcome {
        valid: false,
        extension_id: Some(extension_id(&signed_crx_id)),
        algorithm: Some("sha256_with_rsa".to_string()),
        error: Some(coded(
            ErrorCode::CrxUnsigned,
            "No valid signature: the CRX is unsigned by this key or was tampered with",
        )),
    })
}

fn generate_rsa2048() -> Result<RsaPrivateKey, String> {
    let mut rng = crate::rng::VaultRng;
    RsaPrivateKey::new(&mut rng, 2048).str_err()
}

/// Parse an RSA private key from PEM, accepting PKCS#8 or PKCS#1.
fn parse_rsa_private_pem(pem: &str) -> Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_pkcs8_pem(pem)
        .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
        .map_err(|_| "Not a valid RSA private key (expected PKCS#8 or PKCS#1 PEM)".to_string())
}

/// PKCS#8 DER for at-rest storage, in a zeroizing buffer.
fn private_key_der(private_key: &RsaPrivateKey) -> Result<Zeroizing<Vec<u8>>, String> {
    Ok(Zeroizing::new(
        private_key.to_pkcs8_der().str_err()?.as_bytes().to_vec(),
    ))
}

// At-rest protection over raw DER, AAD-bound to the extension id.

/// Seal a PKCS#8 DER key under a password. Returns `[16 salt][12 iv][ct]`.
fn encrypt_der_with_password(
    der: &[u8],
    ext_id: &str,
    password: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    protected::seal_with_password(
        der,
        ext_id,
        CRX_PASSWORD_AAD_PREFIX,
        password,
        memory_kib,
        iterations,
        parallelism,
    )
}

/// Seal a PKCS#8 DER key under a passkey PRF. Returns `[12 iv][ct]`.
fn encrypt_der_with_prf(
    der: &[u8],
    ext_id: &str,
    prf_output: &[u8],
    stored_secret: &[u8],
) -> Result<Vec<u8>, String> {
    protected::seal_with_prf(
        der,
        ext_id,
        CRX_PASSKEY_AAD_PREFIX,
        CRX_PRF_HKDF_INFO,
        prf_output,
        stored_secret,
    )
}

/// `{ extensionId, publicKeyDerB64, algorithm }`, packed ahead of the blob.
fn protect_meta_json(private_key: &RsaPrivateKey, ext_id: &str) -> Result<String, String> {
    let spki = spki_der(private_key)?;
    Ok(serde_json::json!({
        "extensionId": ext_id,
        "publicKeyDerB64": B64.encode(&spki),
        "algorithm": "rsa2048",
    })
    .to_string())
}

// Separate store from `KEY_STORE` so that one stays OpenPGP-only and
// unlock-only (SECURITY.md §4); handles share the crate-wide `next_handle`.
thread_local! {
    static CRX_KEY_STORE: protected::HandleStore = protected::HandleStore::new();
}

fn crx_store_get(handle: u32) -> Result<RsaPrivateKey, String> {
    CRX_KEY_STORE
        .with(|store| store.with(handle, |der| RsaPrivateKey::from_pkcs8_der(der).str_err()))
        .ok_or("CRX key handle not found - key may have been locked")?
}

/// Store a decrypted DER key only if it parses AND its public half hashes to
/// the AAD-bound extension id. AAD strings are public, so without this an
/// attacker could seal their own key under a victim's id. Plaintext is
/// zeroized on failure.
fn store_decrypted_der(der: Zeroizing<Vec<u8>>, expected_ext_id: &str) -> Result<u32, String> {
    CRX_KEY_STORE.with(|store| {
        store.insert_validated(der, |der| {
            let key = RsaPrivateKey::from_pkcs8_der(der)
                .map_err(|_| "Decrypted data is not a valid RSA private key".to_string())?;
            let actual = extension_id(&crx_id_from_spki(&spki_der(&key)?));
            if actual != expected_ext_id {
                return Err("Decrypted key does not belong to this extension id".to_string());
            }
            Ok(())
        })
    })
}

/// Generate and password-protect an RSA-2048 CRX key. Returns packed
/// `[u32_le json_len][json][blob]`, blob `[16 salt][12 iv][ct]`.
#[wasm_bindgen(js_name = "generateCrxKeyWithPassword")]
pub fn generate_crx_key_with_password(
    password: Vec<u8>,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    let password = Zeroizing::new(password);
    let private_key = generate_rsa2048()?;
    let der = private_key_der(&private_key)?;
    let ext_id = extension_id(&crx_id_from_spki(&spki_der(&private_key)?));
    let blob =
        encrypt_der_with_password(&der, &ext_id, &password, memory_kib, iterations, parallelism)?;
    Ok(protected::pack_meta_blob(&protect_meta_json(&private_key, &ext_id)?, &blob))
}

/// Generate and passkey-protect an RSA-2048 CRX key. Blob is `[12 iv][ct]`.
#[wasm_bindgen(js_name = "generateCrxKeyWithPrf")]
pub fn generate_crx_key_with_prf(
    prf_output: Vec<u8>,
    stored_secret: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let prf_output = Zeroizing::new(prf_output);
    let stored_secret = Zeroizing::new(stored_secret);
    let private_key = generate_rsa2048()?;
    let der = private_key_der(&private_key)?;
    let ext_id = extension_id(&crx_id_from_spki(&spki_der(&private_key)?));
    let blob = encrypt_der_with_prf(&der, &ext_id, &prf_output, &stored_secret)?;
    Ok(protected::pack_meta_blob(&protect_meta_json(&private_key, &ext_id)?, &blob))
}

/// Import an RSA private key (PKCS#8 or PKCS#1 PEM) under a password.
#[wasm_bindgen(js_name = "importCrxKeyWithPassword")]
pub fn import_crx_key_with_password(
    pem: &str,
    password: Vec<u8>,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    let password = Zeroizing::new(password);
    let private_key = parse_rsa_private_pem(pem)?;
    let der = private_key_der(&private_key)?;
    let ext_id = extension_id(&crx_id_from_spki(&spki_der(&private_key)?));
    let blob =
        encrypt_der_with_password(&der, &ext_id, &password, memory_kib, iterations, parallelism)?;
    Ok(protected::pack_meta_blob(&protect_meta_json(&private_key, &ext_id)?, &blob))
}

/// Import an RSA private key (PKCS#8 or PKCS#1 PEM) under a passkey.
#[wasm_bindgen(js_name = "importCrxKeyWithPrf")]
pub fn import_crx_key_with_prf(
    pem: &str,
    prf_output: Vec<u8>,
    stored_secret: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let prf_output = Zeroizing::new(prf_output);
    let stored_secret = Zeroizing::new(stored_secret);
    let private_key = parse_rsa_private_pem(pem)?;
    let der = private_key_der(&private_key)?;
    let ext_id = extension_id(&crx_id_from_spki(&spki_der(&private_key)?));
    let blob = encrypt_der_with_prf(&der, &ext_id, &prf_output, &stored_secret)?;
    Ok(protected::pack_meta_blob(&protect_meta_json(&private_key, &ext_id)?, &blob))
}

/// Re-seal an unlocked CRX key under a password without the plaintext leaving
/// WASM (portable "Export All Keys" backup).
#[wasm_bindgen(js_name = "reprotectCrxKeyWithPassword")]
pub fn reprotect_crx_key_with_password(
    handle: u32,
    password: Vec<u8>,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<Vec<u8>, String> {
    let password = Zeroizing::new(password);
    let private_key = crx_store_get(handle)?;
    let der = private_key_der(&private_key)?;
    let ext_id = extension_id(&crx_id_from_spki(&spki_der(&private_key)?));
    let blob =
        encrypt_der_with_password(&der, &ext_id, &password, memory_kib, iterations, parallelism)?;
    Ok(protected::pack_meta_blob(&protect_meta_json(&private_key, &ext_id)?, &blob))
}

/// Export an unlocked CRX key as UNENCRYPTED PKCS#8 PEM: the deliberate
/// "copy raw key" path, gated behind confirmation in JS. The returned
/// `String` copied across the ABI cannot be zeroized (as `get_key_armored`).
#[wasm_bindgen(js_name = "exportCrxPrivateKeyPem")]
pub fn export_crx_private_key_pem(handle: u32) -> Result<String, String> {
    let private_key = crx_store_get(handle)?;
    let pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .str_err()?;
    Ok(pem.to_string())
}

/// Unlock a password-protected CRX key into `CRX_KEY_STORE`; returns a handle.
#[wasm_bindgen(js_name = "unlockCrxWithPassword")]
#[allow(clippy::too_many_arguments)] // flat wasm ABI; KDF params come from the blob
pub fn unlock_crx_with_password(
    ciphertext: &[u8],
    iv: &[u8],
    salt: &[u8],
    ext_id: &str,
    password: Vec<u8>,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<u32, String> {
    // Owned, not `&[u8]`: wasm-bindgen frees a borrowed copy unscrubbed.
    // SECURITY.md §8.4, T-UNLOCK-PARAM-NOT-OWNED.
    let password = Zeroizing::new(password);
    let der = protected::open_with_password(
        ciphertext,
        iv,
        salt,
        ext_id,
        CRX_PASSWORD_AAD_PREFIX,
        &password,
        memory_kib,
        iterations,
        parallelism,
    )?;
    store_decrypted_der(der, ext_id)
}

/// Unlock a passkey-protected CRX key into `CRX_KEY_STORE`; returns a handle.
#[wasm_bindgen(js_name = "unlockCrxWithPrf")]
pub fn unlock_crx_with_prf(
    ciphertext: &[u8],
    iv: &[u8],
    prf_output: Vec<u8>,
    stored_secret: Vec<u8>,
    ext_id: &str,
) -> Result<u32, String> {
    // Owned + Zeroizing, as above (T-UNLOCK-PARAM-NOT-OWNED).
    let prf_output = Zeroizing::new(prf_output);
    let stored_secret = Zeroizing::new(stored_secret);
    let der = protected::open_with_prf(
        ciphertext,
        iv,
        ext_id,
        CRX_PASSKEY_AAD_PREFIX,
        CRX_PRF_HKDF_INFO,
        &prf_output,
        &stored_secret,
    )?;
    store_decrypted_der(der, ext_id)
}

/// Sign a packed extension ZIP into a CRX3 `.crx` using an unlocked handle.
#[wasm_bindgen(js_name = "signCrxWithHandle")]
pub fn sign_crx_with_handle(zip_bytes: &[u8], key_handle: u32) -> Result<Vec<u8>, String> {
    let private_key = crx_store_get(key_handle)?;
    assemble_crx(zip_bytes, &private_key)
}

/// Drop (and zeroize) an unlocked CRX key handle.
#[wasm_bindgen(js_name = "dropCrxKey")]
pub fn drop_crx_key(handle: u32) -> Result<(), String> {
    CRX_KEY_STORE.with(|store| store.remove(handle));
    Ok(())
}

/// Verify a CRX3 file (no key needed). Returns JSON
/// `{ valid, extensionId?, algorithm?, error? }`.
#[wasm_bindgen(js_name = "verifyCrx")]
pub fn verify_crx(crx: &[u8]) -> String {
    let outcome = verify_crx_inner(crx);
    serde_json::json!({
        "valid": outcome.valid,
        "extensionId": outcome.extension_id,
        "algorithm": outcome.algorithm,
        "error": outcome.error,
    })
    .to_string()
}

#[cfg(test)]
#[path = "crx_tests.rs"]
mod crx_tests;
