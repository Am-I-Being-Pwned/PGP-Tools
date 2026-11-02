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
mod crx_tests {
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
}
