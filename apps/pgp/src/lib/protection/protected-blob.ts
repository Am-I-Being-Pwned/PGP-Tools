/**
 * The at-rest protection fields shared by every key type, and the packed
 * blob format the wasm protect exports return. None of these fields is
 * secret (salts and HKDF secret are stored in the clear by design).
 */

interface PasswordProtection {
  method: "password";
  kdfSalt: string; // base64 (Argon2id salt)
}

/** `storedSecret` is fresh per blob so two blobs off one ceremony still
 *  get distinct AES keys. */
interface PasskeyProtection {
  method: "passkey";
  credentialId: string; // base64url
  prfSalt: string; // base64
  storedSecret: string; // base64 (HKDF salt; not itself secret)
}

export type KeyProtection = PasswordProtection | PasskeyProtection;

// The one JS place that knows the packed-blob offsets.
const IV_BYTES = 12;
const SALT_BYTES = 16;

export interface PasswordBlobParts {
  salt: Uint8Array;
  iv: Uint8Array;
  ct: Uint8Array;
}

export interface PrfBlobParts {
  iv: Uint8Array;
  ct: Uint8Array;
}

/** A truncated blob must fail as a format error, not later as an AEAD
 *  failure the UI would report as a wrong password. */
function requireLength(packed: Uint8Array, min: number, layout: string): void {
  if (packed.length <= min) {
    throw new Error(
      `Malformed protected blob: ${packed.length} bytes cannot hold ${layout}`,
    );
  }
}

/** `[16 salt][12 iv][ct]` — the password (Argon2id) protect exports. */
export function unpackPasswordBlob(packed: Uint8Array): PasswordBlobParts {
  requireLength(packed, SALT_BYTES + IV_BYTES, "[16 salt][12 iv][ct]");
  return {
    salt: packed.slice(0, SALT_BYTES),
    iv: packed.slice(SALT_BYTES, SALT_BYTES + IV_BYTES),
    ct: packed.slice(SALT_BYTES + IV_BYTES),
  };
}

/** `[12 iv][ct]` — the PRF protect exports. */
export function unpackPrfBlob(packed: Uint8Array): PrfBlobParts {
  requireLength(packed, IV_BYTES, "[12 iv][ct]");
  return { iv: packed.slice(0, IV_BYTES), ct: packed.slice(IV_BYTES) };
}

export interface MetaBlob<M> {
  meta: M;
  blob: Uint8Array;
}

/**
 * `[u32_le json_len][json][blob]`, returned by every protect export.
 * wasm-bindgen returns a view with non-zero `byteOffset`: build the
 * DataView over the view's window, never `packed.buffer` alone.
 */
export function unpackMetaBlob<M>(packed: Uint8Array): MetaBlob<M> {
  requireLength(packed, 4, "[u32_le json_len][json][blob]");
  const view = new DataView(
    packed.buffer,
    packed.byteOffset,
    packed.byteLength,
  );
  const jsonLen = view.getUint32(0, true);
  if (4 + jsonLen > packed.length) {
    throw new Error(
      `Malformed protected blob: metadata length ${jsonLen} exceeds the ${packed.length}-byte payload`,
    );
  }
  const json = new TextDecoder().decode(packed.slice(4, 4 + jsonLen));
  return { meta: JSON.parse(json) as M, blob: packed.slice(4 + jsonLen) };
}
