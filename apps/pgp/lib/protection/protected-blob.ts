/**
 * The at-rest shape shared by every protected key blob, and the wire
 * format of the packed blob the wasm protect exports hand back.
 *
 * Every key type we store — OpenPGP certs (`storage/keyring.ts`), CRX
 * RSA signing keys (`crx/types.ts`) — is sealed by the same two
 * mechanisms (Argon2id or WebAuthn-PRF -> AES-256-GCM, all inside WASM),
 * so they all describe that seal with the same fields. Defining the union
 * once means a third key type inherits the format rather than restating
 * it, and that the readers can't drift apart field by field.
 *
 * None of these fields is secret: the salts and the stored HKDF secret
 * are persisted in the clear alongside the ciphertext by design. What is
 * secret is the password / PRF output that combines with them, and that
 * never reaches a stored blob.
 */

/** Argon2id: the salt is all the reader needs to re-derive the AES key
 *  from the user's password. */
export interface PasswordProtection {
  method: "password";
  kdfSalt: string; // base64 (Argon2id salt)
}

/** WebAuthn-PRF: `prfSalt` reproduces the same PRF output from the same
 *  authenticator; `storedSecret` is the HKDF salt mixed with it, fresh
 *  per blob so two blobs off one ceremony still get distinct AES keys. */
export interface PasskeyProtection {
  method: "passkey";
  credentialId: string; // base64url
  prfSalt: string; // base64
  storedSecret: string; // base64 (HKDF salt; not itself secret)
}

export type KeyProtection = PasswordProtection | PasskeyProtection;

// ── packed-blob unpacking ────────────────────────────────────────────
// The wasm protect exports return one packed `Uint8Array` rather than a
// struct, so the layout lives here — on the JS side there is exactly one
// place that knows the offsets, for every key type.

/** AES-GCM nonce, and the Argon2id salt that precedes it in a password
 *  seal. Restated as named constants so the three unpackers below and
 *  the length checks can't drift apart from each other. */
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

/**
 * A blob too short to contain its own header is a FORMAT violation, and
 * must fail as one.
 *
 * `slice` past the end returns a short array rather than throwing, so a
 * truncated blob used to sail through here with a 3-byte "salt" and an
 * empty IV, and only failed several layers down at the AEAD tag check —
 * which the UI reports as a wrong password. That sends the user looking
 * for a credential problem they do not have, while the real fault (a
 * clipped backup, a half-written storage record) goes unnamed.
 */
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

/** `[12 iv][ct]` — the PRF protect exports. No salt: the HKDF salt is
 *  `storedSecret`, which the caller already holds. */
export function unpackPrfBlob(packed: Uint8Array): PrfBlobParts {
  requireLength(packed, IV_BYTES, "[12 iv][ct]");
  return { iv: packed.slice(0, IV_BYTES), ct: packed.slice(IV_BYTES) };
}

/** Metadata plus the raw protection blob, as every wasm protect export
 *  hands it back. `M` is the key type's own public-only metadata. */
export interface MetaBlob<M> {
  meta: M;
  /** Packed binary protection blob — `[16 salt][12 iv][ct]` for the
   *  password variants, `[12 iv][ct]` for the PRF ones. */
  blob: Uint8Array;
}

/**
 * `[u32_le json_len][json][blob]` — the shape EVERY protect export
 * returns, for every key type (OpenPGP, CRX, SSH).
 *
 * wasm-bindgen hands back a view into linear memory, so `byteOffset` is
 * routinely non-zero: the DataView must be constructed over the view's
 * own window, never `packed.buffer` alone.
 */
export function unpackMetaBlob<M>(packed: Uint8Array): MetaBlob<M> {
  requireLength(packed, 4, "[u32_le json_len][json][blob]");
  const view = new DataView(
    packed.buffer,
    packed.byteOffset,
    packed.byteLength,
  );
  const jsonLen = view.getUint32(0, true);
  // A length prefix that runs past the end of the buffer means the blob
  // was truncated (or is not one of ours) — the JSON parse below would
  // otherwise fail with a message about the metadata rather than the
  // format.
  if (4 + jsonLen > packed.length) {
    throw new Error(
      `Malformed protected blob: metadata length ${jsonLen} exceeds the ${packed.length}-byte payload`,
    );
  }
  const json = new TextDecoder().decode(packed.slice(4, 4 + jsonLen));
  return { meta: JSON.parse(json) as M, blob: packed.slice(4 + jsonLen) };
}
