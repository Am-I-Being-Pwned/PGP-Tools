export interface KeyInfo {
  keyId: string; // Fingerprint (hex)
  userIds: string[]; // "Name <email>" strings
  algorithm: string; // e.g. "ed25519", "rsa4096"
  createdAt: number; // Unix timestamp
  expiresAt: number | null;
  isPrivate: boolean;
  /** Sequoia StandardPolicy accepts ≥1 alive, non-revoked encryption key. */
  usableForEncryption: boolean;
  /** Sequoia StandardPolicy accepts ≥1 alive, non-revoked signing key. */
  usableForSigning: boolean;
  /** Human-readable rejection reason (e.g. SHA-1 self-sig, expired). */
  policyError?: string;
  /** Non-blocking flag: the key is usable, but only because the hardened
   *  policy was relaxed to accept it (e.g. it relies on a SHA-1 binding
   *  signature). Surface to the user; do not block the import. */
  securityWarning?: string;
}

/** One row in the per-key breakdown of a certificate: the primary key
 *  or one subkey, with its capability flags and lifecycle status.
 *  "invalid" means the binding signature fails policy (see policyError);
 *  capability flags are then unknown and reported as all-false. */
export interface SubkeyDetail {
  fingerprint: string;
  /** Short (64-bit) key ID, the form most other tools print. */
  keyId: string;
  algorithm: string;
  /** Public-key size in bits, when the algorithm has a meaningful one. */
  bits?: number;
  createdAt: number;
  expiresAt: number | null;
  isPrimary: boolean;
  canSign: boolean;
  canEncrypt: boolean;
  canCertify: boolean;
  canAuthenticate: boolean;
  status: "active" | "expired" | "revoked" | "invalid";
  revocationReason?: string;
  policyError?: string;
}

/** Result of `parseKeyDetails`: primary key first, in cert order.
 *  `truncated` is set when the cert carried more component keys than
 *  the wasm-side row cap (only plausible for crafted certs). */
export interface KeyDetails {
  keys: SubkeyDetail[];
  truncated: boolean;
}

// Discriminated union for encrypt input
export type EncryptInput =
  | { kind: "text"; text: string }
  | { kind: "binary"; binary: Uint8Array; armor?: boolean };

export interface EncryptOptions {
  input: EncryptInput;
  recipientPublicKeys: string[];
}

// Discriminated union for decrypt input
export type DecryptInput =
  | { kind: "armored"; armoredMessage: string }
  | { kind: "binary"; binaryMessage: Uint8Array };

export interface DecryptOptions {
  input: DecryptInput;
  verificationPublicKeys?: string[];
}

export interface VerifyOptions {
  signedMessage: string;
  verificationPublicKeys: string[];
}

/**
 * Signature outcome, decoupled from decryption success:
 *   "valid"       - signature cryptographically verified
 *   "invalid"     - had the signer key but verification failed (possible tamper)
 *   "unknown_key" - signed, but we don't hold the signer's public key
 *   "unsigned"    - no signature present
 */
export type SignatureStatus = "unsigned" | "valid" | "invalid" | "unknown_key";

export interface DecryptResult {
  data: string | Uint8Array;
  signatureValid: boolean | null;
  signatureStatus: SignatureStatus;
  signerKeyId: string | null;
}

export interface VerifyResult {
  text: string;
  signatureValid: boolean;
  signatureStatus: SignatureStatus;
  signerKeyId: string | null;
}

export interface GenerateKeyOptions {
  name: string;
  email: string;
  comment?: string;
  type?: "ecc" | "rsa";
  expiresIn?: number;
}

/** Metadata returned from a protect-flow call (generate or import + protect).
 *  The encrypted blob lives on the wasm-side packed binary and is unpacked
 *  separately by the protect-flow wrapper. */
export interface ProtectResultMeta {
  publicKeyArmored: string;
  keyInfo: KeyInfo;
  revocationCertificate?: string;
}
