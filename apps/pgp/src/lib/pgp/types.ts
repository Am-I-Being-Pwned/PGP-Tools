export interface KeyInfo {
  keyId: string; // Fingerprint (hex)
  userIds: string[];
  algorithm: string;
  createdAt: number;
  expiresAt: number | null;
  isPrivate: boolean;
  /** Sequoia StandardPolicy accepts ≥1 alive, non-revoked encryption key. */
  usableForEncryption: boolean;
  /** Sequoia StandardPolicy accepts ≥1 alive, non-revoked signing key. */
  usableForSigning: boolean;
  /** Human-readable rejection reason (e.g. SHA-1 self-sig, expired). */
  policyError?: string;
  /** Usable only because the hardened policy was relaxed (e.g. SHA-1
   *  binding sig). Surface it; do not block the import. */
  securityWarning?: string;
  /** The owner revoked the whole cert. Kept as a contact so the
   *  revocation sticks, but never encrypted to. */
  revoked?: boolean;
  /** A User ID mixes lookalike alphabets; `securityWarning` explains. */
  lookalike?: boolean;
}

/** "invalid" = binding sig fails policy; capability flags are then all-false. */
export interface SubkeyDetail {
  fingerprint: string;
  /** Short (64-bit) key ID. */
  keyId: string;
  algorithm: string;
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

/** `truncated`: more component keys than the wasm row cap (crafted certs). */
export interface KeyDetails {
  keys: SubkeyDetail[];
  truncated: boolean;
}

export type EncryptInput =
  | { kind: "text"; text: string }
  | { kind: "binary"; binary: Uint8Array; armor?: boolean };

export interface EncryptOptions {
  input: EncryptInput;
  recipientPublicKeys: string[];
}

export type DecryptInput =
  | { kind: "armored"; armoredMessage: string }
  | { kind: "binary"; binaryMessage: Uint8Array };

export interface DecryptOptions {
  input: DecryptInput;
  verificationPublicKeys?: string[];
  /** UNATTENDED runs only: past this many bytes the call throws
   *  `OutputCapReached`. Omit for runs a person started. */
  maxOutputBytes?: number;
}

export interface VerifyOptions {
  signedMessage: string;
  verificationPublicKeys: string[];
  /** See `DecryptOptions.maxOutputBytes`. */
  maxOutputBytes?: number;
}

/** Decoupled from decryption success. "invalid" = had the signer key but
 *  verification failed (possible tamper). */
export type SignatureStatus = "unsigned" | "valid" | "invalid" | "unknown_key";

/** Filled for "valid"; neutral otherwise. */
export interface SignatureDetails {
  /** Signer-chosen (ms): shown, never trusted. */
  signedAt: number | null;
  /** Signing key still alive and unrevoked today. */
  signerKeyCurrent: boolean;
  otherSignerKeyIds: string[];
  /** Signatures from keys we don't hold, next to a good one. */
  unverifiedSignatures: number;
  /** Fingerprints the good signature says it was made FOR. */
  intendedRecipients: string[];
}

export interface DecryptResult extends SignatureDetails {
  data: string | Uint8Array;
  signatureValid: boolean | null;
  signatureStatus: SignatureStatus;
  signerKeyId: string | null;
}

export interface VerifyResult extends SignatureDetails {
  text: string;
  signatureValid: boolean;
  signatureStatus: SignatureStatus;
  signerKeyId: string | null;
}

export interface GenerateKeyOptions {
  name: string;
  /** Omit for a UID with no address (`Name` or `Name (comment)`). */
  email?: string;
  comment?: string;
  type?: "ecc" | "rsa";
  expiresIn?: number;
}

export interface ProtectResultMeta {
  publicKeyArmored: string;
  keyInfo: KeyInfo;
  revocationCertificate?: string;
}
