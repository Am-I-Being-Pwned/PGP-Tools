export interface KeyInfo {
  keyId: string; // Fingerprint (hex)
  userIds: string[]; // "Name <email>" strings
  algorithm: string; // e.g. "ed25519", "rsa4096"
  createdAt: number; // Unix timestamp
  expiresAt: number | null;
  isPrivate: boolean;
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

export interface DecryptResult {
  data: string | Uint8Array;
  signatureValid: boolean | null;
  signerKeyId: string | null;
}

export interface VerifyResult {
  text: string;
  signatureValid: boolean;
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
