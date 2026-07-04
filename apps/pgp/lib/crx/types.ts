/**
 * Wire-format for a stored CRX (Chrome extension) signing key.
 *
 * Structurally a sibling of `ProtectedKeyBlob` (see `storage/keyring.ts`):
 * the RSA-2048 private key is encrypted at rest exactly like a PGP key
 * (Argon2id or PRF -> AES-256-GCM), AAD-bound via
 * `gpg-tools:crx-{password,passkey}:{extensionId}`. Only the public half
 * (`publicKeyDerB64`) and the derived `extensionId` are stored in clear.
 */

/** Shared protection discriminated union — mirrors the keyring's. */
export interface CrxPasswordProtection {
  method: "password";
  kdfSalt: string; // base64 (Argon2id salt)
}

export interface CrxPasskeyProtection {
  method: "passkey";
  credentialId: string; // base64url
  prfSalt: string; // base64
  storedSecret: string; // base64 (HKDF salt; not itself secret)
}

export type CrxProtection = CrxPasswordProtection | CrxPasskeyProtection;

export interface CrxSigningKeyBlob {
  version: 1;
  /** 32-char `a`..`p` Chrome extension id derived from the public key.
   *  Doubles as the stable identity used for AAD binding. */
  extensionId: string;
  /** Optional user-facing label ("My Extension"). */
  label?: string;
  /** SubjectPublicKeyInfo DER, base64 — what the CWS dashboard wants
   *  (as PEM) to register the key. */
  publicKeyDerB64: string;
  /** Signing algorithm; currently always `rsa2048`. */
  algorithm: string;
  protection: CrxProtection;
  encryptedPrivateKey: string; // base64 ciphertext (PKCS#8 DER)
  iv: string; // base64
  createdAt: number;
  lastUsedAt: number;
}

export function isCrxSigningKeyBlob(v: unknown): v is CrxSigningKeyBlob {
  if (typeof v !== "object" || v === null) return false;
  const o = v as Record<string, unknown>;
  return (
    typeof o.extensionId === "string" &&
    typeof o.publicKeyDerB64 === "string" &&
    typeof o.encryptedPrivateKey === "string" &&
    typeof o.iv === "string" &&
    typeof o.protection === "object" &&
    o.protection !== null &&
    typeof (o.protection as Record<string, unknown>).method === "string"
  );
}

/** Render a SubjectPublicKeyInfo DER (base64) as a PEM block for pasting
 *  into the Chrome Web Store "Verified CRX Uploads" dashboard. */
export function publicKeyDerToPem(derB64: string): string {
  const lines = derB64.match(/.{1,64}/g) ?? [derB64];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}
