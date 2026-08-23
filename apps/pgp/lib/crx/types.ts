import type {
  KeyProtection,
  PasskeyProtection,
  PasswordProtection,
} from "../protection/protected-blob";
import { fromBase64 } from "../encoding";

/**
 * Wire-format for a stored CRX (Chrome extension) signing key.
 *
 * Structurally a sibling of `ProtectedKeyBlob` (see `storage/keyring.ts`):
 * the RSA-2048 private key is encrypted at rest exactly like a PGP key
 * (Argon2id or PRF -> AES-256-GCM), AAD-bound via
 * `gpg-tools:crx-{password,passkey}:{extensionId}`. Only the public half
 * (`publicKeyDerB64`) and the derived `extensionId` are stored in clear.
 */

/**
 * How the private half is sealed at rest. Structurally identical to the
 * keyring's, because it IS the same seal — so it is the same union,
 * defined once in `protection/protected-blob.ts`. These aliases stay so
 * CRX call sites keep reading in CRX terms.
 */
export type CrxPasswordProtection = PasswordProtection;
export type CrxPasskeyProtection = PasskeyProtection;
export type CrxProtection = KeyProtection;

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

/**
 * Compute the extension id implied by a SubjectPublicKeyInfo DER (base64):
 * first 16 bytes of SHA-256 over the DER, each nibble mapped to `a`..`p` —
 * exactly how Chrome derives an extension's identity and how the WASM side
 * stamps `extensionId` at generate/import time.
 *
 * `publicKeyDerB64` is NOT covered by the blob's AEAD (only `extensionId`
 * is AAD-bound), so anything accepting a blob from outside — backup import,
 * storage writes — must check the two agree before trusting the public key.
 */
export async function extensionIdFromPublicKeyDer(
  derB64: string,
): Promise<string> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", fromBase64(derB64)),
  );
  let id = "";
  for (const byte of digest.subarray(0, 16)) {
    id +=
      String.fromCharCode(97 + (byte >> 4)) +
      String.fromCharCode(97 + (byte & 0x0f));
  }
  return id;
}

/** True iff the blob's stored public key actually hashes to its claimed
 *  extension id. Reject blobs that fail this before storing them. */
export async function crxBlobIdentityMatches(
  blob: CrxSigningKeyBlob,
): Promise<boolean> {
  try {
    return (
      (await extensionIdFromPublicKeyDer(blob.publicKeyDerB64)) ===
      blob.extensionId
    );
  } catch {
    return false; // unparseable base64 -> not a valid blob
  }
}

/** Render a SubjectPublicKeyInfo DER (base64) as a PEM block for pasting
 *  into the Chrome Web Store "Verified CRX Uploads" dashboard. */
export function publicKeyDerToPem(derB64: string): string {
  const lines = derB64.match(/.{1,64}/g) ?? [derB64];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}
