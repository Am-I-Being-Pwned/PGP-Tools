import { fromBase64 } from "~/lib/encoding";
import type {
  KeyProtection,
  PasskeyProtection,
  PasswordProtection,
} from "~/lib/protection/protected-blob";

/**
 * Stored CRX signing key. Sealed like a PGP key, AAD-bound via
 * `gpg-tools:crx-{password,passkey}:{extensionId}`; only the public key
 * and `extensionId` are in the clear.
 */

/** The shared seal union from `protection/protected-blob.ts`. */
export type CrxPasswordProtection = PasswordProtection;
export type CrxPasskeyProtection = PasskeyProtection;
export type CrxProtection = KeyProtection;

export interface CrxSigningKeyBlob {
  version: 1;
  /** Chrome extension id derived from the public key; the AAD identity. */
  extensionId: string;
  label?: string;
  /** SubjectPublicKeyInfo DER, base64. */
  publicKeyDerB64: string;
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
 * Extension id from SPKI DER (base64), as Chrome derives it.
 *
 * `publicKeyDerB64` is NOT covered by the AEAD (only `extensionId` is
 * AAD-bound), so anything accepting a blob from outside must check the
 * two agree before trusting the public key.
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

/** Reject blobs whose public key doesn't hash to their extension id. */
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

/** SPKI DER (base64) as PEM, for the CWS "Verified CRX Uploads" page. */
export function publicKeyDerToPem(derB64: string): string {
  const lines = derB64.match(/.{1,64}/g) ?? [derB64];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join("\n")}\n-----END PUBLIC KEY-----\n`;
}
