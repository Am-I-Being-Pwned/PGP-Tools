/**
 * TEST-ONLY double for the wasm sealing primitives behind `envelope.ts`
 * (shared so the binding can't drift between suites):
 *
 *  - `encryptStore(domain, pt)` -> `[12-byte IV][header(domain)][pt]`
 *  - `decryptStore` throws unless the header names the SAME domain
 *    (standing in for a failed AEAD tag check).
 *  - the legacy envelope is the identity transform and REJECTS any
 *    domain-headed blob, as a real legacy AES-GCM open would, so a
 *    mismatch fails at the tag check rather than a JSON parse.
 */

import { fromBase64, toBase64 } from "~/lib/encoding";
import type { StoredEnvelope } from "./envelope";

/** NUL-delimited: JSON.stringify always escapes NUL, so no collision. */
const MAGIC = "\u0000gpg-store-v1\u0000";

function header(domain: string): Uint8Array {
  return new TextEncoder().encode(`${MAGIC}${domain}\u0000`);
}

function startsWith(buf: Uint8Array, prefix: Uint8Array): boolean {
  if (buf.length < prefix.length) return false;
  return prefix.every((b, i) => buf[i] === b);
}

const MAGIC_BYTES = new TextEncoder().encode(MAGIC);

/** True iff these bytes were produced by {@link fakeEncryptStore}. */
export function isDomainSealedCiphertext(ciphertext: Uint8Array): boolean {
  return startsWith(ciphertext, MAGIC_BYTES);
}

// ── the primitives (drop-in for lib/pgp/wasm) ───────────────────────

export function fakeEncryptStore(
  domain: string,
  plaintext: Uint8Array,
): Uint8Array {
  if (domain === "") throw new Error("Store domain must not be empty");
  const head = header(domain);
  const packed = new Uint8Array(12 + head.length + plaintext.length);
  packed.set(head, 12);
  packed.set(plaintext, 12 + head.length);
  return packed;
}

export function fakeDecryptStore(
  domain: string,
  ciphertext: Uint8Array,
): Uint8Array {
  if (domain === "") throw new Error("Store domain must not be empty");
  const head = header(domain);
  if (!startsWith(ciphertext, head)) {
    throw new Error("Decryption failed");
  }
  return ciphertext.slice(head.length);
}

export function fakeEncryptContacts(plaintext: Uint8Array): Uint8Array {
  const packed = new Uint8Array(12 + plaintext.length);
  packed.set(plaintext, 12);
  return packed;
}

export function fakeDecryptContacts(ciphertext: Uint8Array): Uint8Array {
  if (isDomainSealedCiphertext(ciphertext)) {
    throw new Error("Decryption failed");
  }
  return new Uint8Array(ciphertext);
}

// ── envelope builders / inspectors for assertions ────────────────────

/** A stored blob exactly as a pre-domain-separation build wrote it. */
export function legacyEnvelope(plaintext: Uint8Array): StoredEnvelope {
  const packed = fakeEncryptContacts(plaintext);
  return {
    iv: toBase64(packed.slice(0, 12)),
    ciphertext: toBase64(packed.slice(12)),
  };
}

/** A stored blob as the current build writes it for `domain`. */
export function domainEnvelope(
  domain: string,
  plaintext: Uint8Array,
): StoredEnvelope {
  const packed = fakeEncryptStore(domain, plaintext);
  return {
    iv: toBase64(packed.slice(0, 12)),
    ciphertext: toBase64(packed.slice(12)),
  };
}

/** Whether a stored blob uses the domain-bound scheme. */
export function isDomainSealed(blob: unknown): boolean {
  if (typeof blob !== "object" || blob === null) return false;
  const ct = (blob as Record<string, unknown>).ciphertext;
  if (typeof ct !== "string") return false;
  return isDomainSealedCiphertext(fromBase64(ct));
}

/** The domain a stored blob is sealed for, or null if it is legacy. */
export function sealedDomain(blob: unknown): string | null {
  if (!isDomainSealed(blob)) return null;
  const ct = fromBase64((blob as StoredEnvelope).ciphertext);
  const text = new TextDecoder().decode(ct.slice(MAGIC_BYTES.length));
  return text.slice(0, text.indexOf("\u0000"));
}

/** The plaintext inside a stored blob, whichever scheme sealed it. */
export function storedPlaintext(blob: StoredEnvelope): Uint8Array {
  const ct = fromBase64(blob.ciphertext);
  const domain = sealedDomain(blob);
  return domain === null ? ct : fakeDecryptStore(domain, ct);
}

// ── module double ────────────────────────────────────────────────────

/** The store-sealing slice of `lib/pgp/wasm`, for a `vi.mock` factory.
 *  `hasSession` is read per call so a test can lock the vault mid-run. */
export function fakeStoreWasm(hasSession: () => boolean) {
  return {
    hasContactsSession: () => Promise.resolve(hasSession()),
    encryptStore: (domain: string, plaintext: Uint8Array) =>
      Promise.resolve(fakeEncryptStore(domain, plaintext)),
    decryptStore: (domain: string, ciphertext: Uint8Array) =>
      Promise.resolve(fakeDecryptStore(domain, ciphertext)),
    encryptContacts: (plaintext: Uint8Array) =>
      Promise.resolve(fakeEncryptContacts(plaintext)),
    decryptContacts: (ciphertext: Uint8Array) =>
      Promise.resolve(fakeDecryptContacts(ciphertext)),
  };
}
