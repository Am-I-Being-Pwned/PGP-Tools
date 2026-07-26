/**
 * TEST-ONLY test double for the wasm sealing primitives behind
 * `envelope.ts`. Imported exclusively from `*.test.ts`, so it is
 * tree-shaken out of the extension bundle.
 *
 * It exists as one shared module rather than a copy per test file
 * because the property under test is the *binding*, and a fake that
 * drifted between test files could easily "pass" a domain-separation
 * test that the real primitives would fail. The contract it models:
 *
 *  - `encryptStore(domain, pt)` -> `[12-byte IV][header(domain)][pt]`
 *  - `decryptStore(domain, ct)` succeeds only when the header names the
 *    SAME domain -- otherwise it throws, standing in for a failed AEAD
 *    tag check.
 *  - the legacy shared envelope is the identity transform (matching what
 *    the existing suites already used), and REJECTS anything carrying a
 *    domain header -- because a real AES-GCM open of a domain-sealed blob
 *    under the shared key and shared AAD fails its tag check too. Without
 *    that, a domain-mismatched blob would fall through the legacy path and
 *    "fail" for the wrong reason (a JSON parse error) instead of at the
 *    tag check, which is the property being asserted.
 */

import type { StoredEnvelope } from "./envelope";
import { fromBase64, toBase64 } from "../encoding";

/** Delimited by NULs, which `JSON.stringify` always escapes, so the
 *  header can never collide with the JSON these stores actually hold. */
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
    // Wrong domain, or a legacy blob: a tag check would fail here.
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

/** Whether a stored blob is sealed under the domain-bound scheme (as
 *  opposed to the legacy shared one). Used to assert that a read
 *  re-sealed, or that a write never emits the legacy format. */
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
