/**
 * Length-hiding padding for encrypted store blobs: GCM ciphertext length
 * tracks the item count, so plaintext is padded to a coarse bucket.
 *
 * Format: `[json-utf8][0x00][0x00 padding...]`. JSON.stringify escapes NUL,
 * so the first raw 0x00 is an unambiguous delimiter; a legacy blob (no NUL)
 * reads whole.
 */

/** Smallest bucket (bytes). Small stores still pad up to here. */
const MIN_BUCKET = 2048;

/** Next power-of-two bucket >= n (>= MIN_BUCKET). */
export function bucketFor(n: number): number {
  let bucket = MIN_BUCKET;
  while (bucket < n) bucket *= 2;
  return bucket;
}

/** Pad `json` to a bucket when `pad` is true (false on `sync`, whose 8 KB
 *  cap can't absorb it; returned unchanged, no delimiter). */
export function padPlaintext(json: Uint8Array, pad: boolean): Uint8Array {
  if (!pad) return json;
  const target = bucketFor(json.length + 1);
  const out = new Uint8Array(target); // zero-filled: delimiter + padding are already 0
  out.set(json, 0);
  return out;
}

/** Strip padding; a blob with no NUL (legacy or sync) is returned whole. */
export function unpadPlaintext(plaintext: Uint8Array): Uint8Array {
  const nul = plaintext.indexOf(0);
  return nul === -1 ? plaintext : plaintext.subarray(0, nul);
}

/** True iff `stored` is already canonically padded for `pad`, so the
 *  one-time normalization can skip the write (idempotent, no churn). */
export function isCanonicalPadding(stored: Uint8Array, pad: boolean): boolean {
  return padPlaintext(unpadPlaintext(stored), pad).length === stored.length;
}
