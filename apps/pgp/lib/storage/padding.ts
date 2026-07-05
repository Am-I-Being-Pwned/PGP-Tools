/**
 * Length-hiding padding for encrypted store blobs.
 *
 * AES-GCM ciphertext length == plaintext length + 16, so an unpadded
 * blob's size tracks the item count almost exactly -- someone with disk
 * access to the profile can watch the keyring grow key-by-key over time.
 * Padding the plaintext up to a coarse bucket quantises the ciphertext
 * size, so the stored blob reveals only which bucket you're in, not the
 * exact count or small changes.
 *
 * Format: `[json-utf8][0x00][0x00 padding...]`. `JSON.stringify` escapes
 * a NUL character to an escape sequence, so a raw 0x00 never
 * appears inside the JSON bytes -- it's an unambiguous end-of-data delimiter. Unpadding finds the first
 * NUL and slices before it; a legacy blob (pure JSON, no NUL) reads
 * whole, which is exactly the value we want, so this is fully
 * backward-compatible.
 */

/** Smallest bucket (bytes). Small stores still pad up to here. */
const MIN_BUCKET = 2048;

/** Next power-of-two bucket >= n (>= MIN_BUCKET). Exponential buckets
 *  mean transitions get rarer as the store grows. */
export function bucketFor(n: number): number {
  let bucket = MIN_BUCKET;
  while (bucket < n) bucket *= 2;
  return bucket;
}

/**
 * Pad `json` (already UTF-8 encoded) to a bucket when `pad` is true.
 * `pad` is false on `sync` storage, whose 8 KB/item cap can't absorb the
 * padding -- there the plaintext is returned unchanged (no delimiter).
 */
export function padPlaintext(json: Uint8Array, pad: boolean): Uint8Array {
  if (!pad) return json;
  // +1 for the NUL delimiter that separates data from padding.
  const target = bucketFor(json.length + 1);
  const out = new Uint8Array(target); // zero-filled: delimiter + padding are already 0
  out.set(json, 0);
  return out;
}

/** Strip padding: return the JSON bytes before the first NUL delimiter.
 *  A blob with no NUL (legacy, or unpadded sync) is returned whole. */
export function unpadPlaintext(plaintext: Uint8Array): Uint8Array {
  const nul = plaintext.indexOf(0);
  return nul === -1 ? plaintext : plaintext.subarray(0, nul);
}
