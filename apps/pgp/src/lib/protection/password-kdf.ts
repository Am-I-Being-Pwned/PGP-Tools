/**
 * Argon2id parameters. Changing these breaks every existing protected
 * blob.
 */
export const ARGON2_MEMORY_KIB = 65536; // 64 MB
export const ARGON2_ITERATIONS = 3;
export const ARGON2_PARALLELISM = 1; // WASM is single-threaded

export function generateSalt(): ArrayBuffer {
  return crypto.getRandomValues(new Uint8Array(16)).buffer;
}
