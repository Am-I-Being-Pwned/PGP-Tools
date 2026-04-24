/**
 * Argon2id parameters used everywhere a password is mixed with a salt.
 * Tuned for browser use: 64 MiB / 3 iterations / single-threaded (WASM).
 * Changing these is a breaking change for every existing protected blob;
 * the derive happens entirely in WASM (`argon2Derive`).
 */
export const ARGON2_MEMORY_KIB = 65536; // 64 MB
export const ARGON2_ITERATIONS = 3;
export const ARGON2_PARALLELISM = 1; // WASM is single-threaded

export function generateSalt(): ArrayBuffer {
  return crypto.getRandomValues(new Uint8Array(16)).buffer;
}
