import { argon2Derive } from "../pgp/wasm";

export const ARGON2_MEMORY_KIB = 65536; // 64 MB
export const ARGON2_ITERATIONS = 3;
export const ARGON2_PARALLELISM = 1; // WASM is single-threaded

/** Derive an AES-256-GCM key from a password using Argon2id (WASM). */
export async function deriveKeyFromPassword(
  password: string,
  salt: ArrayBuffer,
): Promise<CryptoKey> {
  const passwordBytes = new TextEncoder().encode(password);
  const derived = await argon2Derive(
    passwordBytes,
    new Uint8Array(salt),
    ARGON2_MEMORY_KIB,
    ARGON2_ITERATIONS,
    ARGON2_PARALLELISM,
  );

  const key = await crypto.subtle.importKey(
    "raw",
    derived.slice().buffer,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  // Zero sensitive material from JS heap
  derived.fill(0);
  passwordBytes.fill(0);

  return key;
}

/** Generate a random 16-byte salt. */
export function generateSalt(): ArrayBuffer {
  return crypto.getRandomValues(new Uint8Array(16)).buffer;
}
