/** Human-readable message from a caught value. wasm-bindgen surfaces
 *  Rust `Err(String)` as a thrown JS *string* (not an `Error`), so an
 *  `instanceof Error` check alone silently discards every message the
 *  WASM layer writes for the user (e.g. "Incorrect passphrase"). */
export function errorMessage(e: unknown, fallback: string): string {
  if (e instanceof Error) return e.message;
  if (typeof e === "string" && e.trim()) return e;
  return fallback;
}
