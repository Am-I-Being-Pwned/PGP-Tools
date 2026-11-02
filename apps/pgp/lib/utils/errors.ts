import { EngineError } from "../errors/engine-error";

/** Human-readable message from a caught value. wasm-bindgen surfaces
 *  Rust `Err(String)` as a thrown JS *string* (an `EngineError` once a
 *  code is decoded), so an `instanceof Error` check alone silently
 *  discards every message the WASM layer writes for the user. */
export function errorMessage(e: unknown, fallback: string): string {
  if (e instanceof Error || e instanceof EngineError) return e.message;
  if (typeof e === "string" && e.trim()) return e;
  return fallback;
}
