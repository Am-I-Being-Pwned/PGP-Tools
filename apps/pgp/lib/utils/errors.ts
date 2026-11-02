import { EngineError } from "~/lib/errors/engine-error";

/** wasm throws strings / `EngineError`s, not `Error`s, so an `instanceof
 *  Error` check alone would drop every engine message. */
export function errorMessage(e: unknown, fallback: string): string {
  if (e instanceof Error || e instanceof EngineError) return e.message;
  if (typeof e === "string" && e.trim()) return e;
  return fallback;
}
