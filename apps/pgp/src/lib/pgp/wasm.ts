/**
 * Barrel. The trust boundary is the file split: `wasm-public.ts` (no
 * secret material) vs `wasm-secrets.ts` (secret material, each with a
 * `@secret-handling` contract). See SECURITY.md.
 */

export * from "./wasm-loader";
export * from "./wasm-public";
export * from "./wasm-secrets";
