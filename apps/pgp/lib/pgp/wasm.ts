/**
 * ============================================================================
 * Sequoia-PGP WASM module — JS-side surface.
 * ============================================================================
 *
 * This file is intentionally a barrel re-export. The wasm-side surface
 * is split in two so the trust boundary is visible from the file tree:
 *
 *   - `wasm-public.ts`   — calls that do NOT carry secret key material
 *                          across the wasm/JS boundary (parse, verify,
 *                          encrypt to recipients, sign-with-handle,
 *                          decrypt-with-handle, drop, etc).
 *
 *   - `wasm-secrets.ts`  — calls that DO carry secret material in
 *                          either direction. Each function has a
 *                          `@secret-handling` block stating its
 *                          zeroization contract.
 *
 *   - `wasm-loader.ts`   — module init singleton (no secrets).
 *
 * For the threat model, file map, and per-secret zeroization audit
 * table, see `apps/pgp/SECURITY.md`.
 *
 * Auditors: open the two files above. The split is the audit story.
 */

export * from "./wasm-loader";
export * from "./wasm-public";
export * from "./wasm-secrets";
