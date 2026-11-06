/**
 * WASM loader singleton, internal to `lib/pgp/wasm-*`. No secrets cross
 * this file; exports are wrapped by `withEngineErrors` (only thrown error
 * strings are decoded).
 */

import { withEngineErrors } from "~/lib/errors/engine-error";

// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- dynamic import
export type WasmModule = typeof import("../../../gpg-wasm/pkg/gpg_wasm");

let wasmModule: WasmModule | null = null;
let initPromise: Promise<WasmModule> | null = null;
let wasmMemory: WebAssembly.Memory | null = null;

export async function loadWasm(): Promise<WasmModule> {
  if (wasmModule) return wasmModule;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    const mod = await import("../../../gpg-wasm/pkg/gpg_wasm");
    // Same-origin bundle fetch, the wasm subsystem's only one. This
    // `new URL` form shares ONE hashed asset with the glue's reference.
    const wasmUrl = new URL(
      "../../../gpg-wasm/pkg/gpg_wasm_bg.wasm",
      import.meta.url,
    );
    const wasmBytes = await fetch(wasmUrl).then((r) => r.arrayBuffer());
    const output = mod.initSync({ module: wasmBytes });
    wasmMemory = output.memory;
    wasmModule = withEngineErrors(mod);
    return wasmModule;
  })();

  return initPromise;
}

/**
 * DEV-ONLY raw linear-memory snapshot (zeroization debugging). Deliberately
 * breaches "no secrets cross this file"; `import.meta.env.DEV`-gated and
 * tree-shaken from production.
 */
export function dumpWasmMemoryForDev(): Uint8Array | null {
  if (!import.meta.env.DEV) return null;
  if (!wasmMemory) return null;
  return new Uint8Array(wasmMemory.buffer).slice();
}
