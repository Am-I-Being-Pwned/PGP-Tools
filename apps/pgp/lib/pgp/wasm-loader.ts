/**
 * WASM module loader. Internal to the `lib/pgp/wasm-*` modules.
 *
 * Loads `gpg_wasm_bg.wasm` from the extension's own bundle exactly
 * once. The resulting module handle is shared by every wasm-public /
 * wasm-secrets call. No secrets cross this file -- it's a singleton
 * that hands out the wasm-bindgen module reference.
 */

// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- dynamic import
export type WasmModule = typeof import("../../gpg-wasm/pkg/gpg_wasm");

let wasmModule: WasmModule | null = null;
let initPromise: Promise<WasmModule> | null = null;
let wasmMemory: WebAssembly.Memory | null = null;

export async function loadWasm(): Promise<WasmModule> {
  if (wasmModule) return wasmModule;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    const mod = await import("../../gpg-wasm/pkg/gpg_wasm");
    // Same-origin chrome-extension:// fetch: loads the WASM blob from
    // the extension's own bundle. This is the only outbound fetch the
    // wasm subsystem ever makes.
    const wasmUrl = chrome.runtime.getURL("gpg_wasm_bg.wasm");
    const wasmBytes = await fetch(wasmUrl).then((r) => r.arrayBuffer());
    const output = mod.initSync({ module: wasmBytes });
    wasmMemory = output.memory;
    wasmModule = mod;
    return mod;
  })();

  return initPromise;
}

/**
 * DEV-ONLY: snapshot the wasm linear memory as raw bytes.
 *
 * This deliberately breaches the "no secrets cross this file" rule: raw
 * memory can contain decrypted private keys. It exists solely as a
 * debugging aid (e.g. verifying zeroization) and is gated behind
 * `import.meta.env.DEV` -- the runtime guard returns null in any
 * production build, and the whole branch is tree-shaken out. Returns
 * null if the module hasn't been initialised yet.
 */
export function dumpWasmMemoryForDev(): Uint8Array | null {
  if (!import.meta.env.DEV) return null;
  if (!wasmMemory) return null;
  // .slice() copies out of live memory into a detached buffer.
  return new Uint8Array(wasmMemory.buffer).slice();
}

export async function initPgpWasm(): Promise<void> {
  await loadWasm();
}
