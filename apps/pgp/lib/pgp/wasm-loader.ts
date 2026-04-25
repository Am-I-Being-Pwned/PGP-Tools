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
    mod.initSync({ module: wasmBytes });
    wasmModule = mod;
    return mod;
  })();

  return initPromise;
}

export async function initPgpWasm(): Promise<void> {
  await loadWasm();
}
