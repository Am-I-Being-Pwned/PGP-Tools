/**
 * TypeScript wrapper for the Sequoia-PGP WASM module.
 *
 * All crypto operations run in WASM linear memory. Private keys
 * can be stored via handles that never expose key material to JS.
 */

import type { GeneratedKey, GenerateKeyOptions, KeyInfo } from "./types";

// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- dynamic import
type WasmModule = typeof import("../../gpg-wasm/pkg/gpg_wasm");

let wasmModule: WasmModule | null = null;
let initPromise: Promise<WasmModule> | null = null;

async function loadWasm(): Promise<WasmModule> {
  if (wasmModule) return wasmModule;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    const mod = await import("../../gpg-wasm/pkg/gpg_wasm");
    // Fetch WASM binary from extension's public assets and init synchronously
    const wasmUrl = chrome.runtime.getURL("gpg_wasm_bg.wasm");
    const wasmBytes = await fetch(wasmUrl).then((r) => r.arrayBuffer());
    mod.initSync({ module: wasmBytes });
    wasmModule = mod;
    return mod;
  })();

  return initPromise;
}

/** Ensure WASM is loaded. Call once at startup. */
export async function initPgpWasm(): Promise<void> {
  await loadWasm();
}

/** Smoke test - returns "gpg-wasm ok" if WASM is loaded. */
export async function ping(): Promise<string> {
  const wasm = await loadWasm();
  return wasm.ping();
}

/** Parse an armored key and return metadata. */
export async function parseKey(armored: string): Promise<KeyInfo> {
  const wasm = await loadWasm();
  const json = wasm.parseKey(armored);
  return JSON.parse(json) as KeyInfo;
}

/** Generate a new OpenPGP key pair. */
export async function generateKey(
  opts: GenerateKeyOptions,
): Promise<GeneratedKey> {
  const wasm = await loadWasm();
  const json = wasm.generateKey(JSON.stringify(opts));
  return JSON.parse(json) as GeneratedKey;
}

/** Encrypt data to one or more recipients (no signing). */
export async function encrypt(
  plaintext: Uint8Array,
  recipientPublicKeys: string[],
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.encrypt(plaintext, JSON.stringify(recipientPublicKeys), null);
}

export interface SignatureInfo {
  signatureValid: boolean | null;
  signerKeyId: string | null;
}

export interface VerifyResultWasm {
  text: string;
  signatureValid: boolean;
  signerKeyId: string | null;
}

/** Verify a cleartext-signed message. */
export async function verify(
  signedMessage: string,
  verificationPublicKeys: string[],
): Promise<VerifyResultWasm> {
  const wasm = await loadWasm();
  const json = wasm.verify(
    signedMessage,
    JSON.stringify(verificationPublicKeys),
  );
  return JSON.parse(json) as VerifyResultWasm;
}

/** Get the armored private key from a handle (for unprotected export). */
export async function getKeyArmored(handle: number): Promise<string> {
  const wasm = await loadWasm();
  return wasm.getKeyArmored(handle);
}

/** Encrypt with signing via a stored key handle. */
export async function encryptWithSigningHandle(
  plaintext: Uint8Array,
  recipientPublicKeys: string[],
  signingKeyHandle: number,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.encryptWithSigningHandle(
    plaintext,
    JSON.stringify(recipientPublicKeys),
    signingKeyHandle,
  );
}

/** Encrypt key for export via handle (key never leaves WASM as plaintext). */
export async function encryptKeyForExportWithHandle(
  keyHandle: number,
  passphrase: string,
): Promise<string> {
  const wasm = await loadWasm();
  return wasm.encryptKeyForExportWithHandle(keyHandle, passphrase);
}

// ── Argon2id KDF ────────────────────────────────────────────────────

/** Derive a 32-byte key from a password using Argon2id (runs in WASM). */
export async function argon2Derive(
  password: Uint8Array,
  salt: Uint8Array,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  const result = wasm.argon2Derive(
    password,
    salt,
    memoryKib,
    iterations,
    parallelism,
  );
  return new Uint8Array(result);
}

// ── Unlock-and-store (private key never enters JS) ──────────────────

/** Unlock a password-protected key entirely in WASM. Returns a key handle. */
export async function unlockWithPassword(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  salt: Uint8Array,
  keyId: string,
  password: Uint8Array,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<number> {
  const wasm = await loadWasm();
  return wasm.unlockWithPassword(
    ciphertext,
    iv,
    salt,
    keyId,
    password,
    memoryKib,
    iterations,
    parallelism,
  );
}

/** Unlock a passkey-protected key entirely in WASM. Returns a key handle. */
export async function unlockWithPrf(
  ciphertext: Uint8Array,
  iv: Uint8Array,
  prfOutput: Uint8Array,
  storedSecret: Uint8Array,
  keyId: string,
): Promise<number> {
  const wasm = await loadWasm();
  return wasm.unlockWithPrf(ciphertext, iv, prfOutput, storedSecret, keyId);
}

/** Extract the public key from a private key. */
export async function extractPublicKey(
  armoredPrivateKey: string,
): Promise<string> {
  const wasm = await loadWasm();
  return wasm.extractPublicKey(armoredPrivateKey);
}

// ── Key Handle API (private keys stay in WASM memory) ───────────────

/** Store a private key in WASM memory. Returns an opaque handle. */
export async function storeKey(armoredPrivateKey: string): Promise<number> {
  const wasm = await loadWasm();
  return wasm.storeKey(armoredPrivateKey);
}

/** Drop a key from WASM memory. */
export async function dropKey(handle: number): Promise<void> {
  const wasm = await loadWasm();
  wasm.dropKey(handle);
}

export interface DecryptWithHandleResult {
  plaintext: Uint8Array;
  signatureInfo: SignatureInfo;
}

/** Decrypt using a stored key handle. Returns plaintext + signature info in one call. */
export async function decryptWithHandle(
  ciphertext: Uint8Array,
  keyHandle: number,
  verificationPublicKeys?: string[],
): Promise<DecryptWithHandleResult> {
  const wasm = await loadWasm();
  const packed = wasm.decryptWithHandle(
    ciphertext,
    keyHandle,
    verificationPublicKeys ? JSON.stringify(verificationPublicKeys) : null,
  );

  // Unpack: [4 bytes sig_json length (LE u32)][sig_json][plaintext]
  const view = new DataView(
    packed.buffer,
    packed.byteOffset,
    packed.byteLength,
  );
  const sigLen = view.getUint32(0, true);
  const sigJson = new TextDecoder().decode(packed.slice(4, 4 + sigLen));
  const plaintext = packed.slice(4 + sigLen);
  const signatureInfo = JSON.parse(sigJson) as SignatureInfo;

  return { plaintext, signatureInfo };
}

/** Sign using a stored key handle. */
export async function signWithHandle(
  text: string,
  keyHandle: number,
): Promise<string> {
  const wasm = await loadWasm();
  return wasm.signWithHandle(text, keyHandle);
}
