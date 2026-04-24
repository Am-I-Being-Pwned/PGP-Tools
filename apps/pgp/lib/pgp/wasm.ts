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

export async function initPgpWasm(): Promise<void> {
  await loadWasm();
}

export async function ping(): Promise<string> {
  const wasm = await loadWasm();
  return wasm.ping();
}

export async function parseKey(armored: string): Promise<KeyInfo> {
  const wasm = await loadWasm();
  const json = wasm.parseKey(armored);
  return JSON.parse(json) as KeyInfo;
}

export async function generateKey(
  opts: GenerateKeyOptions,
): Promise<GeneratedKey> {
  const wasm = await loadWasm();
  const json = wasm.generateKey(JSON.stringify(opts));
  return JSON.parse(json) as GeneratedKey;
}

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

export async function getKeyArmored(handle: number): Promise<string> {
  const wasm = await loadWasm();
  return wasm.getKeyArmored(handle);
}

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

export async function encryptKeyForExportWithHandle(
  keyHandle: number,
  passphrase: string,
): Promise<string> {
  const wasm = await loadWasm();
  return wasm.encryptKeyForExportWithHandle(keyHandle, passphrase);
}

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

export async function initContactsSessionWithPrf(
  prfOutput: Uint8Array,
  storedSecret: Uint8Array,
): Promise<void> {
  const wasm = await loadWasm();
  wasm.initContactsSessionWithPrf(prfOutput, storedSecret);
}

export async function dropContactsSession(): Promise<void> {
  const wasm = await loadWasm();
  wasm.dropContactsSession();
}

export async function hasContactsSession(): Promise<boolean> {
  const wasm = await loadWasm();
  return wasm.hasContactsSession();
}

export async function encryptContacts(
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.encryptContacts(plaintext);
}

export async function decryptContacts(
  ciphertext: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.decryptContacts(ciphertext, iv);
}

/**
 * Encrypt a canary and init the contacts session in one Argon2id pass.
 * Used during onboarding password setup.
 * Returns `[12-byte IV][ciphertext]`.
 */
export async function encryptCanaryAndInitSession(
  password: Uint8Array,
  salt: Uint8Array,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.encryptCanaryAndInitSession(
    password,
    salt,
    memoryKib,
    iterations,
    parallelism,
  );
}

/**
 * Verify a password and init the contacts session in one Argon2id pass.
 * Returns true if correct (session is now active), false if wrong.
 */
export async function verifyCanaryAndInitSession(
  canaryCiphertext: Uint8Array,
  canaryIv: Uint8Array,
  password: Uint8Array,
  salt: Uint8Array,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<boolean> {
  const wasm = await loadWasm();
  return wasm.verifyCanaryAndInitSession(
    canaryCiphertext,
    canaryIv,
    password,
    salt,
    memoryKib,
    iterations,
    parallelism,
  );
}

export async function extractPublicKey(
  armoredPrivateKey: string,
): Promise<string> {
  const wasm = await loadWasm();
  return wasm.extractPublicKey(armoredPrivateKey);
}

export async function isSecretEncrypted(armored: string): Promise<boolean> {
  const wasm = await loadWasm();
  return wasm.isSecretEncrypted(armored);
}

/**
 * Decrypt an imported passphrase-protected key inside WASM and store it
 * behind a handle. Caller must zero `passphrase` after this returns.
 */
export async function decryptAndStoreImportedKey(
  armored: string,
  passphrase: Uint8Array,
): Promise<number> {
  const wasm = await loadWasm();
  return wasm.decryptAndStoreImportedKey(armored, passphrase);
}

/**
 * Re-encrypt a stored cert (by handle) under a password, entirely in WASM.
 * Returns packed `[16-byte salt][12-byte iv][ciphertext]`.
 * Caller must zero `password`.
 */
export async function encryptHandleWithPassword(
  handle: number,
  password: Uint8Array,
  keyId: string,
  memoryKib: number,
  iterations: number,
  parallelism: number,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.encryptHandleWithPassword(
    handle,
    password,
    keyId,
    memoryKib,
    iterations,
    parallelism,
  );
}

/**
 * Re-encrypt a stored cert (by handle) under a passkey-derived key
 * (HKDF over PRF output + stored secret), entirely in WASM.
 * Returns packed `[12-byte iv][ciphertext]`.
 * Caller must zero `prfOutput` and `storedSecret`.
 */
export async function encryptHandleWithPrf(
  handle: number,
  prfOutput: Uint8Array,
  storedSecret: Uint8Array,
  keyId: string,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.encryptHandleWithPrf(handle, prfOutput, storedSecret, keyId);
}

export async function storeKey(armoredPrivateKey: string): Promise<number> {
  const wasm = await loadWasm();
  return wasm.storeKey(armoredPrivateKey);
}

export async function dropKey(handle: number): Promise<void> {
  const wasm = await loadWasm();
  wasm.dropKey(handle);
}

export interface DecryptWithHandleResult {
  plaintext: Uint8Array;
  signatureInfo: SignatureInfo;
}

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

export async function signWithHandle(
  text: string,
  keyHandle: number,
): Promise<string> {
  const wasm = await loadWasm();
  return wasm.signWithHandle(text, keyHandle);
}
