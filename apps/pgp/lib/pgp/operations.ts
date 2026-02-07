import type {
  DecryptOptions,
  DecryptResult,
  EncryptInput,
  EncryptOptions,
  VerifyOptions,
  VerifyResult,
} from "./types";
import * as wasm from "./wasm";

function resolveInput(input: EncryptInput): Uint8Array {
  return input.kind === "binary"
    ? input.binary
    : new TextEncoder().encode(input.text);
}

function formatOutput(
  input: EncryptInput,
  raw: Uint8Array,
): string | Uint8Array {
  if (input.kind === "text") return new TextDecoder().decode(raw);
  if (input.armor) return new TextDecoder().decode(raw);
  return raw;
}

/** Encrypt to one or more recipients (no signing). */
export async function encrypt(
  opts: EncryptOptions,
): Promise<string | Uint8Array> {
  const result = await wasm.encrypt(
    resolveInput(opts.input),
    opts.recipientPublicKeys,
  );
  return formatOutput(opts.input, result);
}

/** Encrypt with signing via a WASM key handle. */
export async function encryptWithSigningHandle(
  opts: EncryptOptions & { signingKeyHandle: number },
): Promise<string | Uint8Array> {
  const result = await wasm.encryptWithSigningHandle(
    resolveInput(opts.input),
    opts.recipientPublicKeys,
    opts.signingKeyHandle,
  );
  return formatOutput(opts.input, result);
}

/** Decrypt using a WASM key handle. */
export async function decryptWithHandle(
  opts: DecryptOptions & { keyHandle: number },
): Promise<DecryptResult> {
  const ciphertext =
    opts.input.kind === "binary"
      ? opts.input.binaryMessage
      : new TextEncoder().encode(opts.input.armoredMessage);

  const { plaintext, signatureInfo } = await wasm.decryptWithHandle(
    ciphertext,
    opts.keyHandle,
    opts.verificationPublicKeys,
  );

  let data: string | Uint8Array;
  try {
    data = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  } catch {
    data = plaintext;
  }

  return {
    data,
    signatureValid: signatureInfo.signatureValid,
    signerKeyId: signatureInfo.signerKeyId,
  };
}

/** Sign using a WASM key handle. */
export async function signWithHandle(
  text: string,
  keyHandle: number,
): Promise<string> {
  return wasm.signWithHandle(text, keyHandle);
}

/** Verify a cleartext-signed message. */
export async function verify(opts: VerifyOptions): Promise<VerifyResult> {
  return wasm.verify(opts.signedMessage, opts.verificationPublicKeys);
}
