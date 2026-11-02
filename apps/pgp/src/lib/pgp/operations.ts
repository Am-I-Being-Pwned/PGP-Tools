import type {
  DecryptOptions,
  DecryptResult,
  EncryptInput,
  EncryptOptions,
  VerifyOptions,
  VerifyResult,
} from "./types";
import * as wasm from "./wasm";
// Named import on purpose: `wasm.<export>` is the shape audit-invariants
// flags as raw-glue calls escaping the wasm-secrets boundary.
import {
  decryptWithPassword as decryptWithPasswordWasm,
  encryptWithPassword as encryptWithPasswordWasm,
} from "./wasm-secrets";

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

/** Password taken as a string (see {@link decryptWithPassword}); the
 *  encoded buffer is wiped in a `finally`. */
async function encryptToPassword(
  opts: EncryptOptions & { password: string; signingKeyHandle?: number },
): Promise<string | Uint8Array> {
  const passwordBytes = new TextEncoder().encode(opts.password);
  try {
    const result = await encryptWithPasswordWasm(
      resolveInput(opts.input),
      opts.recipientPublicKeys,
      passwordBytes,
      opts.signingKeyHandle,
    );
    return formatOutput(opts.input, result);
  } finally {
    passwordBytes.fill(0);
  }
}

/** Text if valid UTF-8, else bytes. `ignoreBOM` keeps a leading BOM so
 *  Copy/Download round-trip byte-for-byte. */
export function asTextIfUtf8(plaintext: Uint8Array): string | Uint8Array {
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      plaintext,
    );
  } catch {
    return plaintext;
  }
}

export async function encrypt(
  opts: EncryptOptions & { password?: string },
): Promise<string | Uint8Array> {
  if (opts.password !== undefined) {
    return encryptToPassword({ ...opts, password: opts.password });
  }
  const result = await wasm.encrypt(
    resolveInput(opts.input),
    opts.recipientPublicKeys,
  );
  return formatOutput(opts.input, result);
}

export async function encryptWithSigningHandle(
  opts: EncryptOptions & { signingKeyHandle: number; password?: string },
): Promise<string | Uint8Array> {
  if (opts.password !== undefined) {
    return encryptToPassword({ ...opts, password: opts.password });
  }
  const result = await wasm.encryptWithSigningHandle(
    resolveInput(opts.input),
    opts.recipientPublicKeys,
    opts.signingKeyHandle,
  );
  return formatOutput(opts.input, result);
}

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
    opts.maxOutputBytes,
  );

  const data = asTextIfUtf8(plaintext);

  return {
    data,
    ...signatureInfo,
  };
}

/**
 * `gpg --symmetric` decrypt; same {@link DecryptResult} (incl. signature
 * verdict) as {@link decryptWithHandle}. Needs no key.
 *
 * Takes the password as a STRING deliberately: it comes from an
 * `<input type="password">`, so making callers encode would spread the
 * un-wipeable copy. The encoded copy made here is wiped in a `finally`.
 */
export async function decryptWithPassword(
  opts: DecryptOptions & { password: string },
): Promise<DecryptResult> {
  const ciphertext =
    opts.input.kind === "binary"
      ? opts.input.binaryMessage
      : new TextEncoder().encode(opts.input.armoredMessage);

  const passwordBytes = new TextEncoder().encode(opts.password);
  try {
    const { plaintext, signatureInfo } = await decryptWithPasswordWasm(
      ciphertext,
      passwordBytes,
      opts.verificationPublicKeys,
      opts.maxOutputBytes,
    );

    const data = asTextIfUtf8(plaintext);

    return {
      data,
      ...signatureInfo,
    };
  } finally {
    passwordBytes.fill(0);
  }
}

/** The caller must say it was not encrypted -- this result is never a decrypt. */
export async function openUnencrypted(
  opts: DecryptOptions,
): Promise<DecryptResult> {
  const message =
    opts.input.kind === "binary"
      ? opts.input.binaryMessage
      : new TextEncoder().encode(opts.input.armoredMessage);

  const { plaintext, signatureInfo } = await wasm.openUnencrypted(
    message,
    opts.verificationPublicKeys,
    opts.maxOutputBytes,
  );

  const data = asTextIfUtf8(plaintext);

  return {
    data,
    ...signatureInfo,
  };
}

export async function messageEncryption(
  input: DecryptOptions["input"],
): Promise<wasm.MessageEncryption> {
  const ciphertext =
    input.kind === "binary"
      ? input.binaryMessage
      : new TextEncoder().encode(input.armoredMessage);
  return wasm.messageEncryption(ciphertext);
}

/** Fingerprint of the matching candidate, or null. Armored or binary input. */
export async function selectDecryptionKey(
  input: DecryptOptions["input"],
  candidatePublicKeys: string[],
): Promise<string | null> {
  const ciphertext =
    input.kind === "binary"
      ? input.binaryMessage
      : new TextEncoder().encode(input.armoredMessage);
  return wasm.selectDecryptionKey(ciphertext, candidatePublicKeys);
}

export async function signWithHandle(
  text: string,
  keyHandle: number,
): Promise<string> {
  return wasm.signWithHandle(text, keyHandle);
}

export async function verify(opts: VerifyOptions): Promise<VerifyResult> {
  return wasm.verify(
    opts.signedMessage,
    opts.verificationPublicKeys,
    opts.maxOutputBytes,
  );
}
