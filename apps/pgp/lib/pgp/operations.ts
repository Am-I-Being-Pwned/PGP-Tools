import type {
  DecryptOptions,
  DecryptResult,
  EncryptInput,
  EncryptOptions,
  VerifyOptions,
  VerifyResult,
} from "./types";
import * as wasm from "./wasm";
// Named import, not `wasm.decryptWithPassword`, and deliberately: the
// `wasm.<export>` shape is what `scripts/audit-invariants.mjs` looks for
// to find raw-glue calls escaping the wasm-secrets boundary, and every
// other secret-listed wrapper is reached this way from an operations
// module (`lib/age/operations.ts` does the same for
// `decryptAgeWithHandle`). What is imported here IS the boundary
// module's wrapper -- the barrel re-exports the wrappers, never the glue.
import { decryptWithPassword as decryptWithPasswordWasm } from "./wasm-secrets";

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
    signatureStatus: signatureInfo.signatureStatus,
    signerKeyId: signatureInfo.signerKeyId,
  };
}

/**
 * Decrypt a message that was encrypted to a PASSWORD (`gpg --symmetric`).
 *
 * The symmetric sibling of {@link decryptWithHandle}, returning the very
 * same {@link DecryptResult} so a caller renders one shape whichever way
 * the message was opened -- including the signature verdict, because a
 * password-encrypted message can be signed.
 *
 * NO KEY IS NEEDED and none is used: this works with an empty keyring.
 *
 * The password is taken as a STRING here and encoded to bytes inside,
 * with the buffer wiped in a `finally`. Taking a string at this boundary
 * is deliberate -- it comes from an `<input type="password">`, which can
 * only ever produce one, and pretending otherwise by making every caller
 * encode would spread the un-wipeable copy rather than contain it. The
 * copy this function makes IS wiped; the one React holds is bounded by
 * the panel's lifetime, exactly as the key-unlock prompt's is.
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
      signatureStatus: signatureInfo.signatureStatus,
      signerKeyId: signatureInfo.signerKeyId,
    };
  } finally {
    passwordBytes.fill(0);
  }
}

/**
 * Which kinds of session-key packet the message carries, so the caller
 * can decide what to ask the user for BEFORE asking. Needs no password
 * and no key to answer -- it reads the packets in front of the encrypted
 * container.
 */
export async function messageEncryption(
  input: DecryptOptions["input"],
): Promise<wasm.MessageEncryption> {
  const ciphertext =
    input.kind === "binary"
      ? input.binaryMessage
      : new TextEncoder().encode(input.armoredMessage);
  return wasm.messageEncryption(ciphertext);
}

/**
 * Return the fingerprint of the key (from `candidatePublicKeys`) that the
 * message is encrypted to, or null if none match. Accepts armored or binary
 * ciphertext (Sequoia auto-detects armor).
 */
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
