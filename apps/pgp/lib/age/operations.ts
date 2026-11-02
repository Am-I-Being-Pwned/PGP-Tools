/**
 * age / SSH operations: resolve input, call one wasm export, format the
 * output. Key lifetime lives in `./protect-flow.ts`. age has no signing,
 * and age recipients cannot mix with OpenPGP ones in one message
 * (enforced in `lib/encrypt-recipients.ts`).
 */

import type { DecryptInput, EncryptInput } from "../pgp/types";
import type { SshRecipientInfo } from "../pgp/wasm";
import {
  decryptAgeWithHandle,
  encryptAgeToRecipients,
  isAgeMessage,
  parseSshRecipient,
  selectAgeDecryptionKey,
} from "../pgp/wasm";

export type { SshRecipientInfo };

export interface AgeEncryptOptions {
  input: EncryptInput;
  /** Canonical `<type> <base64>` SSH public key lines. */
  recipients: string[];
}

export interface AgeDecryptOptions {
  input: DecryptInput;
  /** An SSH_KEY_STORE handle from `./protect-flow.ts`'s unlock. */
  keyHandle: number;
}

function resolveInput(input: EncryptInput): Uint8Array {
  return input.kind === "binary"
    ? input.binary
    : new TextEncoder().encode(input.text);
}

function resolveCiphertext(input: DecryptInput): Uint8Array {
  return input.kind === "binary"
    ? input.binaryMessage
    : new TextEncoder().encode(input.armoredMessage);
}

/** Encrypt to SSH recipients. Text input is always armored; binary
 *  honours `armor`. */
export async function encryptToRecipients(
  opts: AgeEncryptOptions,
): Promise<string | Uint8Array> {
  const armor = opts.input.kind === "text" || opts.input.armor === true;
  const result = await encryptAgeToRecipients(
    resolveInput(opts.input),
    opts.recipients,
    armor,
  );
  return opts.input.kind === "text" || opts.input.armor
    ? new TextDecoder().decode(result)
    : result;
}

/**
 * Decrypt an age file with an unlocked SSH identity; text if valid UTF-8,
 * else raw bytes.
 *
 * Zeroization: on the TEXT branch the buffer is a spare copy and is
 * `.fill(0)`'d (the returned V8 string can't be -- one fewer copy, not
 * none; SECURITY.md §5). On the BINARY branch the buffer IS the return
 * value and the caller owns/wipes it. Hence no `finally`.
 */
export async function decryptWithHandle(
  opts: AgeDecryptOptions,
): Promise<string | Uint8Array> {
  const plaintext = await decryptAgeWithHandle(
    resolveCiphertext(opts.input),
    opts.keyHandle,
  );
  let text: string;
  try {
    // `ignoreBOM: true` keeps a leading BOM so Copy/Download round-trip
    // the exact file.
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      plaintext,
    );
  } catch {
    // Caller owns the bytes; deliberately not scrubbed.
    return plaintext;
  }
  plaintext.fill(0);
  return text;
}

/** Parse an SSH public key line; throws if unusable as an age recipient. */
export async function parseRecipient(line: string): Promise<SshRecipientInfo> {
  return parseSshRecipient(line);
}

/**
 * Index into `candidateRecipients` of the identity an age file is
 * encrypted to, or null (also for non-age input). Needs no private key,
 * so the picker can be narrowed before a password prompt.
 */
export async function selectDecryptionKey(
  ciphertext: Uint8Array,
  candidateRecipients: string[],
): Promise<number | null> {
  try {
    return await selectAgeDecryptionKey(ciphertext, candidateRecipients);
  } catch {
    return null;
  }
}

/** Sniff for age binary header or armor marker. */
export async function isAgeCiphertext(data: Uint8Array): Promise<boolean> {
  return isAgeMessage(data);
}
