/**
 * ============================================================================
 * age / SSH operations — JS-side coordinator.
 * ============================================================================
 *
 * The age engine's counterpart to `lib/pgp/operations.ts`, and
 * deliberately the same shape: resolve the input to bytes, call one wasm
 * export, format the output. Everything genuinely age-specific lives in
 * `gpg-wasm/src/age.rs`; everything about key lifetime lives in
 * `./protect-flow.ts`. This file is the thin middle.
 *
 * Two differences from the PGP module, both from the format rather than
 * from us:
 *
 *   - age has no signing operation, so there is no `sign` / `verify`
 *     here and no signature status on a decrypt result.
 *   - age recipients are `<type> <base64>` SSH public key lines, not
 *     armored certs, and they cannot be mixed with OpenPGP recipients in
 *     one message (enforced in `lib/encrypt-recipients.ts`).
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

/**
 * Encrypt to one or more SSH recipients.
 *
 * Text input always comes back armored, because that is the only form a
 * user can paste into the message they are writing. Binary input honours
 * `armor`, matching `lib/pgp/operations.ts`.
 */
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
 * Decrypt an age file (binary or armored) with an unlocked SSH identity.
 *
 * Returns text when the plaintext is valid UTF-8 and the raw bytes
 * otherwise -- the same fallback `decryptWithHandle` makes for PGP, so a
 * caller can render either engine's result the same way.
 *
 * ZEROIZATION, and precisely what it buys. `decryptAgeWithHandle`'s
 * contract says the caller should scrub the buffer it returns; this is
 * that caller, and it does -- but only on the branch where it can, and
 * the two branches differ in kind:
 *
 *   - TEXT: the decoded `string` is what goes to the UI, so the buffer
 *     is a copy nobody needs any more and `.fill(0)` genuinely removes
 *     one live copy of the plaintext from the JS heap. It does NOT
 *     reduce the exposure to zero: the returned string is an immutable
 *     V8 string and cannot be zeroized at all, and it is the copy that
 *     lives longest (the workspace holds it until `wipe()`, §8.11).
 *     Same honest caveat as §5's "JS-side OpenSSH key-file Uint8Array"
 *     row -- one fewer copy, not no copies.
 *   - BINARY: the buffer IS the return value. Ownership passes to the
 *     caller, so scrubbing it here would hand back zeros. `wipePlaintext`
 *     /`zeroizeResultBytes` in the workspace is what wipes this one, and
 *     that is the right place for it.
 *
 * A `finally` would be wrong for exactly that reason: it cannot tell the
 * two branches apart.
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
    text = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  } catch {
    // Not UTF-8: the bytes themselves are the result and the caller owns
    // them from here. Deliberately not scrubbed -- see above.
    return plaintext;
  }
  plaintext.fill(0);
  return text;
}

/** Parse one SSH public key line into its canonical recipient form plus
 *  the public facts about it. Throws on anything unusable as an age
 *  recipient. */
export async function parseRecipient(
  line: string,
): Promise<SshRecipientInfo> {
  return parseSshRecipient(line);
}

/**
 * Which of the user's SSH identities an age file is encrypted to, as an
 * index into `candidateRecipients`, or null when none of them is a
 * recipient.
 *
 * The age answer to `lib/pgp/operations.ts`'s `selectDecryptionKey`, and
 * the reason it has to exist separately: that one parses OpenPGP packets
 * and throws on age ciphertext, so a caller that only knew about it left
 * whichever PGP key was selected in place and failed at decrypt.
 *
 * Derivable with no private key at all -- age's ssh stanzas name their
 * recipient by a hash of its public key -- so the caller can narrow the
 * key picker before asking for a password. Returns null rather than
 * throwing when the file is not age ciphertext, so it can be called on
 * anything the decrypt screen is holding.
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

/** Cheap sniff for routing: does this look like an age message at all?
 *  Accepts both the binary header and the armor marker. */
export async function isAgeCiphertext(data: Uint8Array): Promise<boolean> {
  return isAgeMessage(data);
}
