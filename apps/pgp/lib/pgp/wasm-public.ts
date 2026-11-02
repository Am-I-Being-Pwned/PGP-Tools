/**
 * Public-side wasm wrappers: NO SECRET KEY MATERIAL CROSSES THIS BOUNDARY.
 * Only public material in/out, or KEY_STORE via opaque handle. Anything
 * taking a password/PRF or returning private-key bytes belongs in
 * `wasm-secrets.ts`. SECURITY.md §3.
 */

import type { EngineError } from "../errors/engine-error";
import type {
  KeyDetails,
  KeyInfo,
  SignatureDetails,
  SignatureStatus,
} from "./types";
import type { WasmModule } from "./wasm-loader";
import { decodeEngineError } from "../errors/engine-error";
import { loadWasm } from "./wasm-loader";

// ── status / metadata ────────────────────────────────────────────────

export async function ping(): Promise<string> {
  const wasm = await loadWasm();
  return wasm.ping();
}

// ── CRX verification (no key material; pure public check) ────────────

export interface CrxVerifyResult {
  /** True iff a `sha256_with_rsa` proof verifies AND its key's SHA-256
   *  matches the signed crx_id. */
  valid: boolean;
  /** Claimed id; present even for a tampered-but-well-formed CRX. */
  extensionId?: string;
  algorithm?: string;
  error?: EngineError | string;
}

/** Malformed input yields `{ valid: false, error }` rather than throwing. */
export async function verifyCrx(crx: Uint8Array): Promise<CrxVerifyResult> {
  const wasm = await loadWasm();
  const r = JSON.parse(wasm.verifyCrx(crx)) as CrxVerifyResult & {
    error?: string;
  };
  return r.error === undefined
    ? r
    : { ...r, error: decodeEngineError(r.error) };
}

/** Metadata only. Accepts private armor; secrets are dropped inside the call. */
export async function parseKey(armored: string): Promise<KeyInfo> {
  const wasm = await loadWasm();
  const json = wasm.parseKey(armored);
  return JSON.parse(json) as KeyInfo;
}

/** Per-component-key breakdown, primary first. Secrets dropped as in `parseKey`. */
export async function parseKeyDetails(armored: string): Promise<KeyDetails> {
  const wasm = await loadWasm();
  const json = wasm.parseKeyDetails(armored);
  return JSON.parse(json) as KeyDetails;
}

export interface ParsedCert {
  keyInfo: KeyInfo;
  armored: string;
}

/** Every cert in a blob (publishers bundle yearly-rotated certs; `parseKey`
 *  sees only the first). Store/encrypt against each cert's own armor. */
export async function parseKeys(armored: string): Promise<ParsedCert[]> {
  const wasm = await loadWasm();
  const json = wasm.parseKeys(armored);
  return JSON.parse(json) as ParsedCert[];
}

/** Secret material is dropped inside the wasm call. */
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

// ── encrypt / sign / verify (public-key crypto only) ─────────────────

export async function encrypt(
  plaintext: Uint8Array,
  recipientPublicKeys: string[],
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.encrypt(
    plaintext,
    JSON.stringify(recipientPublicKeys),
    null,
    null,
  );
}

export interface SignatureInfo extends SignatureDetails {
  signatureValid: boolean | null;
  signatureStatus: SignatureStatus;
  signerKeyId: string | null;
}

export interface VerifyResultWasm extends SignatureDetails {
  text: string;
  signatureValid: boolean;
  signatureStatus: SignatureStatus;
  signerKeyId: string | null;
}

/** An import can only ADD what the owner signed, never roll a contact
 *  back. Throws when `incoming` is a different key. */
export async function mergePublicKey(
  storedArmored: string,
  incomingArmored: string,
): Promise<string> {
  const wasm = await loadWasm();
  return wasm.mergePublicKey(storedArmored, incomingArmored);
}

/** Issuer fingerprints / key IDs of a bare revocation certificate, or
 *  null when the input isn't one. */
export async function revocationIssuers(
  armored: string,
): Promise<string[] | null> {
  const wasm = await loadWasm();
  try {
    return JSON.parse(wasm.revocationIssuers(armored)) as string[];
  } catch {
    return null;
  }
}

// ── an unattended run's output ceiling ───────────────────────────────

/** Result exceeded an unattended run's `maxOutputBytes`. Not a failure:
 *  the user's click runs uncapped. */
export class OutputCapReached extends Error {
  constructor() {
    super("Output cap reached");
    this.name = "OutputCapReached";
  }
}

/** Matched by VALUE against `outputCapReachedMessage()`, never transcribed prose. */
export function withOutputCap<T>(wasm: WasmModule, run: () => T): T {
  try {
    return run();
  } catch (e) {
    if (typeof e === "string" && e === wasm.outputCapReachedMessage()) {
      throw new OutputCapReached();
    }
    throw e;
  }
}

/** `maxOutputBytes`: unattended runs only (see {@link OutputCapReached}). */
export async function verify(
  signedMessage: string,
  verificationPublicKeys: string[],
  maxOutputBytes?: number,
): Promise<VerifyResultWasm> {
  const wasm = await loadWasm();
  const json = withOutputCap(wasm, () =>
    wasm.verify(
      signedMessage,
      JSON.stringify(verificationPublicKeys),
      maxOutputBytes,
    ),
  );
  return JSON.parse(json) as VerifyResultWasm;
}

// ── handle-mediated operations ───────────────────────────────────────
// The handle is JS's only view of the cert; it never leaves wasm.

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
    null,
  );
}

export interface DecryptWithHandleResult {
  /** User data, not key material; crosses by design. */
  plaintext: Uint8Array;
  signatureInfo: SignatureInfo;
}

/**
 * Unpack `[LE u32 sig_json len][sig_json][plaintext]`. The single reader of
 * `pack_decrypt_result`'s layout, which delivers verdict and plaintext
 * atomically; don't hand-roll a second one.
 */
export function unpackDecryptResult(
  packed: Uint8Array,
): DecryptWithHandleResult {
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

/** `maxOutputBytes`: see {@link verify}. */
export async function decryptWithHandle(
  ciphertext: Uint8Array,
  keyHandle: number,
  verificationPublicKeys?: string[],
  maxOutputBytes?: number,
): Promise<DecryptWithHandleResult> {
  const wasm = await loadWasm();
  const packed = withOutputCap(wasm, () =>
    wasm.decryptWithHandle(
      ciphertext,
      keyHandle,
      verificationPublicKeys ? JSON.stringify(verificationPublicKeys) : null,
      maxOutputBytes,
    ),
  );
  return unpackDecryptResult(packed);
}

export async function signWithHandle(
  text: string,
  keyHandle: number,
): Promise<string> {
  const wasm = await loadWasm();
  return wasm.signWithHandle(text, keyHandle);
}

/** Fingerprint of the candidate the message is addressed to, or null;
 *  picks a key without unlocking every candidate. */
export async function selectDecryptionKey(
  ciphertext: Uint8Array,
  candidatePublicKeys: string[],
): Promise<string | null> {
  const wasm = await loadWasm();
  const json = wasm.selectDecryptionKey(
    ciphertext,
    JSON.stringify(candidatePublicKeys),
  );
  return JSON.parse(json) as string | null;
}

/** Session-key packet kinds present; `password` and `publicKey` can both be true. */
export interface MessageEncryption {
  password: boolean;
  publicKey: boolean;
  /** False for a signed-only "PGP MESSAGE": it must never be shown as
   *  decrypted -- see `openUnencrypted`. */
  encrypted: boolean;
}

/** Shape only (can't tell whether a given key/password works); lets the
 *  UI ask for a password instead of failing down the key path. */
export async function messageEncryption(
  ciphertext: Uint8Array,
): Promise<MessageEncryption> {
  const wasm = await loadWasm();
  return JSON.parse(wasm.messageEncryption(ciphertext)) as MessageEncryption;
}

/** A message with no encryption layer, with its signature verdict. The
 *  engine refuses each kind on the other's path, so they can't substitute. */
export async function openUnencrypted(
  message: Uint8Array,
  verificationPublicKeys?: string[],
  maxOutputBytes?: number,
): Promise<DecryptWithHandleResult> {
  const wasm = await loadWasm();
  const packed = withOutputCap(wasm, () =>
    wasm.openUnencrypted(
      message,
      verificationPublicKeys ? JSON.stringify(verificationPublicKeys) : null,
      maxOutputBytes,
    ),
  );
  return unpackDecryptResult(packed);
}

/** For imported keys (generation already makes one). Public output only. */
export async function revocationCertificateWithHandle(
  keyHandle: number,
): Promise<string> {
  const wasm = await loadWasm();
  return wasm.revocationCertificateWithHandle(keyHandle);
}

/** Drop (and zeroize) a KEY_STORE entry. */
export async function dropKey(handle: number): Promise<void> {
  const wasm = await loadWasm();
  wasm.dropKey(handle);
}

// ── age / SSH recipients (public key material only) ──────────────────
// The age engine's no-secret half; identities live in `wasm-secrets.ts`.

export interface SshRecipientInfo {
  /** Canonical `<type> <base64>`, comment stripped; persisted as the
   *  contact's "armor". */
  recipient: string;
  algorithm: string;
  /** `SHA256:...`; the key's stable identity. */
  fingerprint: string;
  comment: string;
}

/** Throws on anything not a usable `ssh-ed25519` / `ssh-rsa` recipient. */
export async function parseSshRecipient(
  line: string,
): Promise<SshRecipientInfo> {
  const wasm = await loadWasm();
  return JSON.parse(wasm.parseSshRecipient(line)) as SshRecipientInfo;
}

/** One unusable recipient fails the whole call. */
export async function encryptAgeToRecipients(
  plaintext: Uint8Array,
  recipients: string[],
  armor: boolean,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.encryptAgeToRecipients(
    plaintext,
    JSON.stringify(recipients),
    armor,
  );
}

/** Age twin of {@link selectDecryptionKey}: index into
 *  `candidateRecipients` or null. Header-only, no secret. Throws on non-age. */
export async function selectAgeDecryptionKey(
  ciphertext: Uint8Array,
  candidateRecipients: string[],
): Promise<number | null> {
  const wasm = await loadWasm();
  const json = wasm.selectAgeDecryptionKey(
    ciphertext,
    JSON.stringify(candidateRecipients),
  );
  return JSON.parse(json) as number | null;
}

/**
 * Names an unsupported key format (`.ppk`, PKCS#8, legacy PEM) or null, so
 * the preview can explain before the protect step. Public side like
 * `parseKey`: nothing secret returns and wasm `Zeroizing`-wraps the input.
 */
export async function sshPrivateKeyFormatRejection(
  keyFile: Uint8Array,
): Promise<string | null> {
  const wasm = await loadWasm();
  return JSON.parse(wasm.sshPrivateKeyFormatRejection(keyFile)) as
    string | null;
}

/** Match the "needs passphrase" error by this value, never transcribed
 *  prose: a stale copy silently makes protected keys unimportable. */
export async function sshPassphraseRequiredMessage(): Promise<string> {
  const wasm = await loadWasm();
  return wasm.sshPassphraseRequiredMessage();
}

/** Cheap sniff for routing, not a validity check. */
export async function isAgeMessage(data: Uint8Array): Promise<boolean> {
  const wasm = await loadWasm();
  return wasm.isAgeMessage(data);
}

// ── contacts session (uses an in-WASM AES key derived from master) ───
// The session key never crosses to JS.

export async function dropContactsSession(): Promise<void> {
  const wasm = await loadWasm();
  wasm.dropContactsSession();
}

export async function hasContactsSession(): Promise<boolean> {
  const wasm = await loadWasm();
  return wasm.hasContactsSession();
}

// ── per-store envelope (domain-separated key AND AAD) ────────────────
// `domain` must be the chrome.storage key the blob lives under. Call only
// via `lib/storage/envelope.ts`, which owns that convention.

/** Returns `[12-byte IV][ciphertext]`. */
export async function encryptStore(
  domain: string,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.encryptStore(domain, plaintext);
}

/** Open a blob sealed for the SAME `domain`; any other domain rejects. */
export async function decryptStore(
  domain: string,
  ciphertext: Uint8Array,
  iv: Uint8Array,
): Promise<Uint8Array> {
  const wasm = await loadWasm();
  return wasm.decryptStore(domain, ciphertext, iv);
}

// ── legacy (pre-v1) shared envelope ─────────────────────────────────
// `decryptContacts` is the migration read path; `encryptContacts` is for
// tests only. Production must not write this format -- use `encryptStore`.

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
