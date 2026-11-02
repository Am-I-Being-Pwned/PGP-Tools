/** Split text into armored key and message blocks for both engines
 *  (OpenPGP, age/OpenSSH). The marker patterns live here because
 *  `classify-action.ts` and `drop-routing.ts` must agree with them
 *  exactly, or a drop routes to a screen that finds nothing. */

const PUBLIC_BLOCK =
  /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----/g;
const PRIVATE_BLOCK =
  /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g;

function matchAll(text: string, re: RegExp): string[] {
  // Module-level regexes are /g/: reset lastIndex.
  re.lastIndex = 0;
  const blocks: string[] = [];
  let match;
  while ((match = re.exec(text)) !== null) {
    blocks.push(match[0]);
  }
  return blocks;
}

export function splitPublicKeyBlocks(text: string): string[] {
  return matchAll(text, PUBLIC_BLOCK);
}

export function splitPrivateKeyBlocks(text: string): string[] {
  return matchAll(text, PRIVATE_BLOCK);
}

// ── age / SSH markers ────────────────────────────────────────────────

export const AGE_ARMOR_BEGIN = "-----BEGIN AGE ENCRYPTED FILE-----";

/** First line of a binary age file; the literal the Rust sniffer
 *  (`is_age_message`) checks. */
export const AGE_BINARY_MAGIC = "age-encryption.org/v1";

/** The only label OpenSSH emits for a private key; encrypted or not
 *  can't be told from the header. */
export const OPENSSH_PRIVATE_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----";

/**
 * Private-key formats the age engine recognises but refuses (PuTTY .ppk,
 * PKCS#8, legacy encrypted PEM), so its curated "convert it with ..."
 * message is shown. Must mirror `reject_foreign_private_key_format` in
 * gpg-wasm/src/age.rs exactly. Unencrypted PKCS#1 is deliberately absent:
 * that is a CRX signing key, checked before the SSH branch.
 */
const FOREIGN_SSH_PRIVATE_MARKERS = [
  "PuTTY-User-Key-File",
  "-----BEGIN PRIVATE KEY-----",
  "-----BEGIN ENCRYPTED PRIVATE KEY-----",
] as const;

/** Matched anywhere: it sits under a varying BEGIN line. */
export const LEGACY_PEM_ENCRYPTED = "Proc-Type: 4,ENCRYPTED";

export function looksLikeForeignSshPrivateKey(text: string): boolean {
  if (text.includes(LEGACY_PEM_ENCRYPTED)) return true;
  const trimmed = text.trimStart();
  return FOREIGN_SSH_PRIVATE_MARKERS.some((m) => trimmed.startsWith(m));
}

const AGE_BLOCK =
  /-----BEGIN AGE ENCRYPTED FILE-----[\s\S]*?-----END AGE ENCRYPTED FILE-----/g;
const OPENSSH_PRIVATE_BLOCK =
  /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----/g;

/**
 * One supported SSH public key line (`ssh-ed25519`/`ssh-rsa`). Line-start
 * anchor plus the `AAAA` prefix (every wire blob starts with a 4-byte
 * length with zero top bytes) keep prose and armor bodies out.
 */
const SSH_PUBLIC_LINE =
  /^[ \t]*(?:ssh-ed25519|ssh-rsa)[ \t]+AAAA[A-Za-z0-9+/]+={0,3}(?:[ \t]+[^\r\n]*)?/gm;

/**
 * The same shape with ANY algorithm name, for paths where the engine's
 * refusal is what the user should see.
 *
 * Invariant: the engine decides validity; every layer above it forwards
 * and displays. Narrowing the type here would replace "ECDSA keys are not
 * supported" with a false "no keys found". Users: `github/response.ts`,
 * `import/prepare.ts`, `classify-action.ts`, `drop-routing.ts` -- keep
 * this list honest so a new narrowing finds its siblings.
 */
const SSH_PUBLIC_CANDIDATE_LINE =
  /^[ \t]*[A-Za-z][A-Za-z0-9@._-]{2,63}[ \t]+AAAA[A-Za-z0-9+/]+={0,3}(?:[ \t]+[^\r\n]*)?/gm;

export function splitAgeBlocks(text: string): string[] {
  return matchAll(text, AGE_BLOCK);
}

export function splitSshPrivateKeyBlocks(text: string): string[] {
  return matchAll(text, OPENSSH_PRIVATE_BLOCK);
}

export function splitSshPublicKeyLines(text: string): string[] {
  return matchAll(text, SSH_PUBLIC_LINE).map((line) => line.trim());
}

/** Any-algorithm SSH key lines; see {@link SSH_PUBLIC_CANDIDATE_LINE}. */
export function splitSshPublicKeyCandidateLines(text: string): string[] {
  return matchAll(text, SSH_PUBLIC_CANDIDATE_LINE).map((line) => line.trim());
}

/** Routing only -- the engine re-checks. */
export function looksLikeAgeMessage(text: string): boolean {
  return text.includes(AGE_ARMOR_BEGIN) || text.includes(AGE_BINARY_MAGIC);
}

export interface ArmoredKeyBlocks {
  publicKeys: string[];
  privateKeys: string[];
  /** age recipients. */
  sshPublicKeys: string[];
  /** age identities. */
  sshPrivateKeys: string[];
}

/** Split a mixed armored dump (e.g. our backup bundle) into key blocks of
 *  every kind we import. */
export function splitArmoredKeyBlocks(text: string): ArmoredKeyBlocks {
  return {
    publicKeys: splitPublicKeyBlocks(text),
    privateKeys: splitPrivateKeyBlocks(text),
    // Deliberately the narrow matcher: this splits our own backup, whose
    // SSH lines the engine already accepted.
    sshPublicKeys: splitSshPublicKeyLines(text),
    sshPrivateKeys: splitSshPrivateKeyBlocks(text),
  };
}
