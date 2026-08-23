/** Split text into individual armored key blocks and message blocks, for
 *  both engines: OpenPGP armor, and the age / OpenSSH forms.
 *
 *  This module is also where the marker patterns themselves live, because
 *  `classify-action.ts` and `drop-routing.ts` must agree with it exactly:
 *  a header one of them recognises and another does not is a drop routed
 *  to a screen that then reports it found nothing. */

const PUBLIC_BLOCK =
  /-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]*?-----END PGP PUBLIC KEY BLOCK-----/g;
const PRIVATE_BLOCK =
  /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----/g;

function matchAll(text: string, re: RegExp): string[] {
  // Fresh lastIndex per call -- the module-level regexes are /g/.
  re.lastIndex = 0;
  const blocks: string[] = [];
  let match;
  while ((match = re.exec(text)) !== null) {
    blocks.push(match[0]);
  }
  return blocks;
}

/** Every armored public-key block in `text`, in order. */
export function splitPublicKeyBlocks(text: string): string[] {
  return matchAll(text, PUBLIC_BLOCK);
}

/** Every armored private-key block in `text`, in order. */
export function splitPrivateKeyBlocks(text: string): string[] {
  return matchAll(text, PRIVATE_BLOCK);
}

// ── age / SSH markers ────────────────────────────────────────────────

/** age's armored form. The binary form has no header line -- it starts
 *  with {@link AGE_BINARY_MAGIC} instead. */
export const AGE_ARMOR_BEGIN = "-----BEGIN AGE ENCRYPTED FILE-----";

/** First line of a BINARY age file: the format's version string. Matching
 *  it as text is safe -- it is ASCII, and it is the literal the Rust
 *  sniffer (`is_age_message`) checks for. */
export const AGE_BINARY_MAGIC = "age-encryption.org/v1";

/** OpenSSH's private key container. Note this is the *only* PEM label
 *  OpenSSH emits for a private key, encrypted or not -- the passphrase
 *  state is inside the body, not the header, so it cannot be told apart
 *  here. */
export const OPENSSH_PRIVATE_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----";

/**
 * Private-key files that are NOT OpenSSH v1 but are still the age
 * engine's to answer for: a PuTTY `.ppk`, a PKCS#8 key, and a legacy PEM
 * encrypted with the pre-OpenSSH-v1 scheme.
 *
 * Recognition, deliberately not acceptance. `gpg-wasm/src/age.rs` has a
 * curated message for each ("export it with PuTTYgen", "convert it with
 * `ssh-keygen -p -f`"), and none of them could ever be shown while these
 * formats were not recognised anywhere: they fell through to the OpenPGP
 * parse and came back as the generic "that doesn't look like a key".
 *
 * The markers mirror `reject_foreign_private_key_format` exactly -- a
 * format matched here that wasm does not name would route into the SSH
 * branch and then report nothing, which is the same failure the header
 * of this module warns about.
 *
 * Note what is NOT here: an unencrypted `-----BEGIN RSA PRIVATE KEY-----`
 * (PKCS#1). That is a CRX signing key in this app, and the import flow
 * checks for one before it reaches the SSH branch at all.
 */
const FOREIGN_SSH_PRIVATE_MARKERS = [
  "PuTTY-User-Key-File",
  "-----BEGIN PRIVATE KEY-----",
  "-----BEGIN ENCRYPTED PRIVATE KEY-----",
] as const;

/** The legacy PEM encryption header. Matched anywhere in the text rather
 *  than at the start: it sits under the BEGIN line, and which BEGIN line
 *  varies (`RSA PRIVATE KEY`, `DSA PRIVATE KEY`, `EC PRIVATE KEY`). */
export const LEGACY_PEM_ENCRYPTED = "Proc-Type: 4,ENCRYPTED";

/** True when the text is a private key in a format the age engine
 *  recognises but refuses. See {@link FOREIGN_SSH_PRIVATE_MARKERS}. */
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
 * One SSH public key line: `<type> <base64>[ comment]`.
 *
 * Anchored to the start of a line (`/m`) and required to begin `AAAA` --
 * every SSH wire-format blob opens with a 4-byte big-endian length whose
 * top bytes are zero, so its base64 always does. Together those two rules
 * keep the pattern from firing on prose that merely mentions
 * `ssh-ed25519`, and on the base64 body of an armored block (whose lines
 * carry no spaces).
 *
 * `ssh-ed25519` and `ssh-rsa` only: those are the recipient types the age
 * engine supports (`gpg-wasm/src/age.rs`). A dropped `ssh-dss` key should
 * be reported as unusable, not silently ignored as "not a key".
 */
const SSH_PUBLIC_LINE =
  /^[ \t]*(?:ssh-ed25519|ssh-rsa)[ \t]+AAAA[A-Za-z0-9+/]+={0,3}(?:[ \t]+[^\r\n]*)?/gm;

/**
 * The same line shape with the TYPE LEFT OPEN: any
 * `<algorithm> AAAA<base64>` line, whatever the algorithm names itself.
 *
 * This is the form used where a line is about to be handed to the engine
 * and the engine's refusal is what the user should see -- the GitHub
 * import, which fetches keys somebody actually published. Narrowing to
 * the supported types there turns "ECDSA keys are not supported" into
 * "this account has published no keys", which is simply false, and it
 * duplicates the engine's list of supported types in a second place
 * where it can drift. The worker shape-checks; `parseSshRecipient`
 * decides validity, and it has a curated message for each type it
 * refuses (FIDO, ECDSA, DSA, out-of-range RSA, ...).
 *
 * That lesson has now had to be learned FOUR times, in four different
 * shapes, which is why it is written down here rather than fixed
 * quietly: a bare `catch { continue }` in `import/prepare.ts` swallowed
 * the messages on the paste path; `github/response.ts` filtered the key
 * types out of existence on the fetch path; and `prepare.ts`,
 * `classify-action.ts` and `drop-routing.ts` each narrowed the *shape*
 * so those lines never reached the engine at all.
 *
 * The invariant, stated once: **the engine decides validity; every
 * layer above it forwards and displays.** A layer that drops a line the
 * engine would have explained is not being strict, it is replacing a
 * true, actionable message with a false one.
 *
 * Users: `github/response.ts`, `import/prepare.ts`,
 * `classify-action.ts`, `drop-routing.ts` -- the fetch path AND every
 * paste/drop/selection path. Keep this list honest; it is how the next
 * reader knows whether a narrowing they are about to add has a sibling.
 *
 * `AAAA` still anchors it: every SSH wire-format blob opens with a
 * 4-byte big-endian length whose top bytes are zero, so its base64
 * always starts that way regardless of algorithm. That -- plus a type
 * token restricted to the characters real algorithm names use
 * (`ecdsa-sha2-nistp256`, `sk-ssh-ed25519@openssh.com`, `ssh-dss`) --
 * is what keeps prose and HTML out.
 */
const SSH_PUBLIC_CANDIDATE_LINE =
  /^[ \t]*[A-Za-z][A-Za-z0-9@._-]{2,63}[ \t]+AAAA[A-Za-z0-9+/]+={0,3}(?:[ \t]+[^\r\n]*)?/gm;

/** Every armored age block in `text`, in order. */
export function splitAgeBlocks(text: string): string[] {
  return matchAll(text, AGE_BLOCK);
}

/** Every OpenSSH private key block in `text`, in order. */
export function splitSshPrivateKeyBlocks(text: string): string[] {
  return matchAll(text, OPENSSH_PRIVATE_BLOCK);
}

/** Every SSH public key line in `text`, in order, trimmed. A pasted
 *  `authorized_keys` file is exactly this and nothing else. */
export function splitSshPublicKeyLines(text: string): string[] {
  return matchAll(text, SSH_PUBLIC_LINE).map((line) => line.trim());
}

/** Every line in `text` shaped like an SSH public key of ANY algorithm,
 *  in order, trimmed. See {@link SSH_PUBLIC_CANDIDATE_LINE}: use this
 *  where the engine gets to answer for the line, not this module. */
export function splitSshPublicKeyCandidateLines(text: string): string[] {
  return matchAll(text, SSH_PUBLIC_CANDIDATE_LINE).map((line) => line.trim());
}

/** True when the text carries age ciphertext in either form. Used for
 *  routing only -- the engine re-checks. */
export function looksLikeAgeMessage(text: string): boolean {
  return text.includes(AGE_ARMOR_BEGIN) || text.includes(AGE_BINARY_MAGIC);
}

export interface ArmoredKeyBlocks {
  publicKeys: string[];
  privateKeys: string[];
  /** SSH public key lines -- age recipients. */
  sshPublicKeys: string[];
  /** OpenSSH private key blocks -- age identities. */
  sshPrivateKeys: string[];
}

/** Split a (possibly mixed) armored dump into key blocks of every kind
 *  we import -- e.g. a "backup all keys" file with several of each, or a
 *  pasted `authorized_keys` alongside a PGP block. The two SSH lists are
 *  additive: a caller that only knows about OpenPGP keeps working
 *  unchanged. */
export function splitArmoredKeyBlocks(text: string): ArmoredKeyBlocks {
  return {
    publicKeys: splitPublicKeyBlocks(text),
    privateKeys: splitPrivateKeyBlocks(text),
    // DELIBERATELY the narrow matcher, and the only remaining caller of
    // it. This splits a BACKUP bundle we wrote ourselves, so every SSH
    // line in it is one the engine already accepted -- an unsupported
    // type could never have been stored. Widening here would buy
    // nothing and would mean a corrupted bundle yields a "key" that
    // then has to be refused, instead of simply not matching.
    sshPublicKeys: splitSshPublicKeyLines(text),
    sshPrivateKeys: splitSshPrivateKeyBlocks(text),
  };
}
