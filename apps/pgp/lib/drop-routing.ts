/** Routing for the app-wide global dropzone.
 *
 *  A drop is matched against an ordered list of {@link DropRule}s — the
 *  first rule whose `match` returns true owns the drop and runs. The last
 *  rule should be a catch-all. To teach the global dropzone a new route
 *  (e.g. a detached-signature file, a vCard, a backup bundle) add a rule;
 *  nothing in the dropzone component itself needs to change. */

import { splitSshPublicKeyCandidateLines } from "./armor-blocks";
import { looksLikeBinaryKey, readKeyFile } from "./binary-armor";

/** A drag payload once dropped: the raw files and any dragged text/plain. */
export interface DropPayload {
  files: File[];
  text: string;
}

/** Lightweight signals a rule inspects to decide if it owns a drop.
 *  `sampleText` is the dragged text plus a bounded prefix of each file —
 *  enough to spot an armor header without reading whole files.
 *  `hasBinaryKeyFile` flags a file whose bytes are a raw (non-armored)
 *  OpenPGP key export, which carries no armor header to sample. */
export interface DropSample {
  files: File[];
  text: string;
  sampleText: string;
  hasBinaryKeyFile: boolean;
}

/** A drop rule. Rules are tried in order; the first match wins. */
export interface DropRule {
  id: string;
  match: (sample: DropSample) => boolean;
  run: (payload: DropPayload) => void | Promise<void>;
}

// Any armored PRIVATE key header: an OpenPGP private block, or a raw PEM of
// any flavour (RSA / EC / DSA / ENCRYPTED / OPENSSH / plain PKCS#8). Kept
// deliberately broad — anything matching here must be routed AWAY from the
// workspace (and its at-rest draft) and toward the import flow. Anchored to
// the "-----BEGIN " armor prefix so a stray "PRIVATE KEY" substring in a
// message body can't trip it.
const PRIVATE_KEY_HEADER_RE =
  /-----BEGIN (?:PGP PRIVATE KEY BLOCK|(?:[A-Z0-9]+ )*PRIVATE KEY)-----/;
const PUBLIC_KEY_HEADER = "-----BEGIN PGP PUBLIC KEY BLOCK-----";

/** True when the text carries an armored private-key header of any kind.
 *  `BEGIN OPENSSH PRIVATE KEY` has always matched the regex above -- what
 *  it lacked was a destination, which the import pipeline now provides
 *  (`lib/import/prepare.ts`, kind `ssh-private`). */
export function looksLikePrivateKey(text: string): boolean {
  return PRIVATE_KEY_HEADER_RE.test(text);
}

/** True when the text carries an SSH PUBLIC key line -- a dropped
 *  `id_ed25519.pub` or `authorized_keys`. Unlike every other key form we
 *  route, this one has no armor header at all, so the private-key regex
 *  above cannot see it and a drop of one used to land in the workspace as
 *  if it were a message to encrypt.
 *
 *  ANY algorithm, via the candidate splitter -- the same one
 *  `import/prepare.ts` and `classify-action.ts` now use. A dropped ECDSA
 *  or FIDO `sk-*` `.pub` is a key the import flow has something to say
 *  about ("ECDSA keys are not supported ..."), so routing it to the
 *  workspace as message text is the fourth instance of one pattern: the
 *  engine decides validity; every layer above it forwards and displays.
 *  Widening here cannot take a drop from another engine -- an armored
 *  block of any kind is matched by the header rules above and its base64
 *  body has no spaces for this shape to catch. */
export function looksLikeSshPublicKey(text: string): boolean {
  return splitSshPublicKeyCandidateLines(text).length > 0;
}

/** True when the text carries an importable key of any kind -- either
 *  engine, either half. */
export function looksLikeKey(text: string): boolean {
  return (
    PRIVATE_KEY_HEADER_RE.test(text) ||
    text.includes(PUBLIC_KEY_HEADER) ||
    looksLikeSshPublicKey(text)
  );
}

// Armored keys sit at the very top of their file, so a prefix is enough to
// classify — and it keeps a large binary drop from being read wholesale
// into memory just to decide where it should go.
const SAMPLE_BYTES = 64 * 1024;
// Classify at most this many files from a single drop — a guard against a
// pathological many-file drop turning classification into a memory sink.
const MAX_SAMPLE_FILES = 50;
// An armored key is tiny; never read a "key" file larger than this into
// memory for import. A giant file whose first bytes happen to look like a
// key is skipped rather than slurped whole.
const MAX_KEY_FILE_BYTES = 1024 * 1024;

/** Read a bounded prefix of each file and combine with the dragged text,
 *  for classification only. Each prefix is read once as bytes: decoded
 *  for the armor-header text sample, and sniffed raw for binary
 *  (non-armored) key exports, which have no header to sample. */
export async function buildDropSample(
  payload: DropPayload,
): Promise<DropSample> {
  const prefixes = await Promise.all(
    payload.files.slice(0, MAX_SAMPLE_FILES).map(async (f) => {
      try {
        return new Uint8Array(await f.slice(0, SAMPLE_BYTES).arrayBuffer());
      } catch {
        return new Uint8Array(0);
      }
    }),
  );
  const decoder = new TextDecoder();
  return {
    files: payload.files,
    text: payload.text,
    sampleText: [payload.text, ...prefixes.map((b) => decoder.decode(b))].join(
      "\n",
    ),
    hasBinaryKeyFile: prefixes.some(looksLikeBinaryKey),
  };
}

/** Read every dropped file fully and join, armoring raw binary key
 *  exports on the fly. Used by the key-import route, where files are
 *  small key blobs. Oversized files are skipped so an accidental huge
 *  drop can't be loaded wholesale into memory. */
export async function readAllFilesText(files: File[]): Promise<string> {
  const texts = await Promise.all(
    files.map((f) =>
      f.size <= MAX_KEY_FILE_BYTES
        ? readKeyFile(f).catch(() => "")
        : Promise.resolve(""),
    ),
  );
  return texts.join("\n");
}

/** The first rule that matches the sample, or null if none do. */
export function resolveDropRule(
  rules: DropRule[],
  sample: DropSample,
): DropRule | null {
  return rules.find((r) => r.match(sample)) ?? null;
}
