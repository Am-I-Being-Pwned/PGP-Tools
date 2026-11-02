/** Global-dropzone routing: ordered {@link DropRule}s, first match wins;
 *  the last rule should be a catch-all. */

import { splitSshPublicKeyCandidateLines } from "./armor-blocks";
import { looksLikeBinaryKey, readKeyFile } from "./binary-armor";

export interface DropPayload {
  files: File[];
  text: string;
}

/** `sampleText` is the dragged text plus a bounded prefix of each file.
 *  `hasBinaryKeyFile` flags a raw (non-armored) key export, which has no
 *  header to sample. */
export interface DropSample {
  files: File[];
  text: string;
  sampleText: string;
  hasBinaryKeyFile: boolean;
}

export interface DropRule {
  id: string;
  match: (sample: DropSample) => boolean;
  run: (payload: DropPayload) => void | Promise<void>;
}

// Deliberately broad (OpenPGP private block or any PEM private key): a match
// must be routed AWAY from the workspace and its at-rest draft, to import.
// Anchored to "-----BEGIN " so a stray "PRIVATE KEY" in a body can't trip it.
const PRIVATE_KEY_HEADER_RE =
  /-----BEGIN (?:PGP PRIVATE KEY BLOCK|(?:[A-Z0-9]+ )*PRIVATE KEY)-----/;
const PUBLIC_KEY_HEADER = "-----BEGIN PGP PUBLIC KEY BLOCK-----";

export function looksLikePrivateKey(text: string): boolean {
  return PRIVATE_KEY_HEADER_RE.test(text);
}

/** SSH public key line (`.pub`, `authorized_keys`) of ANY algorithm: the
 *  engine decides validity, layers above only forward. Can't steal an
 *  armored block (its base64 body has no spaces). */
export function looksLikeSshPublicKey(text: string): boolean {
  return splitSshPublicKeyCandidateLines(text).length > 0;
}

/** An importable key of either engine, either half. */
export function looksLikeKey(text: string): boolean {
  // A signed/encrypted message is a message even if its text quotes a key.
  const start = text.trimStart();
  if (
    start.startsWith("-----BEGIN PGP SIGNED MESSAGE-----") ||
    start.startsWith("-----BEGIN PGP MESSAGE-----")
  ) {
    return false;
  }
  return (
    PRIVATE_KEY_HEADER_RE.test(text) ||
    text.includes(PUBLIC_KEY_HEADER) ||
    looksLikeSshPublicKey(text)
  );
}

// Memory bounds: classify from a prefix, cap files sampled, and never slurp
// a "key" file larger than MAX_KEY_FILE_BYTES.
const SAMPLE_BYTES = 64 * 1024;
const MAX_SAMPLE_FILES = 50;
const MAX_KEY_FILE_BYTES = 1024 * 1024;

/** Bounded prefix of each file plus the dragged text, for classification only. */
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

/** Key-import route: read and join all files (binary keys armored);
 *  oversized files are skipped. */
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

export function resolveDropRule(
  rules: DropRule[],
  sample: DropSample,
): DropRule | null {
  return rules.find((r) => r.match(sample)) ?? null;
}
