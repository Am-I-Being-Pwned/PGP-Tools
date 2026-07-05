/** Routing for the app-wide global dropzone.
 *
 *  A drop is matched against an ordered list of {@link DropRule}s — the
 *  first rule whose `match` returns true owns the drop and runs. The last
 *  rule should be a catch-all. To teach the global dropzone a new route
 *  (e.g. a detached-signature file, a vCard, a backup bundle) add a rule;
 *  nothing in the dropzone component itself needs to change. */

/** A drag payload once dropped: the raw files and any dragged text/plain. */
export interface DropPayload {
  files: File[];
  text: string;
}

/** Lightweight signals a rule inspects to decide if it owns a drop.
 *  `sampleText` is the dragged text plus a bounded prefix of each file —
 *  enough to spot an armor header without reading whole files. */
export interface DropSample {
  files: File[];
  text: string;
  sampleText: string;
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

/** True when the text carries an armored private-key header of any kind. */
export function looksLikePrivateKey(text: string): boolean {
  return PRIVATE_KEY_HEADER_RE.test(text);
}

/** True when the text carries an importable key header (public or private). */
export function looksLikeKey(text: string): boolean {
  return PRIVATE_KEY_HEADER_RE.test(text) || text.includes(PUBLIC_KEY_HEADER);
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
 *  for classification only. */
export async function buildDropSample(
  payload: DropPayload,
): Promise<DropSample> {
  const prefixes = await Promise.all(
    payload.files.slice(0, MAX_SAMPLE_FILES).map((f) =>
      f
        .slice(0, SAMPLE_BYTES)
        .text()
        .catch(() => ""),
    ),
  );
  return {
    files: payload.files,
    text: payload.text,
    sampleText: [payload.text, ...prefixes].join("\n"),
  };
}

/** Read every dropped file fully and join. Used by the key-import route,
 *  where files are small armored blobs. Oversized files are skipped so an
 *  accidental huge drop can't be loaded wholesale into memory. */
export async function readAllFilesText(files: File[]): Promise<string> {
  const texts = await Promise.all(
    files.map((f) =>
      f.size <= MAX_KEY_FILE_BYTES
        ? f.text().catch(() => "")
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
