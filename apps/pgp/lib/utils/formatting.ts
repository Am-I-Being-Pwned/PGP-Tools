/** Format algorithm names like "ed25519Legacy" -> "ed25519 Legacy" */
export function formatAlgorithm(algo: string): string {
  return algo.replace(/([a-z\d])([A-Z])/g, "$1 $2");
}

/** Format fingerprint into 4-char blocks: "ABCD 1234 EF56 ..." */
export function formatFingerprint(fp: string): string {
  return fp.match(/.{1,4}/g)?.join(" ") ?? fp;
}
