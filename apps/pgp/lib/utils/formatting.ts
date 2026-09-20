import { t } from "../i18n";

/** Format algorithm names like "ed25519Legacy" -> "ed25519 Legacy" */
export function formatAlgorithm(algo: string): string {
  return algo.replace(/([a-z\d])([A-Z])/g, "$1 $2");
}

/** Format fingerprint into 4-char blocks: "ABCD 1234 EF56 ..." */
export function formatFingerprint(fp: string): string {
  return fp.match(/.{1,4}/g)?.join(" ") ?? fp;
}

/** Format a byte count for display: "512 B", "1.2 KB", "3.4 MB". */
export function formatFileSize(bytes: number): string {
  if (bytes < 1024) return t("keys_size_bytes", { size: bytes });
  if (bytes < 1024 * 1024)
    return t("keys_size_kb", { size: (bytes / 1024).toFixed(1) });
  return t("keys_size_mb", { size: (bytes / (1024 * 1024)).toFixed(1) });
}
