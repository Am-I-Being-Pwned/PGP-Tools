import { t, tn } from "./i18n";

/**
 * Sanity ceiling, NOT a memory guard: wasm32's 4 GiB address space is the
 * only bound that is a fact (the renderer's real limit varies by device).
 * Files well below it can still OOM, and a failed `memory.grow` aborts the
 * engine and drops unlocked keys. Decompression bombs are stopped by the
 * output/input ratio in `decrypt_limit` (`gpg-wasm/src/lib.rs`).
 */
export const MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024;

export const MAX_FILE_LABEL = "4 GB";

export interface FileSizeSplit<T> {
  accepted: T[];
  rejected: T[];
}

/** Partition (not reject the whole drop) so the other files still load. */
export function splitOversizedFiles<T extends { size: number }>(
  files: T[],
): FileSizeSplit<T> {
  const accepted: T[] = [];
  const rejected: T[] = [];
  for (const file of files) {
    if (file.size > MAX_FILE_BYTES) rejected.push(file);
    else accepted.push(file);
  }
  return { accepted, rejected };
}

export function oversizedFilesMessage(
  rejected: { name: string }[],
): string | null {
  if (rejected.length === 0) return null;
  const names = rejected.map((f) => f.name);
  const listed =
    names.length <= 3
      ? names.join(", ")
      : t("app_oversized_more", {
          names: names.slice(0, 3).join(", "),
          count: names.length - 3,
        });
  return tn("app_oversized_files", names.length, {
    files: listed,
    limit: MAX_FILE_LABEL,
  });
}

/** Matches the engine's `MAX_SIGNED_INPUT_BYTES`; nothing bigger can verify. */
export const MAX_VERIFY_FILE_BYTES = 24 * 1024 * 1024;
export const MAX_VERIFY_FILE_LABEL = "24 MB";
