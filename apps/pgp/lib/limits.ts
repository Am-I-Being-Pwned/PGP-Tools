/**
 * Sanity ceiling on a file the panel will attempt.
 *
 * WHAT THIS IS, AND WHAT IT IS NOT. It is not a memory guard. wasm32 can
 * address 4 GiB in total, and decrypting an N-byte file costs a multiple
 * of N across the JS heap and linear memory, so a file anywhere near
 * this ceiling will fail long before it reaches it -- and it fails
 * badly, because a failed `memory.grow` makes the Rust allocator return
 * null and `handle_alloc_error` ABORTS, killing the crypto engine and
 * the unlocked keys with it.
 *
 * So why cap at 4 GiB rather than somewhere safe? Because the number
 * that would be "safe" is not knowable from here. The wasm module
 * declares no maximum memory, so the real ceiling is whatever Chrome
 * grants that renderer, which moves with the device and with memory
 * pressure. A lower figure would be a guess wearing the costume of a
 * limit, and it would refuse files that work on the machine in front of
 * the user. This is the one bound that is a FACT about the platform:
 * past it, nothing can possibly work.
 *
 * The protection that actually stops the attack lives elsewhere, and is
 * a ratio rather than a size: `decrypt_limit` in `gpg-wasm/src/lib.rs`
 * ties how much a message may decrypt TO to how much ciphertext it came
 * FROM. That refuses a decompression bomb without having to refuse a
 * large legitimate file, which is the trade a flat number cannot make.
 */
export const MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024;

/** `MAX_FILE_BYTES` rendered the way the error message says it. */
export const MAX_FILE_LABEL = "4 GB";

export interface FileSizeSplit<T> {
  /** Files within the ceiling, in their original order. */
  accepted: T[];
  /** Files refused for being too large, in their original order. */
  rejected: T[];
}

/**
 * Partition dropped files into what we can safely load and what we
 * cannot. Deliberately a pure function over `{ name, size }` so the rule
 * can be tested without constructing real `File`s or a DOM.
 *
 * Partition rather than reject-the-whole-drop: someone who drags a
 * folder containing one huge file should still get the other files, with
 * the skipped one named.
 */
export function splitOversizedFiles<T extends { size: number }>(
  files: T[],
): FileSizeSplit<T> {
  const accepted: T[] = [];
  const rejected: T[] = [];
  for (const file of files) {
    // Strictly greater: a file of exactly the ceiling is allowed, so the
    // limit reads the same way to a user as it does in the code.
    if (file.size > MAX_FILE_BYTES) rejected.push(file);
    else accepted.push(file);
  }
  return { accepted, rejected };
}

/**
 * The message shown when a drop is refused. Names the files rather than
 * saying "a file was too large", because a multi-file drop otherwise
 * leaves the user guessing which one to remove.
 */
export function oversizedFilesMessage(
  rejected: { name: string }[],
): string | null {
  if (rejected.length === 0) return null;
  const names = rejected.map((f) => f.name);
  const listed =
    names.length <= 3
      ? names.join(", ")
      : `${names.slice(0, 3).join(", ")} and ${names.length - 3} more`;
  const subject = names.length === 1 ? "file is" : "files are";
  return `${listed}: ${subject} larger than ${MAX_FILE_LABEL} and can't be processed in the panel.`;
}
