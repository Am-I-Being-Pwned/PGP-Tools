import type { WorkspaceAction } from "~/lib/messages";
import type { StoredKeyKind } from "~/lib/storage/key-kind";
import { safeFileName } from "~/lib/utils/file-name";

function recipientSlug(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 24)
    .replace(/-+$/, "");
  return slug || "recipient";
}

/** "to-alice" / "to-alice+2" tag for encrypt output names. */
function recipientTag(recipients: string[]): string {
  if (recipients.length === 0) return "";
  const first = recipientSlug(recipients[0]);
  const extra = recipients.length - 1;
  return extra > 0 ? `to-${first}+${extra}` : `to-${first}`;
}

/** "2026-07-16-1432" -- sortable, filesystem-safe, minute precision. */
function timestampTag(now: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${now.getFullYear()}-${p(now.getMonth() + 1)}-${p(now.getDate())}-${p(now.getHours())}${p(now.getMinutes())}`;
}

/**
 * Default download name for the output. Encrypt names carry a recipient
 * tag + timestamp ("message.to-alice.2026-07-16-1432.gpg") -- metadata
 * leak documented in SECURITY.md. The extension follows `engine`: an age
 * file must never be named `.gpg`.
 */
export function outputFileName(
  mode: WorkspaceAction,
  fileNames: string[],
  zipFiles: boolean,
  opts?: {
    recipients?: string[];
    now?: Date;
    engine?: StoredKeyKind | null;
    binary?: boolean;
  },
): string {
  fileNames = fileNames.map(safeFileName);
  const ext = opts?.engine === "ssh" ? "age" : "gpg";
  if (mode === "encrypt") {
    const parts = [
      recipientTag(opts?.recipients ?? []),
      timestampTag(opts?.now ?? new Date()),
    ].filter(Boolean);
    const suffix = parts.join(".");
    if (fileNames.length === 0) return `message.${suffix}.${ext}`;
    if (fileNames.length === 1 || !zipFiles)
      return `${fileNames[0]}.${suffix}.${ext}`;
    return `files.${suffix}.zip.${ext}`;
  }
  // Never name plaintext like ciphertext: it gets treated, and shared, as such.
  if (fileNames.length === 0) {
    if (mode === "sign") return "signed.asc";
    if (mode === "verify") return "verified.txt";
    return opts?.binary ? "decrypted.bin" : "decrypted.txt";
  }
  if (fileNames.length === 1 || !zipFiles) {
    const name = fileNames[0];
    if (mode === "sign") return `${name}.asc`;
    return name.replace(/\.(gpg|pgp|asc|age)$/i, "") || "decrypted";
  }
  return "decrypted-files.zip";
}

/**
 * Deduplicate a batch's output names so the name in the signer note is the
 * name on disk (the browser's own "(1)" renaming would diverge). Compared
 * case-insensitively, as macOS/Windows filesystems do.
 */
export function uniqueOutputNames(names: readonly string[]): string[] {
  const taken = new Set(names.map((n) => n.toLowerCase()));
  const used = new Set<string>();
  return names.map((name) => {
    if (!used.has(name.toLowerCase())) {
      used.add(name.toLowerCase());
      return name;
    }
    const dot = name.lastIndexOf(".");
    const [stem, ext] =
      dot > 0 ? [name.slice(0, dot), name.slice(dot)] : [name, ""];
    // Skip names another input owns, so renaming never creates a new clash.
    const free = (n: number) => {
      const key = `${stem} (${n})${ext}`.toLowerCase();
      return !used.has(key) && !taken.has(key);
    };
    let n = 2;
    while (!free(n)) n++;
    const candidate = `${stem} (${n})${ext}`;
    used.add(candidate.toLowerCase());
    return candidate;
  });
}
