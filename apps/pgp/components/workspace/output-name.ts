import type { WorkspaceAction } from "../../lib/messages";
import type { StoredKeyKind } from "../../lib/storage/key-kind";

/** Filesystem-safe slug of a recipient display name, capped so long
 *  corporate names don't swallow the whole filename. */
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
 * Default download name for the current operation's output.
 * `fileNames` is the (possibly empty) list of input file names.
 * Encrypt outputs carry a recipient tag and a timestamp so a Downloads
 * folder full of ciphertext stays identifiable
 * ("message.to-alice.2026-07-16-1432.gpg").
 *
 * `engine` names the format the ciphertext is actually in: `.gpg` for
 * OpenPGP, `.age` for age. The extension is not decoration -- it is what
 * tells the user (and every other tool they might open the file with)
 * which program can read it, so an age file must never be handed over
 * named `.gpg`.
 */
export function outputFileName(
  mode: WorkspaceAction,
  fileNames: string[],
  zipFiles: boolean,
  opts?: { recipients?: string[]; now?: Date; engine?: StoredKeyKind | null },
): string {
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
  if (fileNames.length === 0) return `output.${ext}`;
  if (fileNames.length === 1 || !zipFiles) {
    const name = fileNames[0];
    if (mode === "sign") return `${name}.asc`;
    // Strip whichever ciphertext extension the input carried, so
    // "report.pdf.age" decrypts back to "report.pdf".
    return name.replace(/\.(gpg|pgp|asc|age)$/i, "") || name;
  }
  return "decrypted-files.zip";
}
