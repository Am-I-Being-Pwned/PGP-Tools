import type { WorkspaceAction } from "../../lib/messages";

/**
 * Default download name for the current operation's output.
 * `fileNames` is the (possibly empty) list of input file names.
 */
export function outputFileName(
  mode: WorkspaceAction,
  fileNames: string[],
  zipFiles: boolean,
): string {
  if (fileNames.length === 0) return "output.gpg";
  if (fileNames.length === 1 || !zipFiles) {
    const name = fileNames[0];
    if (mode === "encrypt") return `${name}.gpg`;
    if (mode === "sign") return `${name}.asc`;
    return name.replace(/\.(gpg|pgp|asc)$/i, "") || name;
  }
  if (mode === "encrypt") return "encrypted-files.zip.gpg";
  return "decrypted-files.zip";
}
