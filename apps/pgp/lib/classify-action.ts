import type { OperationAction } from "./messages";

/** Classify selected text by PGP armor header to decide which action
 *  the side panel should take. Substring checks only -- no parsing
 *  here, the side panel re-validates. */
export function classifyAction(text: string): OperationAction {
  if (text.includes("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
    return "import-public";
  }
  if (text.includes("-----BEGIN PGP PRIVATE KEY BLOCK-----")) {
    return "import-private";
  }
  if (text.includes("-----BEGIN PGP MESSAGE-----")) return "decrypt";
  if (text.includes("-----BEGIN PGP SIGNED MESSAGE-----")) return "verify";
  return "encrypt";
}
