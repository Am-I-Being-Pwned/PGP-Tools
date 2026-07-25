import type { PublicContactKey } from "../storage/contacts";
import { downloadText } from "../utils/download";

/** Dated filename for an exported key bundle, e.g. pgp-tools-keys-2025-01-31.asc */
export function backupFileName(): string {
  return `pgp-tools-keys-${new Date().toISOString().slice(0, 10)}.asc`;
}

/**
 * Download one key's public half under a name derived from its display name,
 * e.g. alice-example-public.asc. `ext` is "asc" (PGP armor) or "pem" (CRX).
 */
export function downloadPublicKey(
  text: string,
  displayName: string,
  ext: "asc" | "pem" = "asc",
): void {
  const slug = displayName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40)
    .replace(/-+$/, "");
  downloadText(text.trim() + "\n", `${slug || "key"}-public.${ext}`);
}

/**
 * Download just contacts' public keys as one armored `.asc`. No unlock or
 * passphrase is involved (public material only), so the selection island uses
 * this to export a contacts-only selection immediately instead of opening the
 * unlock/passphrase page. Returns the number of keys written.
 */
export function downloadPublicKeysBundle(contacts: PublicContactKey[]): number {
  const parts = contacts.map((c) => c.armoredPublicKey.trim()).filter(Boolean);
  downloadText(parts.join("\n\n") + "\n", backupFileName());
  return parts.length;
}
