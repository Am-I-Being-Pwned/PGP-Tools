import type { PublicContactKey } from "../storage/contacts";
import { downloadText } from "../utils/download";

export function backupFileName(): string {
  return `pgp-tools-keys-${new Date().toISOString().slice(0, 10)}.asc`;
}

/** `ext`: "asc" (PGP), "pem" (CRX) or "pub" (SSH recipient line). */
export function downloadPublicKey(
  text: string,
  displayName: string,
  ext: "asc" | "pem" | "pub" = "asc",
): void {
  const slug = displayName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40)
    .replace(/-+$/, "");
  downloadText(text.trim() + "\n", `${slug || "key"}-public.${ext}`);
}

/** Public material only, so no unlock needed. Returns keys written. */
export function downloadPublicKeysBundle(contacts: PublicContactKey[]): number {
  const parts = contacts.map((c) => c.armoredPublicKey.trim()).filter(Boolean);
  downloadText(parts.join("\n\n") + "\n", backupFileName());
  return parts.length;
}
