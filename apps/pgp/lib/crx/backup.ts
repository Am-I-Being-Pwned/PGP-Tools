/**
 * Round-trips CRX signing keys through the "Export/Import All Keys" backup.
 *
 * A CRX key is a raw RSA-2048 key, not OpenPGP, so it can't be an armored
 * PGP block. Instead each key is written as a self-protected
 * `CrxSigningKeyBlob` (JSON) inside a clearly-labelled block appended to the
 * same `.asc` file. Non-PGP tools (GnuPG, etc.) ignore the unknown block;
 * PGP Tools parses it back on import.
 *
 * These functions are just the (de)serialization boundary — they neither
 * unlock nor re-seal. The bulk "Export All Keys" flow unlocks each CRX key
 * and re-seals it under the single export passphrase before calling
 * `serializeCrxKeyBlocks`, so the exported blob restores on any device (a
 * passkey seal is bound to one authenticator). On import the blob is stored
 * as-is under whatever protection it already carries.
 */

import { fromBase64, toBase64 } from "../encoding";
import type { CrxSigningKeyBlob } from "./types";
import { isCrxSigningKeyBlob } from "./types";

const BEGIN = "-----BEGIN PGP TOOLS CRX SIGNING KEY-----";
const END = "-----END PGP TOOLS CRX SIGNING KEY-----";

/** Serialize CRX keys into labelled base64 blocks (empty string if none). */
export function serializeCrxKeyBlocks(blobs: CrxSigningKeyBlob[]): string {
  return blobs
    .map((blob) => {
      const json = JSON.stringify(blob);
      const body = toBase64(new TextEncoder().encode(json));
      const wrapped = body.match(/.{1,64}/g)?.join("\n") ?? body;
      return `${BEGIN}\n${wrapped}\n${END}`;
    })
    .join("\n\n");
}

/** Extract any CRX signing-key blocks from a backup file's text. Malformed
 *  or non-CRX blocks are silently skipped. */
export function parseCrxKeyBlocks(text: string): CrxSigningKeyBlob[] {
  const blobs: CrxSigningKeyBlob[] = [];
  const re = new RegExp(`${BEGIN}\\s*([\\s\\S]*?)\\s*${END}`, "g");
  let match: RegExpExecArray | null;
  while ((match = re.exec(text)) !== null) {
    try {
      const body = match[1].replace(/\s+/g, "");
      const json = new TextDecoder().decode(fromBase64(body));
      const parsed: unknown = JSON.parse(json);
      if (isCrxSigningKeyBlob(parsed)) blobs.push(parsed);
    } catch {
      // Skip a corrupt block rather than failing the whole import.
    }
  }
  return blobs;
}
