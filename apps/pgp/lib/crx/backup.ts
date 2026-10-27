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

import type { CrxSigningKeyBlob } from "./types";
import { fromBase64, toBase64 } from "../encoding";
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

/** Most CRX blocks one backup is read for. A real backup holds a
 *  handful; the cap keeps a crafted file from making the panel decode
 *  and parse thousands of blobs. */
export const MAX_CRX_BLOCKS = 64;

/** Longest block body read, in characters. A sealed CRX blob is a few
 *  KB of base64; anything far past that is not one. */
const MAX_CRX_BLOCK_CHARS = 64 * 1024;

/** Extract any CRX signing-key blocks from a backup file's text. Malformed
 *  or non-CRX blocks are silently skipped.
 *
 *  A linear `indexOf` scan, never a regex: the old
 *  `BEGIN\s*([\s\S]*?)\s*END` backtracked over every BEGIN with no END
 *  after it, so a pasted file of a hundred bare BEGIN lines froze the
 *  panel for half a minute. Here each BEGIN is matched to the next END
 *  once, and a BEGIN with none ends the scan. */
export function parseCrxKeyBlocks(text: string): CrxSigningKeyBlob[] {
  const blobs: CrxSigningKeyBlob[] = [];
  let from = 0;
  for (let found = 0; found < MAX_CRX_BLOCKS; found++) {
    const begin = text.indexOf(BEGIN, from);
    if (begin === -1) break;
    const bodyStart = begin + BEGIN.length;
    const end = text.indexOf(END, bodyStart);
    if (end === -1) break;
    from = end + END.length;
    // A second BEGIN before this END: the first block was never closed.
    // Read from the last BEGIN, so one torn block cannot swallow the
    // next whole one.
    const last = text.lastIndexOf(BEGIN, end);
    const body = text.slice(last + BEGIN.length, end);
    if (body.length > MAX_CRX_BLOCK_CHARS) continue;
    try {
      const json = new TextDecoder().decode(
        fromBase64(body.replace(/\s+/g, "")),
      );
      const parsed: unknown = JSON.parse(json);
      if (isCrxSigningKeyBlob(parsed)) blobs.push(parsed);
    } catch {
      // Skip a corrupt block rather than failing the whole import.
    }
  }
  return blobs;
}
