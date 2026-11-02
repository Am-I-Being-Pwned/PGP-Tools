/**
 * (De)serialize CRX signing keys as labelled JSON blocks appended to the
 * "Export All Keys" `.asc`; PGP tools ignore the unknown block. No unlock
 * or re-seal here: export re-seals under the export passphrase first so
 * the blob restores on any device.
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

/** Caps work on a crafted backup. */
export const MAX_CRX_BLOCKS = 64;

const MAX_CRX_BLOCK_CHARS = 64 * 1024;

/** Extract CRX blocks, skipping malformed ones. A linear `indexOf` scan,
 *  never a regex: a lazy BEGIN..END regex backtracks catastrophically on
 *  unterminated BEGINs. */
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
    // Read from the last BEGIN so a torn block can't swallow the next.
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
