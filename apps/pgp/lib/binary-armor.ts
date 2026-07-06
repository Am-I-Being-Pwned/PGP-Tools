/**
 * Binary OpenPGP key support for the import paths. `gpg --export`
 * without `--armor` produces raw packet bytes (the `.gpg` shape our file
 * pickers already accept); reading those with `file.text()` mangles them
 * irreversibly through UTF-8 decoding. Instead, detect the binary shape
 * and armor it on the fly so the rest of the import pipeline (armor
 * splitting, Sequoia parsing) sees a normal armored block.
 */

/** RFC 4880 §6.1 CRC-24 over the payload bytes. */
function crc24(bytes: Uint8Array): number {
  let crc = 0xb704ce;
  for (const byte of bytes) {
    crc ^= byte << 16;
    for (let i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
  }
  return crc & 0xffffff;
}

function toBase64(bytes: Uint8Array): string {
  // btoa via String.fromCharCode overflows the stack on large inputs;
  // build the binary string in chunks (keys can be up to 1 MiB).
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

/** OpenPGP packet tag of the first packet, or null when `bytes` doesn't
 *  start with a packet header (armored text, BOM'd text, other files all
 *  fall through: tag values outside the key tags return null too). */
function firstPacketTag(bytes: Uint8Array): number | null {
  if (bytes.length < 2) return null;
  const b = bytes[0];
  if ((b & 0x80) === 0) return null;
  return b & 0x40 ? b & 0x3f : (b >> 2) & 0x0f;
}

/** A binary key export starts with its primary key packet. */
const ARMOR_LABEL: Record<number, string> = {
  5: "PGP PRIVATE KEY BLOCK",
  6: "PGP PUBLIC KEY BLOCK",
};

/** Armor raw binary OpenPGP key bytes, or return null when the bytes
 *  don't look like a binary key export (caller falls back to text). */
export function binaryKeyToArmored(bytes: Uint8Array): string | null {
  const tag = firstPacketTag(bytes);
  const label = tag === null ? undefined : ARMOR_LABEL[tag];
  if (!label) return null;

  const body = toBase64(bytes).replace(/(.{64})/g, "$1\n").trimEnd();
  const crc = crc24(bytes);
  const crcB64 = toBase64(
    new Uint8Array([(crc >> 16) & 0xff, (crc >> 8) & 0xff, crc & 0xff]),
  );
  return `-----BEGIN ${label}-----\n\n${body}\n=${crcB64}\n-----END ${label}-----\n`;
}

/** Read a key file as armored text: armored files pass through
 *  untouched, raw binary exports (the `gpg --export` default) are
 *  armored on the fly. */
export async function readKeyFile(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  return binaryKeyToArmored(bytes) ?? new TextDecoder().decode(bytes);
}
