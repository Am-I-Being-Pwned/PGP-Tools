/**
 * Armor binary `gpg --export` output on the fly: `file.text()` would
 * mangle raw packets irreversibly through UTF-8 decoding.
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
  // Chunked: spreading a large array into fromCharCode overflows the stack.
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

/** First packet's tag, or null if `bytes` doesn't start with a packet
 *  header. */
function firstPacketTag(bytes: Uint8Array): number | null {
  if (bytes.length < 2) return null;
  const b = bytes[0];
  if ((b & 0x80) === 0) return null;
  return b & 0x40 ? b & 0x3f : (b >> 2) & 0x0f;
}

const ARMOR_LABEL: Record<number, string> = {
  5: "PGP PRIVATE KEY BLOCK",
  6: "PGP PUBLIC KEY BLOCK",
};

export function looksLikeBinaryKey(bytes: Uint8Array): boolean {
  const tag = firstPacketTag(bytes);
  return tag !== null && tag in ARMOR_LABEL;
}

/** Null when not a binary key export (caller falls back to text). */
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

/** Read a key file as armored text, armoring binary exports. */
export async function readKeyFile(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  return binaryKeyToArmored(bytes) ?? new TextDecoder().decode(bytes);
}
