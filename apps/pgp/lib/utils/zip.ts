import { zipSync } from "fflate";

/** Zip multiple files into a single Uint8Array archive. */
export async function zipFiles(files: File[]): Promise<Uint8Array> {
  const entries: Record<string, Uint8Array> = {};
  for (const file of files) {
    const buffer = await file.arrayBuffer();
    entries[file.name] = new Uint8Array(buffer);
  }
  return zipSync(entries);
}

/** Check if a Uint8Array starts with the ZIP magic bytes (PK\x03\x04). */
export function isZipArchive(data: Uint8Array): boolean {
  return (
    data.length >= 4 &&
    data[0] === 0x50 &&
    data[1] === 0x4b &&
    data[2] === 0x03 &&
    data[3] === 0x04
  );
}

/**
 * Cheaply check whether a ZIP contains a `manifest.json` entry (i.e. looks
 * like a packed Chrome extension). Reads only the central directory --
 * no file data is decompressed -- so it's fast even on large archives.
 */
export function zipHasManifest(data: Uint8Array): boolean {
  if (!isZipArchive(data) || data.length < 22) return false;
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const EOCD_SIG = 0x06054b50;
  const CEN_SIG = 0x02014b50;

  // Locate the End Of Central Directory, scanning back past any archive
  // comment (max 65535 bytes).
  const minStart = Math.max(0, data.length - 22 - 0xffff);
  let eocd = -1;
  for (let i = data.length - 22; i >= minStart; i--) {
    if (dv.getUint32(i, true) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return false;

  const count = dv.getUint16(eocd + 10, true);
  let off = dv.getUint32(eocd + 16, true);
  const decoder = new TextDecoder();

  for (let n = 0; n < count; n++) {
    if (off + 46 > data.length || dv.getUint32(off, true) !== CEN_SIG) break;
    const nameLen = dv.getUint16(off + 28, true);
    const extraLen = dv.getUint16(off + 30, true);
    const commentLen = dv.getUint16(off + 32, true);
    const nameStart = off + 46;
    if (nameStart + nameLen > data.length) break;
    const name = decoder.decode(data.subarray(nameStart, nameStart + nameLen));
    if (name === "manifest.json" || name.endsWith("/manifest.json")) return true;
    off = nameStart + nameLen + extraLen + commentLen;
  }
  return false;
}
