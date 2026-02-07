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
