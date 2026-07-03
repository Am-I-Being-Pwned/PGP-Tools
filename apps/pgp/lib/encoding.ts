/** Shared base64 / base64url codecs. Single source of truth. */

function asBytes(data: Uint8Array | ArrayBuffer): Uint8Array {
  return data instanceof Uint8Array ? data : new Uint8Array(data);
}

export function toBase64(data: Uint8Array | ArrayBuffer): string {
  const bytes = asBytes(data);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function fromBase64(b64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function toBase64url(data: Uint8Array | ArrayBuffer): string {
  return toBase64(data)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export function fromBase64url(b64url: string): Uint8Array<ArrayBuffer> {
  const b64 = b64url
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(b64url.length + ((4 - (b64url.length % 4)) % 4), "=");
  return fromBase64(b64);
}

/** Unpack WASM `[12-byte IV][ciphertext]` format. */
export function unpackIvCiphertext(packed: Uint8Array): {
  iv: Uint8Array;
  ciphertext: Uint8Array;
} {
  return { iv: packed.slice(0, 12), ciphertext: packed.slice(12) };
}
