// Throwaway OpenPGP private key + a distinctive base64 slice of its SECRET
// material (the heap-scan needle). Test-only, never real. The decrypt path
// encrypts to this key via the app at runtime, so no ciphertext fixture is
// needed. Regenerate: see e2e/README.md.

export const PRIVATE_KEY_FIXTURE = {
  name: "Heap Test",
  privateKey:
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\nlFgEakqTdRYJKwYBBAHaRw8BAQdAzWF8DjkjzsaxfCCWDgLCq6AA/knN5L5X1oVD\nt8Jo7RsAAP91vIgxMaSLqpZnXfCY0/CxSWbIUK6v9mglCixGYmjF2xHWtBtIZWFw\nIFRlc3QgPGhlYXBAdGVzdC5sb2NhbD6ImQQTFgoAQRYhBF7cm1t/M4hlArW/7Im6\n5QvFtzCrBQJqSpN1AhsDBQkB4TOABQsJCAcCAiICBhUKCQgLAgQWAgMBAh4HAheA\nAAoJEIm65QvFtzCr2mEA/iVKS8ZE6uHVwn4fGKz8dWnDYvkLOG2w7CARJbFC0C4S\nAPsGM/TsJS5qNdspXx5EiCoEPqPL7/wX4Y81AefTeaZaApxdBGpKk3USCisGAQQB\nl1UBBQEBB0COQwNskK1O+myf/rjcR2iDpls96UYTfG+q13BhFNx9agMBCAcAAP9L\nsdVXTGz1djJbE6M3YsNx7gZZZWN5VNxelqH7VwKMyBBViHgEGBYKACAWIQRe3Jtb\nfzOIZQK1v+yJuuULxbcwqwUCakqTdQIbDAAKCRCJuuULxbcwq1zvAQCl1ir5B+8M\n9QeuF10CmZQDeGVMtwmwHhZ6iyi0n5E9WgEA57BcQxHohAWVIF4VJnNmDFi1hkbB\nWjbTRD4KKTy0nwc=\n=yN6i\n-----END PGP PRIVATE KEY BLOCK-----\n",
  /** A 44-char base64 slice of the SECRET key material (unique). */
  secretNeedle: "APsGM/TsJS5qNdspXx5EiCoEPqPL7/wX4Y81AefTeaZa",
  /** Plaintext round-tripped through encrypt+decrypt in the workspace. */
  decryptedPlaintext: "heap-decrypt-plaintext-sentinel-42",
};
